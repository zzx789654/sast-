"""Test suite for SAST Studio.

Runs fully without any scanner installed: subprocess calls are faked and the
pure normalization/parsing functions are tested directly.
"""
from __future__ import annotations

import io
import json
import shutil
import zipfile
from pathlib import Path

import pytest

from app.adapters.base import CommandResult
from app.models import Finding, Severity, ToolKind, ToolStatus


# ---------------------------------------------------------------- availability
def test_missing_tool_reports_unavailable(tmp_path, monkeypatch):
    """With no binary on PATH, scan() degrades gracefully with an install hint."""
    from app.adapters.semgrep import SemgrepAdapter

    # Force absence regardless of what is actually installed in the test env.
    monkeypatch.setattr(shutil, "which", lambda name: None)
    result = SemgrepAdapter().scan(tmp_path)
    assert result.status == ToolStatus.UNAVAILABLE
    assert result.available is False
    assert result.install_hint  # non-empty guidance
    assert result.findings == []


# ---------------------------------------------------------------- semgrep e2e
def test_semgrep_normalization(monkeypatch, tmp_path):
    from app.adapters import semgrep

    (tmp_path / "a.py").write_text("x = 1\n")
    sample = {
        "results": [
            {
                "check_id": "python.lang.security.audit.sql-injection",
                "path": str(tmp_path / "a.py"),
                "start": {"line": 10},
                "end": {"line": 12},
                "extra": {
                    "severity": "ERROR",
                    "message": "Possible SQL injection",
                    "lines": "    cur.execute(\"SELECT * FROM t WHERE id=\" + uid)",
                    "metadata": {
                        "cwe": ["CWE-89: SQL Injection"],
                        "owasp": ["A03:2021 - Injection"],
                        "references": ["https://example.com"],
                        "category": "security",
                    },
                },
            }
        ]
    }

    def fake_run(args, **kw):
        if "--version" in args:
            return CommandResult(0, "1.55.0", "")
        return CommandResult(1, json.dumps(sample), "")  # nonzero when findings

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(semgrep, "run_command", fake_run)

    result = semgrep.SemgrepAdapter().scan(tmp_path)
    assert result.status == ToolStatus.OK
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.HIGH
    assert f.start_line == 10 and f.end_line == 12
    assert "CWE-89: SQL Injection" in f.cwe
    assert f.file == "a.py"
    # the offending source line is kept so the UI can show the code itself
    assert "cur.execute" in f.extra["snippet"]
    assert result.summary["high"] == 1


def test_semgrep_snippet_is_bounded():
    """Snippets come from scanned files, so they must not be unbounded."""
    from app.adapters.semgrep import MAX_SNIPPET_CHARS, MAX_SNIPPET_LINES, _snippet

    assert _snippet(None) == ""
    assert _snippet("requires login") == ""          # semgrep pro placeholder
    many = chr(10).join(f"line {i}" for i in range(200))
    assert len(_snippet(many).splitlines()) == MAX_SNIPPET_LINES
    assert len(_snippet("x" * 9000)) <= MAX_SNIPPET_CHARS


# ---------------------------------------------------------------- trivy
def test_trivy_parser(tmp_path):
    from app.adapters.trivy import _parse

    data = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2021-23337", "PkgName": "lodash",
                     "InstalledVersion": "4.17.0", "FixedVersion": "4.17.21",
                     "Severity": "HIGH", "Title": "Command injection in lodash",
                     "PrimaryURL": "https://avd.aquasec.com/x",
                     "CweIDs": ["CWE-77"]},
                ],
            },
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {"ID": "DS002", "Title": "root user", "Severity": "MEDIUM",
                     "Message": "Specify a non-root USER",
                     "CauseMetadata": {"StartLine": 1, "EndLine": 1}},
                ],
            },
            {
                "Target": "config.py",
                "Secrets": [
                    {"RuleID": "aws-access-key-id", "Category": "AWS",
                     "Severity": "CRITICAL", "Title": "AWS Access Key",
                     "StartLine": 3, "Match": "key = AKIAIOSFODNN7EXAMPLE"},
                ],
            },
        ]
    }
    findings = _parse(data, tmp_path)
    cats = sorted(f.extra["category"] for f in findings)
    assert cats == ["misconfiguration", "secret", "vulnerability"]
    vuln = next(f for f in findings if f.extra["category"] == "vulnerability")
    assert vuln.severity == Severity.HIGH and "CWE-77" in vuln.cwe
    secret = next(f for f in findings if f.extra["category"] == "secret")
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(secret.model_dump())


# ---------------------------------------------------------------- bearer
def test_bearer_parser(tmp_path):
    from app.adapters.bearer import _parse

    data = {
        "high": [
            {"id": "python_django_sql_injection", "title": "SQL injection",
             "description": "Untrusted input in SQL", "line_number": 20,
             "filename": "views.py", "cwe_ids": ["89"],
             "documentation_url": "https://docs.bearer.com/x"}
        ],
        "warning": [
            {"id": "python_logger", "title": "Sensitive data in logs",
             "line_number": 5, "filename": "app.py", "cwe_ids": ["532"]}
        ],
    }
    findings = _parse(data, tmp_path)
    assert len(findings) == 2
    high = next(f for f in findings if f.rule_id == "python_django_sql_injection")
    assert high.severity == Severity.HIGH
    assert "CWE-89" in high.cwe and high.start_line == 20
    warn = next(f for f in findings if f.rule_id == "python_logger")
    assert warn.severity == Severity.LOW  # warning maps to low


# ---------------------------------------------------------------- npm audit
def test_npm_audit_parser():
    from app.adapters.npm_audit import _parse_v7

    data = {
        "vulnerabilities": {
            "lodash": {
                "severity": "high",
                "range": "<4.17.21",
                "fixAvailable": True,
                "via": [
                    {"source": 1065, "title": "Prototype Pollution",
                     "url": "https://npmjs.com/advisories/1065",
                     "severity": "high", "cwe": ["CWE-1321"]}
                ],
            }
        }
    }
    findings = _parse_v7(data)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert "CWE-1321" in f.cwe
    assert f.extra["package"] == "lodash"


# ---------------------------------------------------------------- osv-scanner
def test_osv_parser(tmp_path):
    from app.adapters.osv_scanner import _parse

    data = {
        "results": [
            {
                "source": {"path": str(tmp_path / "requirements.txt")},
                "packages": [
                    {
                        "package": {"name": "django", "version": "2.2.0",
                                    "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {"id": "GHSA-xxxx", "summary": "SQL injection in Django",
                             "database_specific": {"severity": "CRITICAL"},
                             "references": [{"url": "https://example.com/adv"}]}
                        ],
                    }
                ],
            }
        ]
    }
    findings = _parse(data, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.extra["package"] == "django"
    assert f.file == "requirements.txt"


# ---------------------------------------------------------------- gitleaks + mask
def test_gitleaks_parser_masks_secret(tmp_path):
    from app.adapters.gitleaks import _parse, _mask

    data = [
        {"RuleID": "aws-access-token", "Description": "AWS Access Key",
         "File": str(tmp_path / "config.py"), "StartLine": 3, "EndLine": 3,
         "Secret": "AKIAIOSFODNN7EXAMPLE",
         "Match": "aws_key = AKIAIOSFODNN7EXAMPLE"}
    ]
    findings = _parse(data, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.file == "config.py"
    # the raw secret must never appear verbatim
    assert "AKIAIOSFODNN7EXAMPLE" not in f.extra["secret_preview"]
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(f.model_dump())


def test_mask_short_and_long():
    from app.adapters.gitleaks import _mask

    assert set(_mask("abcd")) == {"*"}
    masked = _mask("AKIAIOSFODNN7EXAMPLE")
    assert masked.startswith("AKIA") and masked.endswith("MPLE") and "*" in masked


# ---------------------------------------------------------------- source safety
def test_zip_slip_blocked(tmp_path):
    from app.source import extract_zip, SourceError

    bad_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("../escape.txt", "pwned")
    with pytest.raises(SourceError):
        extract_zip(bad_zip, tmp_path / "out")
    # nothing escaped into the parent
    assert not (tmp_path / "escape.txt").exists()


def test_zip_extract_ok(tmp_path):
    from app.source import extract_zip

    good = tmp_path / "good.zip"
    with zipfile.ZipFile(good, "w") as zf:
        zf.writestr("src/app.py", "print('hi')")
    root = extract_zip(good, tmp_path / "out")
    assert (root / "src" / "app.py").read_text() == "print('hi')"


def test_git_url_validation():
    from app.source import validate_git_url, SourceError

    assert validate_git_url("https://github.com/org/repo").startswith("https")
    for bad in ["file:///etc/passwd", "ssh://git@host/repo", "ftp://x/y", ""]:
        with pytest.raises(SourceError):
            validate_git_url(bad)


def test_local_path_validation(tmp_path):
    from app.source import resolve_local_path, SourceError

    assert resolve_local_path(str(tmp_path)) == tmp_path.resolve()
    with pytest.raises(SourceError):
        resolve_local_path(str(tmp_path / "does-not-exist"))


# ---------------------------------------------------------------- inventory
def test_inventory_and_language_detection(tmp_path):
    from app.inventory import inventory, has_language

    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "b.js").write_text("var x")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("ignored")  # skipped dir

    inv = inventory(tmp_path)
    assert inv["total_files"] == 2  # node_modules excluded
    assert inv["languages"]["python"] == 1
    assert inv["languages"]["javascript"] == 1
    assert has_language(tmp_path, {"python"}) is True
    assert has_language(tmp_path, {"ruby"}) is False


# ---------------------------------------------------------------- applicability (防呆)
def test_bearer_applicability_reason(tmp_path):
    from app.adapters.bearer import BearerAdapter

    ok, reason = BearerAdapter().applicability(tmp_path)
    assert ok is False and "Bearer" in reason
    (tmp_path / "x.py").write_text("x = 1")
    assert BearerAdapter().applicability(tmp_path)[0] is True


def test_npm_applicability_reason(tmp_path):
    from app.adapters.npm_audit import NpmAuditAdapter

    ok, reason = NpmAuditAdapter().applicability(tmp_path)
    assert ok is False and "package.json" in reason
    (tmp_path / "package.json").write_text("{}")
    assert NpmAuditAdapter().applicability(tmp_path)[0] is True


# ---------------------------------------------------------------- orchestrator
def test_orchestrator_state_machine(monkeypatch, tmp_path):
    from app import orchestrator
    from app.adapters.base import BaseAdapter
    from app.models import ScanTarget

    class FakeAdapter(BaseAdapter):
        name = "fake"
        kind = ToolKind.SAST
        binary = "fake"

        def probe(self):
            return True, "1.0"

        def applicable(self, target_dir):
            return True

        def _execute(self, target_dir):
            # Medium is the severity that asks for a reviewer; High blocks.
            return [Finding(tool="fake", severity=Severity.MEDIUM, title="boom")]

    monkeypatch.setattr(orchestrator, "get_adapters", lambda names: [FakeAdapter()])
    mgr = orchestrator.JobManager()
    job = mgr.new_job(ScanTarget(kind="path", display=str(tmp_path)), ["fake"])
    assert job.status.value == "queued"
    mgr._prepare_and_maybe_scan(job.id, {"kind": "path", "path": str(tmp_path)}, False)

    assert job.status.value == "policy_review"
    assert job.summary["medium"] == 1
    assert job.summary["total"] == 1
    assert job.results["fake"].status == ToolStatus.OK
    # progress + phase are populated for the live UI
    assert job.results["fake"].phase.value == "finished"
    assert job.progress["percent"] == 100
    assert job.progress["finished"] == job.progress["total"] == 1
    # The verdict stands; signing it off happens outside this application,
    # so there is no longer a way to change it from here.
    assert not hasattr(mgr, "review")
    assert job.status.value == "policy_review"


def test_high_finding_blocks_and_cannot_be_waived(monkeypatch, tmp_path):
    """A High finding blocks, and there is no longer any way to wave it through."""
    from app import orchestrator
    from app.adapters.base import BaseAdapter
    from app.models import ScanTarget

    class HighAdapter(BaseAdapter):
        name = "fake"
        kind = ToolKind.SAST
        binary = "fake"

        def probe(self):
            return True, "1.0"

        def applicable(self, target_dir):
            return True

        def _execute(self, target_dir):
            return [Finding(tool="fake", severity=Severity.HIGH, title="rce",
                            file="a.py", start_line=3)]

    monkeypatch.setattr(orchestrator, "get_adapters", lambda names: [HighAdapter()])
    mgr = orchestrator.JobManager()
    job = mgr.new_job(ScanTarget(kind="path", display=str(tmp_path)), ["fake"])
    mgr._prepare_and_maybe_scan(job.id, {"kind": "path", "path": str(tmp_path)}, False)

    assert job.status.value == "blocked"
    assert job.policy_evaluation["decision"] == "blocked"
    assert job.policy_evaluation["counts"]["high"] == 1
    # The false-positive exception route was removed along with the policy
    # form, so the manager must not carry one any more.
    assert not hasattr(mgr, "add_exception")
    # Nor is there a review route back: the verdict is final in the app.
    assert not hasattr(mgr, "review")


def test_confirm_flow(monkeypatch, tmp_path):
    from app import orchestrator
    from app.adapters.base import BaseAdapter
    from app.models import JobStatus, ScanTarget

    class FakeAdapter(BaseAdapter):
        name = "fake"
        kind = ToolKind.SAST
        binary = "fake"

        def probe(self):
            return True, "1.0"

        def applicability(self, target_dir):
            return True, ""

        def _execute(self, target_dir):
            # Medium, so the scan pauses for review and the confirm flow --
            # which is what this test is about -- stays observable.
            return [Finding(tool="fake", severity=Severity.MEDIUM, title="x")]

    monkeypatch.setattr(orchestrator, "get_adapters", lambda names: [FakeAdapter()])
    mgr = orchestrator.JobManager()
    (tmp_path / "a.py").write_text("x = 1")
    job = mgr.new_job(ScanTarget(kind="path", display=str(tmp_path)), ["fake"])

    # phase 1: prepare + inventory, then pause
    mgr._prepare_and_maybe_scan(job.id, {"kind": "path", "path": str(tmp_path)}, True)
    assert job.status == JobStatus.AWAITING
    assert job.inventory["total_files"] >= 1
    assert job.applicability[0]["name"] == "fake"
    assert job.id in mgr._pending

    # phase 2: confirm -> scan runs
    pending = mgr._pending.pop(job.id)
    mgr._scan(job, pending["scan_root"], pending["external"])
    assert job.status == JobStatus.POLICY_REVIEW
    assert job.summary["medium"] == 1


def test_cancel_flow(monkeypatch, tmp_path):
    from app import orchestrator
    from app.models import JobStatus, ScanTarget

    mgr = orchestrator.JobManager()
    job = mgr.new_job(ScanTarget(kind="path", display=str(tmp_path)), ["semgrep"])
    mgr._prepare_and_maybe_scan(job.id, {"kind": "path", "path": str(tmp_path)}, True)
    assert job.status == JobStatus.AWAITING
    assert mgr.cancel(job.id) is True
    assert job.status == JobStatus.CANCELLED
    assert job.id not in mgr._pending
    # cancelling again is a no-op
    assert mgr.cancel(job.id) is False


def test_orchestrator_reports_source_error(tmp_path):
    from app import orchestrator
    from app.models import ScanTarget

    mgr = orchestrator.JobManager()
    job = mgr.new_job(ScanTarget(kind="git", display="bad"), ["semgrep"])
    mgr._prepare_and_maybe_scan(job.id, {"kind": "git", "url": "file:///etc/passwd"}, False)
    assert job.status.value == "error"
    assert "scheme" in job.error.lower() or "SourceError" in job.error


# ---------------------------------------------------------------- API
@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def test_api_tools(client):
    data = client.get("/api/tools").json()
    names = {t["name"] for t in data["tools"]}
    assert names == {"semgrep", "bearer", "trivy", "npm_audit",
                     "osv_scanner", "gitleaks"}
    assert "allow_local_path" in data["config"]
    # each tool advertises its languages + requirement for the picker
    assert all("languages" in t and "requirement" in t for t in data["tools"])


def test_api_policies(client):
    """The rule is fixed now, so the endpoint states it instead of offering
    templates to choose between."""
    res = client.get("/api/policies")
    assert res.status_code == 200
    body = res.json()
    assert "templates" not in body and "default" not in body
    ids = [r["id"] for r in body["rules"]]
    assert "block_high_and_above" in ids
    assert "secret_block" in ids
    assert "medium_manual_review" in ids


@pytest.mark.parametrize("severities,expected", [
    ([], "passed"),                                   # nothing found
    ([Severity.INFO], "passed"),
    ([Severity.LOW], "passed"),
    ([Severity.LOW, Severity.INFO], "passed"),
    ([Severity.MEDIUM], "manual_review"),
    ([Severity.LOW, Severity.MEDIUM], "manual_review"),
    ([Severity.HIGH], "blocked"),
    ([Severity.CRITICAL], "blocked"),
    ([Severity.MEDIUM, Severity.HIGH], "blocked"),    # worst severity wins
])
def test_verdict_ladder(severities, expected):
    """High and above blocks, medium needs a reviewer, low or nothing passes."""
    from app.models import Job, ScanTarget, ToolResult
    from app.policies import evaluate_policy

    job = Job(
        id="ladder",
        target=ScanTarget(kind="upload", display="x.zip"),
        results={
            "semgrep": ToolResult(
                tool="semgrep", kind=ToolKind.SAST, status=ToolStatus.OK,
                findings=[Finding(tool="semgrep", rule_id="r%d" % i, severity=sev)
                          for i, sev in enumerate(severities)],
            ),
        },
    )
    assert evaluate_policy(job)["decision"] == expected


def test_secret_blocks_whatever_severity_it_was_given():
    """A leaked credential is already public; its grading does not change that."""
    from app.models import Job, ScanTarget, ToolResult
    from app.policies import evaluate_policy

    job = Job(
        id="secret",
        target=ScanTarget(kind="upload", display="x.zip"),
        results={
            "gitleaks": ToolResult(
                tool="gitleaks", kind=ToolKind.SECRET, status=ToolStatus.OK,
                # deliberately LOW: the rule must not depend on the grading
                findings=[Finding(tool="gitleaks", rule_id="aws-key",
                                  severity=Severity.LOW)],
            ),
        },
    )
    result = evaluate_policy(job)
    assert result["decision"] == "blocked"
    assert result["counts"]["secrets"] == 1


def test_scan_cannot_be_created_with_a_policy():
    """The policy form is gone, so new_job must not take one any more."""
    import inspect

    from app.orchestrator import JobManager

    params = inspect.signature(JobManager.new_job).parameters
    assert "policy" not in params


def test_api_inspect(client, tmp_path):
    (tmp_path / "app.py").write_text("import os\n")
    res = client.post("/api/inspect", data={
        "source_kind": "path", "local_path": str(tmp_path)})
    assert res.status_code == 200
    data = res.json()
    assert data["inventory"]["total_files"] == 1
    assert data["inventory"]["languages"]["python"] == 1
    tools = {t["name"]: t for t in data["tools"]}
    assert tools["bearer"]["applicable"] is True        # python is supported
    assert tools["npm_audit"]["applicable"] is False     # no package.json
    assert "package.json" in tools["npm_audit"]["reason"]


def test_api_inspect_rejects_non_path(client):
    res = client.post("/api/inspect", data={"source_kind": "git"})
    assert res.status_code == 400


def test_api_upload_awaits_then_confirms(client, monkeypatch):
    import io
    import time
    import zipfile

    # no tools installed -> confirmed scan finishes instantly
    monkeypatch.setattr(shutil, "which", lambda name: None)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("src/app.py", "print('hi')\n")
    buf.seek(0)

    res = client.post(
        "/api/scans",
        data={"source_kind": "upload", "tools": "semgrep"},
        files={"file": ("proj.zip", buf, "application/zip")},
    )
    assert res.status_code == 201
    jid = res.json()["id"]

    # phase 1: pauses awaiting confirmation, with an inventory to review
    job = None
    for _ in range(100):
        job = client.get("/api/scans/" + jid).json()
        if job["status"] in ("awaiting_confirmation", "done", "error"):
            break
        time.sleep(0.05)
    assert job["status"] == "awaiting_confirmation"
    assert job["inventory"]["total_files"] == 1
    assert job["applicability"][0]["name"] == "semgrep"

    # phase 2: confirm -> runs to completion
    assert client.post(f"/api/scans/{jid}/confirm").status_code == 200
    for _ in range(100):
        job = client.get("/api/scans/" + jid).json()
        if job["status"] in ("done", "error"):
            break
        time.sleep(0.05)
    assert job["status"] == "done"
    assert "semgrep" in job["results"]


def test_docker_cpu_and_memory_math():
    from app.docker_stats import _cpu_percent, _memory

    stats = {
        "cpu_stats": {"cpu_usage": {"total_usage": 200},
                      "system_cpu_usage": 2000, "online_cpus": 2},
        "precpu_stats": {"cpu_usage": {"total_usage": 100},
                         "system_cpu_usage": 1000},
        "memory_stats": {"usage": 1000, "limit": 2000, "stats": {"cache": 200}},
    }
    # cpu_delta=100, sys_delta=1000, online=2 -> 100/1000*2*100 = 20.0
    assert _cpu_percent(stats) == 20.0
    mem = _memory(stats)
    assert mem["mem_used"] == 800 and mem["mem_limit"] == 2000
    assert mem["mem_pct"] == 40.0


def test_docker_stats_disabled_by_default():
    from app import docker_stats
    from app.config import config

    assert config.ENABLE_DOCKER_STATS is False
    result = docker_stats.collect()
    assert result["available"] is False
    assert "disabled" in result["reason"]
    assert result["containers"] == []


def test_api_system_reports_docker(client):
    data = client.get("/api/system").json()
    assert "docker" in data
    assert data["docker"]["available"] is False   # not enabled in tests


def test_api_confirm_wrong_state(client, tmp_path):
    # a local-path scan runs directly (no awaiting), so confirm is a 409
    import time
    res = client.post("/api/scans", data={
        "source_kind": "path", "tools": "semgrep", "local_path": str(tmp_path)})
    jid = res.json()["id"]
    for _ in range(100):
        if client.get("/api/scans/" + jid).json()["status"] in ("done", "error"):
            break
        time.sleep(0.05)
    assert client.post(f"/api/scans/{jid}/confirm").status_code == 409
    assert client.post("/api/scans/deadbeef/confirm").status_code == 404


def test_api_scan_not_found(client):
    assert client.get("/api/scans/deadbeef").status_code == 404


def test_api_rejects_bad_git_scheme(client):
    res = client.post("/api/scans", data={
        "source_kind": "git", "tools": "semgrep", "git_url": "file:///etc/passwd"})
    assert res.status_code == 400


def test_api_path_scan_end_to_end(client, tmp_path, monkeypatch):
    import time

    # Simulate no scanners installed so the job completes instantly and
    # deterministically, exercising the full HTTP + orchestration path only.
    monkeypatch.setattr(shutil, "which", lambda name: None)

    (tmp_path / "hello.py").write_text("print('hi')\n")
    res = client.post("/api/scans", data={
        "source_kind": "path", "tools": "semgrep,gitleaks",
        "local_path": str(tmp_path)})
    assert res.status_code == 201
    job_id = res.json()["id"]

    job = None
    for _ in range(100):
        job = client.get("/api/scans/" + job_id).json()
        if job["status"] in ("done", "error"):
            break
        time.sleep(0.05)
    assert job["status"] == "done"
    # both requested tools reported (as unavailable, since none are installed)
    assert set(job["results"].keys()) == {"semgrep", "gitleaks"}
    assert all(r["status"] == "unavailable" for r in job["results"].values())


# ---------------------------------------------------------------- capacity
def test_docker_capacity_verdicts():
    """Capacity answers "is this enough?", not just "what is the usage?"."""
    from app.docker_stats import _capacity

    host = 16 * 10**9
    base = {"state": "running", "mem_limit": 2 * 10**9}

    assert _capacity({**base, "mem_pct": 30.0, "cpu_pct": 25.0}, host)["level"] == "ok"
    assert _capacity({**base, "mem_pct": 80.0}, host)["level"] == "warn"
    assert _capacity({**base, "mem_pct": 94.0}, host)["level"] == "tight"

    # a limit equal to host memory means no limit was really set
    unset = _capacity({"state": "running", "mem_pct": 5.0, "mem_limit": host}, host)
    assert unset["mem_unlimited"] is True and unset["level"] == "warn"

    # hard evidence of running short outranks a merely high percentage
    assert _capacity({**base, "mem_pct": 40.0, "oom_killed": True}, host)["level"] == "tight"
    assert _capacity({**base, "mem_pct": 40.0, "throttled": True}, host)["level"] == "tight"

    # busy CPU alone is a note, not a failure: scanners are meant to use cores
    busy = _capacity({**base, "mem_pct": 20.0, "cpu_pct": 97.0}, host)
    assert busy["level"] == "warn" and "cpu_busy" in busy["reasons"]

    assert _capacity({"state": "exited"}, host)["level"] == "idle"


# ---------------------------------------------------------------- CSV export
def test_csv_export(client, tmp_path, monkeypatch):
    from app import orchestrator
    from app.adapters.base import BaseAdapter

    class A(BaseAdapter):
        name = "semgrep"
        kind = ToolKind.SAST
        binary = "semgrep"

        def probe(self):
            return True, "1.0"

        def applicable(self, d):
            return True

        def _execute(self, d):
            return [
                Finding(tool="semgrep", rule_id="r1", severity=Severity.HIGH,
                        title="eval used", file="a.py", start_line=4,
                        cwe=["CWE-95"]),
                # a file name that Excel would otherwise run as a formula
                Finding(tool="semgrep", rule_id="r2", severity=Severity.LOW,
                        title="odd", file="=cmd|'/c calc'!A1", start_line=1),
            ]

    monkeypatch.setattr(orchestrator, "get_adapters", lambda names: [A()])
    (tmp_path / "a.py").write_text("x=1\n")
    res = client.post("/api/scans", data={
        "source_kind": "path", "tools": "semgrep", "local_path": str(tmp_path),
    })
    job_id = res.json()["id"]

    # The scan runs on a worker thread, so wait for it rather than assuming it
    # finished. Without this the export can race the scan and return headers
    # with no rows -- which passed on a fast machine and failed on CI.
    import time as _time
    for _ in range(100):
        if client.get("/api/scans/" + job_id).json()["status"] in ("done", "error",
                                                                   "blocked",
                                                                   "policy_review"):
            break
        _time.sleep(0.05)

    csv_res = client.get(f"/api/scans/{job_id}/export.csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    assert f"sast-scan-{job_id}.csv" in csv_res.headers["content-disposition"]

    body = csv_res.text
    assert body.startswith("\ufeff")          # BOM so Excel reads UTF-8
    assert "eval used" in body and "CWE-95" in body
    # formula injection is defused (CWE-1236)
    assert "'=cmd" in body and "\n=cmd" not in body

    assert client.get("/api/scans/nope/export.csv").status_code == 404


def test_semgrep_ruleset_is_compatible_with_metrics_off(monkeypatch, tmp_path):
    """Regression: semgrep refuses to build the "auto" config while metrics are
    off, so the scan errors out on every run. We always pass --metrics=off (no
    code data leaves the host), so the ruleset must never be "auto"."""
    from app.adapters import semgrep
    from app.config import config

    assert config.SEMGREP_RULES != "auto"

    captured = {}

    def fake_run(args, **kw):
        captured["args"] = args
        return CommandResult(0, '{"results": []}', "")

    monkeypatch.setattr(semgrep, "run_command", fake_run)
    semgrep.SemgrepAdapter()._execute(tmp_path)

    args = captured["args"]
    assert "--metrics=off" in args
    assert args[args.index("--config") + 1] != "auto"


def test_finding_card_i18n_keys_exist_in_both_languages():
    """The finding card labels every field, so a key missing from one language
    renders the raw key to the user (a bug we shipped once already)."""
    import re

    src = (Path(__file__).resolve().parents[1] / "app/static/i18n.js").read_text("utf-8")
    needed = [
        "find.why", "find.howToFix", "find.location", "find.notProvided",
        "find.untitled", "find.upgradeTo", "find.fixAvailable", "find.noFixYet",
    ]
    for key in needed:
        # one definition per language dictionary
        assert len(re.findall(rf'"{re.escape(key)}"\s*:', src)) == 2, key


# ------------------------------------------------------------------- operator
def test_admin_status_reports_updatable_tools():
    from app import admin

    st = admin.status()
    assert st["running"] is False
    names = {t["name"] for t in st["tools_available"]}
    assert "semgrep" in names
    # Pinned binaries must be flagged, otherwise the button looks like it did
    # nothing when it silently cannot change their version.
    pinned = {t["name"] for t in st["tools_available"] if not t["in_place"]}
    assert "gitleaks" in pinned and "osv_scanner" in pinned


def test_admin_update_commands_are_fixed_argv():
    """Update commands must never be built from request input."""
    from app import admin

    cmds = admin._update_commands(["semgrep", "gitleaks", "not-a-tool"])
    assert cmds, "semgrep should be updatable"
    for _name, cmd in cmds:
        assert isinstance(cmd, list)          # argv, never a shell string
        assert all(isinstance(part, str) for part in cmd)
    # An unknown name contributes no command at all.
    assert all(n in {"semgrep", "trivy", "npm_audit"} for n, _ in cmds)


def test_admin_update_rejects_unknown_tools_via_api(monkeypatch):
    from app import admin

    started = {}
    monkeypatch.setattr(admin.threading, "Thread",
                        lambda **kw: type("T", (), {"start": lambda s: started.setdefault("ran", True)})())
    try:
        res = admin.start_update(["definitely-not-a-tool"])
        # Falls back to every known tool rather than running nothing at all.
        assert res["started"] is True
    finally:
        with admin.state.lock:
            admin.state.running = False


def test_admin_rejects_concurrent_jobs():
    """Two installs at once would fight over the same files."""
    from app import admin

    with admin.state.lock:
        admin.state.running = True
    try:
        res = admin.start_update(["semgrep"])
        assert res["started"] is False
        assert "already running" in res["reason"]
        # A restart must not interrupt an update either.
        assert admin.restart_app()["restarting"] is False
    finally:
        with admin.state.lock:
            admin.state.running = False


def test_admin_endpoints_are_post_only(client):
    """A GET must not be able to trigger an update or a restart.

    The static mount swallows unmatched routes, so a rejected GET surfaces as
    404 rather than 405; either way it must not reach the handler.
    """
    assert client.get("/api/admin/update-tools").status_code in (404, 405)
    assert client.get("/api/admin/restart").status_code in (404, 405)
    assert client.get("/api/admin/status").status_code == 200

    body = client.get("/api/admin/status").json()
    assert body["running"] is False          # a GET started nothing


@pytest.mark.parametrize("text,secret", [
    # The fake values below are spelled so that a secret scanner does not
    # mistake them for real ones: a high-entropy placeholder here costs a
    # false positive on every future scan, which teaches people to skim past
    # gitleaks output -- exactly the habit this project exists to prevent.
    ("https://user:NOT-A-REAL-SECRET@pypi.internal/simple/", "NOT-A-REAL-SECRET"),
    ("NPM_TOKEN=NOT-A-REAL-TOKEN", "NOT-A-REAL-TOKEN"),
    ("api_key: NOT-A-REAL-KEY", "NOT-A-REAL-KEY"),
    ("Authorization: Bearer NOT-A-REAL-BEARER", "NOT-A-REAL-BEARER"),
    ("Authorization: Basic NOT-A-REAL-BASIC", "NOT-A-REAL-BASIC"),
    ("machine pypi.org login bob password NOT-A-REAL-PASSWORD", "NOT-A-REAL-PASSWORD"),
    ("ERROR: cannot write /usr/local/lib/python3.11/site-packages/x", "site-packages"),
    ("config at /home/appuser/.config/pip/pip.conf", "appuser"),
    ("cannot write /usr/local/bin/trivy", "/usr/local/bin"),
    ("temp at /tmp/pip-build-abc/foo", "/tmp/pip-build"),
    ("cfg /etc/pip.conf", "/etc/pip.conf"),
])
def test_admin_log_scrubs_secrets_and_paths(text, secret):
    """/api/admin/status has no login, so the log must not carry credentials.

    Each case is a way a package manager leaks its surroundings into stdout.
    """
    from app.admin import _scrub

    assert secret not in _scrub(text)


def test_admin_log_keeps_ordinary_output_readable():
    """Scrubbing must not eat the output people actually need to read."""
    from app.admin import _scrub

    line = "Successfully installed semgrep-1.177.0"
    assert line in _scrub(line)


def test_restart_releases_the_job_slot_if_the_signal_fails():
    """If SIGTERM does not end the process, the panel must not stay locked."""
    import app.admin as admin

    with admin.state.lock:
        admin.state.running = True
        admin.state.kind = "restart"

    # Simulate the tail of _stop() after a SIGTERM that did nothing.
    with admin.state.lock:
        admin.state.running = False
        admin.state.kind = ""
        admin.state.ok = False
    assert admin.state.snapshot()["running"] is False
    # And the real code must contain that recovery path at all.
    src = (Path(__file__).resolve().parents[1] / "app/admin.py").read_text("utf-8")
    assert "RESTART_GRACE" in src
    assert src.count("state.running = False") >= 2  # update path + restart path


def test_restart_is_throttled_and_claims_the_job_slot(tmp_path, monkeypatch):
    """Repeated restarts could keep the service bouncing; one per minute.

    The marker has to live on disk: an in-memory timestamp would be erased by
    the very restart it is meant to limit, so every request would look like
    the first one (which is exactly how this failed on the real deployment).
    """
    from app import admin

    marker = tmp_path / ".last-restart"
    monkeypatch.setattr(admin, "RESTART_MARKER", marker)

    with admin.state.lock:
        admin.state.running = False

    calls = []
    original = admin.threading.Thread
    admin.threading.Thread = lambda **kw: type(
        "T", (), {"start": lambda s: calls.append(kw.get("target"))})()
    try:
        first = admin.restart_app()
        assert first["restarting"] is True
        assert marker.exists()             # survives the process going away

        # The slot is claimed inside the lock, so an update cannot slip into
        # the gap and then be killed half-way through installing.
        assert admin.start_update(["semgrep"])["started"] is False

        # Simulate the process actually restarting: in-memory state is new,
        # but the on-disk marker is still there.
        with admin.state.lock:
            admin.state.running = False
        second = admin.restart_app()
        assert second["restarting"] is False
        assert "wait" in second["reason"]
    finally:
        admin.threading.Thread = original
        with admin.state.lock:
            admin.state.running = False


def test_restart_throttle_survives_a_missing_marker(tmp_path, monkeypatch):
    """A read-only or absent volume must not block restarting entirely."""
    from app import admin

    monkeypatch.setattr(admin, "RESTART_MARKER",
                        tmp_path / "nonexistent" / ".last-restart")
    assert admin._last_restart_age() is None      # unknown, not "just now"


def test_update_always_releases_the_job_slot(monkeypatch):
    """An escaping error must not wedge the panel permanently."""
    from app import admin

    monkeypatch.setattr(admin, "_run_updates",
                        lambda tools: (_ for _ in ()).throw(RuntimeError("boom")))
    with admin.state.lock:
        admin.state.running = True
        admin.state.ok = None
    admin._run_update(["semgrep"])

    snap = admin.state.snapshot()
    assert snap["running"] is False      # released despite the error
    assert snap["ok"] is False
    assert "boom" in snap["log"]


def test_npm_is_not_updated_in_place():
    """npm -g fails as non-root and only produced noisy, leaky output."""
    from app import admin

    assert not any(n == "npm_audit" for n, _ in admin._update_commands(["npm_audit"]))


# ---------------------------------------------------------------- rule editor
@pytest.fixture()
def rules_env(tmp_path, monkeypatch):
    """Point the rule store at a temp dir so tests never touch a real one."""
    from app import rules as rules_mod
    from app.config import config

    monkeypatch.setattr(config, "RULES_DIR", tmp_path / "rules")
    return rules_mod


@pytest.mark.parametrize("name", [
    "../etc/passwd", "..\\windows", "a/b", "a\\b", "has.dot", "",
    "UPPERCASE", "-leading", "x" * 60, "with space", "semi;colon",
])
def test_rule_names_cannot_escape_the_rules_directory(rules_env, name):
    """The name becomes a filename, so anything but a plain slug is refused."""
    with pytest.raises(ValueError):
        rules_env._safe_path("semgrep", name)


def test_rule_path_stays_inside_the_rules_dir(rules_env):
    path = rules_env._safe_path("semgrep", "my-rule")
    assert path.parent == rules_env.rules_dir("semgrep").resolve()
    assert path.name == "my-rule.yaml"
    assert rules_env._safe_path("trivy", "x").name == "x.rego"


def test_builtin_templates_are_listed_and_readable(rules_env):
    names = {(r["engine"], r["name"]) for r in rules_env.list_rules()}
    assert ("semgrep", "example-dangerous-eval") in names
    assert ("trivy", "example-dockerfile-root") in names
    rule = rules_env.read_rule("semgrep", "example-dangerous-eval")
    assert rule.builtin is True
    assert "rules:" in rule.content


def test_builtin_templates_cannot_be_overwritten_or_deleted(rules_env):
    with pytest.raises(ValueError, match="built-in"):
        rules_env.save_rule("semgrep", "example-dangerous-eval", "rules: []")
    with pytest.raises(ValueError, match="built-in"):
        rules_env.delete_rule("semgrep", "example-dangerous-eval")


def test_invalid_rule_is_not_saved(rules_env, monkeypatch):
    """A rule that fails validation must never reach disk.

    Storing it would turn a typo into a scan-time error, far away from the
    editor where it was typed.
    """
    monkeypatch.setattr(rules_env, "validate_rule",
                        lambda engine, content: {"ok": False, "message": "boom"})
    with pytest.raises(ValueError, match="boom"):
        rules_env.save_rule("semgrep", "broken", "rules: [")
    assert not rules_env._safe_path("semgrep", "broken").exists()


def test_oversized_rule_is_rejected(rules_env):
    huge = "x" * (rules_env.MAX_RULE_BYTES + 1)
    with pytest.raises(ValueError, match="larger than"):
        rules_env.save_rule("semgrep", "huge", huge)


def test_empty_rule_is_rejected(rules_env):
    with pytest.raises(ValueError, match="empty"):
        rules_env.save_rule("semgrep", "blank", "   \n  ")


def test_save_read_and_delete_round_trip(rules_env, monkeypatch):
    monkeypatch.setattr(rules_env, "validate_rule",
                        lambda engine, content: {"ok": True, "message": "ok"})
    rules_env.save_rule("semgrep", "my-rule", "rules: []\n")
    assert rules_env.read_rule("semgrep", "my-rule").content == "rules: []\n"
    assert ("semgrep", "my-rule") in {(r["engine"], r["name"])
                                      for r in rules_env.list_rules()}
    rules_env.delete_rule("semgrep", "my-rule")
    with pytest.raises(FileNotFoundError):
        rules_env.read_rule("semgrep", "my-rule")


def test_materialize_copies_rules_into_the_scan(rules_env, monkeypatch, tmp_path):
    """Rules are copied per scan, so editing one mid-scan changes nothing."""
    monkeypatch.setattr(rules_env, "validate_rule",
                        lambda engine, content: {"ok": True, "message": ""})
    rules_env.save_rule("semgrep", "r1", "rules: []\n")

    dest = tmp_path / "job" / "semgrep"
    paths = rules_env.materialize("semgrep", ["r1", "does-not-exist"], dest)
    assert [p.name for p in paths] == ["r1.yaml"]
    assert paths[0].read_text("utf-8") == "rules: []\n"

    # Editing the stored rule afterwards must not change the copy.
    rules_env.save_rule("semgrep", "r1", "rules: [changed]\n")
    assert paths[0].read_text("utf-8") == "rules: []\n"


def test_validation_is_honest_when_the_scanner_is_missing(rules_env, monkeypatch):
    """Never claim a rule is fine when nothing actually checked it."""
    monkeypatch.setattr(rules_env.shutil, "which", lambda name: None)
    result = rules_env.validate_rule("semgrep", "rules: []")
    assert result["ok"] is False
    assert result.get("checked") is False
    assert "not installed" in result["message"]


def test_semgrep_adapter_adds_custom_rules_to_the_default_config(monkeypatch, tmp_path):
    """A custom rule must add to the registry rulesets, not replace them."""
    from app.adapters import semgrep
    from app.config import config

    captured = {}

    def fake_run(args, **kw):
        captured["args"] = args
        return CommandResult(0, '{"results": []}', "")

    monkeypatch.setattr(semgrep, "run_command", fake_run)
    adapter = semgrep.SemgrepAdapter()
    adapter.custom_rules = [tmp_path / "mine.yaml"]
    adapter._execute(tmp_path)

    args = captured["args"]
    configs = [args[i + 1] for i, a in enumerate(args) if a == "--config"]
    # Every default ruleset is still there, with the custom rule added to it.
    assert "p/default" in configs
    assert str(tmp_path / "mine.yaml") in configs
    assert len(configs) == len(config.SEMGREP_RULESETS) + 1


def test_api_rules_endpoints(client):
    res = client.get("/api/rules")
    assert res.status_code == 200
    body = res.json()
    assert set(body["engines"]) == {"semgrep", "trivy"}
    assert any(r["builtin"] for r in body["rules"])

    # a built-in is readable
    r = client.get("/api/rules/semgrep/example-dangerous-eval")
    assert r.status_code == 200 and r.json()["builtin"] is True

    # and protected
    assert client.post("/api/rules/semgrep/example-dangerous-eval",
                       data={"content": "rules: []"}).status_code == 400
    assert client.delete("/api/rules/semgrep/example-dangerous-eval").status_code == 400
    assert client.get("/api/rules/semgrep/missing").status_code == 404


@pytest.mark.parametrize("rego,blocked", [
    ("resp := http.send({})", True),
    ("resp := http.send ({})", True),           # space before the paren
    ("resp:=http.send(x)", True),               # no spaces at all
    ("rt := opa.runtime().env", True),
    ("x := net.lookup_ip_addr(\"h\")", True),
    ("y := trace(\"m\")", True),
    ("# do not use http.send() here", False),   # a comment may mention it
    ("msg := \"http.send is banned\"", False),  # so may a string
    ("deny contains r if { input.x == 1 }", False),
])
def test_rego_network_builtins_are_refused(rules_env, rego, blocked):
    """Rego is a real language and Trivy gives it OPA's full built-in set.

    Verified on the deployment: a rule calling http.send made a live request
    out of the container and got a 200 back. With no login in front of the
    editor that is a way to probe the internal network, so these built-ins are
    refused before the rule is ever stored or run.
    """
    assert bool(rules_env.check_rego_builtins(rego)) is blocked


def test_rego_guard_runs_before_the_rule_does(rules_env, monkeypatch):
    """Validation executes the rule, so the check must come first."""
    ran = {"subprocess": False}

    def fake_run(*a, **kw):
        ran["subprocess"] = True
        raise AssertionError("the rule must not be executed")

    monkeypatch.setattr(rules_env.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(rules_env.subprocess, "run", fake_run)

    result = rules_env.validate_rule("trivy", "deny if { http.send({}) }")
    assert result["ok"] is False
    assert "http.send" in result["message"]
    assert ran["subprocess"] is False


def test_rule_count_is_capped(rules_env, monkeypatch):
    """The name space is large enough to fill a volume one rule at a time."""
    monkeypatch.setattr(rules_env, "validate_rule",
                        lambda engine, content: {"ok": True, "message": ""})
    monkeypatch.setattr(rules_env, "MAX_RULES_PER_ENGINE", 3)
    for i in range(3):
        rules_env.save_rule("semgrep", f"rule-{i}", "rules: []\n")
    with pytest.raises(ValueError, match="at most 3"):
        rules_env.save_rule("semgrep", "one-too-many", "rules: []\n")
    # Overwriting one that already exists is still fine at the cap.
    rules_env.save_rule("semgrep", "rule-0", "rules: [updated]\n")


def test_save_is_atomic(rules_env, monkeypatch):
    """A crash mid-write must not leave half a rule for a scan to run."""
    monkeypatch.setattr(rules_env, "validate_rule",
                        lambda engine, content: {"ok": True, "message": ""})
    rules_env.save_rule("semgrep", "atomic", "rules: []\n")
    path = rules_env._safe_path("semgrep", "atomic")

    real_replace = rules_env.os.replace
    monkeypatch.setattr(rules_env.os, "replace",
                        lambda *a: (_ for _ in ()).throw(OSError("crash")))
    with pytest.raises(OSError):
        rules_env.save_rule("semgrep", "atomic", "rules: [broken half")
    # The original survived; the partial write went to a temp file instead.
    monkeypatch.setattr(rules_env.os, "replace", real_replace)
    assert path.read_text("utf-8") == "rules: []\n"


def test_name_with_trailing_newline_is_rejected(rules_env):
    """"$" also matches before a trailing newline; \Z does not."""
    with pytest.raises(ValueError):
        rules_env._safe_path("semgrep", "abc\n")


def test_semgrep_scan_bounds_runaway_rules(monkeypatch, tmp_path):
    """A custom regex can backtrack forever; semgrep must give up on it."""
    from app.adapters import semgrep

    captured = {}
    monkeypatch.setattr(semgrep, "run_command",
                        lambda args, **kw: (captured.update(args=args),
                                            CommandResult(0, '{"results": []}', ""))[1])
    semgrep.SemgrepAdapter()._execute(tmp_path)
    args = captured["args"]
    assert "--timeout" in args
    assert "--timeout-threshold" in args


def test_custom_rule_id_drops_the_workspace_path():
    """A rule loaded from a file is reported by its path; show the id instead."""
    from app.adapters.semgrep import _clean_check_id

    assert _clean_check_id(
        "data.workspaces.abc123.rules.semgrep.no-pickle-loads") == "no-pickle-loads"
    # A registry rule keeps its full, meaningful identifier.
    registry = "python.lang.security.deserialization.pickle.avoid-pickle"
    assert _clean_check_id(registry) == registry


# ------------------------------------------------------------------ rulesets
def test_rulesets_endpoint_never_offers_auto(client):
    """"auto" cannot work here: semgrep refuses it while metrics are off."""
    res = client.get("/api/rulesets")
    assert res.status_code == 200
    body = res.json()
    ids = [r["id"] for r in body["semgrep"]]
    assert "auto" not in ids
    assert "p/default" in ids and "p/owasp-top-ten" in ids
    # Every published ruleset is on by default: semgrep unions them, so more
    # rulesets means more coverage rather than a different set.
    assert body["default"] == ids


def test_unknown_rulesets_are_dropped(client, tmp_path, monkeypatch):
    """A request must not be able to point semgrep at an arbitrary location."""
    from app import orchestrator

    monkeypatch.setattr(orchestrator, "get_adapters", lambda names: [])
    (tmp_path / "a.py").write_text("x = 1\n")
    res = client.post("/api/scans", data={
        "source_kind": "path", "tools": "semgrep", "local_path": str(tmp_path),
        "rulesets": json.dumps({"semgrep": ["p/default", "/etc/passwd",
                                            "https://evil.test/rules.yaml"]}),
    })
    assert res.status_code == 201
    job = orchestrator.manager.get(res.json()["id"])
    assert job.rulesets["semgrep"] == ["p/default"]


def test_semgrep_runs_every_selected_ruleset(monkeypatch, tmp_path):
    from app.adapters import semgrep

    captured = {}
    monkeypatch.setattr(semgrep, "run_command",
                        lambda args, **kw: (captured.update(args=args),
                                            CommandResult(0, '{"results": []}', ""))[1])
    adapter = semgrep.SemgrepAdapter()
    adapter.rulesets = ["p/default", "p/owasp-top-ten"]
    adapter._execute(tmp_path)

    args = captured["args"]
    configs = [args[i + 1] for i, a in enumerate(args) if a == "--config"]
    assert configs == ["p/default", "p/owasp-top-ten"]


# -------------------------------------------------------------------- stages
def test_each_tool_names_its_own_first_stage():
    """"running" for eight minutes says nothing; the work differs per tool."""
    from app.adapters import ADAPTERS

    stages = {a.name: a.first_stage for a in ADAPTERS}
    assert stages["trivy"] == "vulndb"        # downloads a database
    assert stages["semgrep"] == "rules"       # fetches and compiles rules
    assert stages["gitleaks"] == "secrets"    # neither of the above
    assert stages["bearer"] == "dataflow"
    assert len(set(stages.values())) > 1      # not all the same word


def test_adapter_reports_its_stages_in_order(monkeypatch, tmp_path):
    from app.adapters import semgrep

    seen = []
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(semgrep, "run_command",
                        lambda args, **kw: CommandResult(0, "1.0", "")
                        if "--version" in args
                        else CommandResult(0, '{"results": []}', ""))
    adapter = semgrep.SemgrepAdapter()
    adapter._on_stage = seen.append
    adapter.scan(tmp_path)

    assert seen == ["probing", "checking", "rules"]


def test_stage_reporting_never_breaks_a_scan(monkeypatch, tmp_path):
    """Progress is cosmetic; a failure there must not fail the scan."""
    from app.adapters import semgrep

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(semgrep, "run_command",
                        lambda args, **kw: CommandResult(0, "1.0", "")
                        if "--version" in args
                        else CommandResult(0, '{"results": []}', ""))
    adapter = semgrep.SemgrepAdapter()
    adapter._on_stage = lambda stage: (_ for _ in ()).throw(RuntimeError("boom"))
    result = adapter.scan(tmp_path)
    assert result.status == ToolStatus.OK


def test_pdf_export_renders_every_finding_first():
    """The list is paged, and printing captures only what is in the DOM.

    A PDF that silently stopped at the first hundred findings would be worse
    than a slow one: the person reading it would not know any were missing.
    """
    src = (Path(__file__).resolve().parents[1] / "app/static/app.js").read_text("utf-8")
    export = src[src.index('$("#export-pdf")'):]
    export = export[:export.index("});") + 3]
    assert "renderAll" in export
    assert export.index("renderAll") < export.index("window.print")


def test_manual_review_verdict_survives_without_the_form():
    """The form is gone, but the verdict still has to reach the export."""
    from app.models import Job, ScanTarget, ToolResult
    from app.policies import evaluate_policy

    job = Job(
        id="r", target=ScanTarget(kind="git", display="x"),
        results={"semgrep": ToolResult(
            tool="semgrep", kind=ToolKind.SAST, status=ToolStatus.OK,
            findings=[Finding(tool="semgrep", rule_id="r1",
                              severity=Severity.MEDIUM)])},
    )
    result = evaluate_policy(job)
    assert result["decision"] == "manual_review"
    assert len(result["manual_review_findings"]) == 1


# ------------------------------------------------------ judging a finding
def test_bearer_findings_carry_the_offending_code():
    """Without the code, a false positive and a real bug read identically.

    This is not hypothetical: scanning this project reported a Critical OS
    command injection against the one function that exists to prevent it, and
    nothing on the card let a reader see that.
    """
    from app.adapters.bearer import _parse

    sample = {"critical": [{
        "id": "python_lang_os_command_injection",
        "title": "Unsanitized user input in OS command",
        "description": "...",
        "filename": "app/adapters/base.py",
        "line_number": 41,
        "cwe_ids": ["78"],
        "code_extract": "proc = subprocess.run(args, shell=False, timeout=t)",
    }]}
    findings = _parse(sample, Path("."))
    assert findings[0].extra["snippet"] == (
        "proc = subprocess.run(args, shell=False, timeout=t)")


def test_bearer_snippet_is_bounded():
    from app.adapters.bearer import MAX_SNIPPET_CHARS, MAX_SNIPPET_LINES, _snippet

    assert _snippet(None) == ""
    assert _snippet("") == ""
    long_code = "\n".join("line %d" % i for i in range(100))
    assert len(_snippet(long_code).splitlines()) == MAX_SNIPPET_LINES
    assert len(_snippet("x" * 5000)) <= MAX_SNIPPET_CHARS


def test_every_finding_card_offers_a_judgement():
    """A reader needs somewhere to record that a finding is a false positive,
    or it gets re-argued on every scan and the noise trains people to skim."""
    src = (Path(__file__).resolve().parents[1] / "app/static/app.js").read_text("utf-8")
    assert "renderTriage" in src
    assert "card.appendChild(renderTriage(f))" in src
    # The mark has to identify the finding across scans, not by list position.
    assert "function findingKey(f)" in src
    assert "f.tool, f.rule_id, f.file, f.start_line" in src


def test_triage_marks_print_but_the_buttons_do_not():
    """The PDF should carry the judgement, not the controls that set it."""
    css = (Path(__file__).resolve().parents[1] / "app/static/style.css").read_text("utf-8")
    print_block = css[css.index("@media print"):]
    print_block = print_block[:print_block.index("\n}\n")]
    assert ".tri-btn" in print_block          # buttons hidden
    assert ".tri-mark" in print_block         # mark kept


def test_nginx_config_does_not_name_the_host_variable():
    """Semgrep's request-host-used rule matches text, comments included.

    Proven with an A/B scan: two configs with an identical, already-fixed
    proxy_set_header directive, differing only by a comment that names the
    variable -- 0 findings without it, 1 finding (pointing at the comment
    line) with it. Explaining why something is avoided must not look like
    doing it.
    """
    conf = (Path(__file__).resolve().parents[1] / "nginx/nginx.conf").read_text("utf-8")
    # The Host the backend receives must stay a fixed value, so nothing
    # downstream can build a link from a header the client controls.
    assert "proxy_set_header Host              sast-studio;" in conf
    assert "proxy_set_header Host              $host" not in conf

    # X-Forwarded-Host does carry the client's value, deliberately: the CSRF
    # check needs to know what the browser actually asked for, and rewriting
    # Host had made every legitimate form post look cross-site. It is compared
    # against the request's own Origin, never used to build anything.
    forwarded = [l for l in conf.splitlines() if "$http_host" in l]
    assert len(forwarded) == 1
    assert "X-Forwarded-Host" in forwarded[0]


# ------------------------------------------------------------ page load speed
def test_tool_probes_run_in_parallel():
    """Six sequential "--version" calls cost ~2.4s on every page load.

    semgrep and bearer are ~900ms each, so the total was the sum rather than
    the slowest. They do not depend on each other.
    """
    src = (Path(__file__).resolve().parents[1] / "app/main.py").read_text("utf-8")
    block = src[src.index("def probe_all()"):]
    block = block[:block.index("\n\n")]
    assert "ThreadPoolExecutor" in block
    assert "pool.map" in block


def test_tool_probe_result_is_cached_and_cleared_by_an_update():
    """A version only changes when someone updates a scanner.

    Caching it is safe only if updating clears it -- a stale version after an
    update looks exactly like an update that did not work.
    """
    from app.main import _tool_cache

    _tool_cache.clear()
    assert _tool_cache.get() is None

    _tool_cache.set([{"name": "semgrep", "version": "1.0"}])
    assert _tool_cache.get()[0]["version"] == "1.0"

    _tool_cache.clear()
    assert _tool_cache.get() is None

    # The update endpoint must be the thing that clears it.
    src = (Path(__file__).resolve().parents[1] / "app/main.py").read_text("utf-8")
    update = src[src.index("async def admin_update_tools"):]
    update = update[:update.index("@app.")]
    assert "_tool_cache.clear()" in update


def test_tool_cache_expires():
    """A scanner can also be changed from outside the app."""
    import time as _time

    from app.main import _ToolCache

    cache = _ToolCache()
    cache.TTL = 0.01
    cache.set([{"name": "x"}])
    _time.sleep(0.02)
    assert cache.get() is None


def test_startup_requests_are_not_serialised():
    """Awaiting each load in turn made the page sit blank for the slowest."""
    src = (Path(__file__).resolve().parents[1] / "app/static/app.js").read_text("utf-8")
    init = src[src.index("async function init()"):]
    init = init[:init.index("\n}")]
    assert "Promise.all" in init
    # And one failing endpoint must not blank the rest of the page.
    assert ".catch(" in init


def test_cached_tools_response_is_identical_to_an_uncached_one(client):
    """A cache must be invisible to callers.

    Caching only the tools list meant a hit returned {tools, cached} while a
    miss returned {tools, config}. The UI read .config.allow_local_path, so
    every page load after the first threw and took the Monitor tab's version
    list down with it -- while the header, rendered earlier, still worked.
    """
    from app.main import _tool_cache

    _tool_cache.clear()
    miss = client.get("/api/tools").json()      # populates the cache
    hit = client.get("/api/tools").json()       # served from it

    assert sorted(miss.keys()) == sorted(hit.keys())
    assert miss == hit
    # The field the UI actually depends on.
    assert "config" in hit
    assert "allow_local_path" in hit["config"]


def test_monitor_tab_survives_a_response_without_config():
    """Defence in depth: the page should degrade, not blank out."""
    src = (Path(__file__).resolve().parents[1] / "app/static/app.js").read_text("utf-8")
    load = src[src.index("async function loadTools()"):]
    load = load[:load.index("\n}")]
    # Never dereference .config directly; it must be guarded.
    assert "state.toolsData.config.allow_local_path" not in load
    assert "state.toolsData.config || {}" in load


# ====================================================================
# accounts, tokens and MCP
# ====================================================================
@pytest.fixture()
def accounts_env(tmp_path, monkeypatch):
    """A fresh account store per test, so none of them share state."""
    from app import accounts
    from app.config import config

    monkeypatch.setattr(config, "ACCOUNTS_DB", tmp_path / "accounts.db")
    accounts.init_db()
    return accounts


def test_passwords_are_hashed_not_stored(accounts_env):
    """A stolen database must not hand over anyone's password."""
    user = accounts_env.create_user("alice", "a-long-enough-password")
    import sqlite3

    with sqlite3.connect(accounts_env._db_path()) as conn:
        stored = conn.execute("SELECT password FROM users WHERE id = ?",
                              (user.id,)).fetchone()[0]
    assert "a-long-enough-password" not in stored
    assert stored.startswith("scrypt$")
    # The parameters travel with the hash so the cost can be raised later
    # without invalidating every existing password.
    assert stored.split("$")[1] == str(accounts_env.SCRYPT_N)
    assert accounts_env.verify_password("a-long-enough-password", stored)
    assert not accounts_env.verify_password("wrong", stored)


def test_authenticate_rejects_wrong_password_and_disabled_users(accounts_env):
    user = accounts_env.create_user("bob", "bob-password-1234")
    assert accounts_env.authenticate("bob", "bob-password-1234") is not None
    assert accounts_env.authenticate("bob", "nope") is None
    assert accounts_env.authenticate("nobody", "anything") is None

    accounts_env.create_user("admin", "admin-password-x1", is_admin=True)
    accounts_env.set_disabled(user.id, True)
    assert accounts_env.authenticate("bob", "bob-password-1234") is None


def test_the_last_administrator_cannot_be_removed(accounts_env):
    """Otherwise a single click locks everybody out of the deployment."""
    admin = accounts_env.create_user("admin", "admin-password-x1", is_admin=True)

    with pytest.raises(ValueError, match="last"):
        accounts_env.set_disabled(admin.id, True)
    with pytest.raises(ValueError, match="last"):
        accounts_env.set_admin(admin.id, False)
    with pytest.raises(ValueError, match="last"):
        accounts_env.delete_user(admin.id)

    # With a second administrator, the first may go.
    accounts_env.create_user("admin2", "another-password-1", is_admin=True)
    accounts_env.set_disabled(admin.id, True)


def test_changing_a_password_ends_every_session(accounts_env):
    """A password is usually changed because it leaked."""
    user = accounts_env.create_user("carol", "carol-password-12")
    token = accounts_env.start_session(user.id)
    assert accounts_env.session_user(token) is not None

    accounts_env.set_password(user.id, "carol-new-password-9")
    assert accounts_env.session_user(token) is None


def test_api_token_is_bound_to_its_user(accounts_env):
    """A token is that person acting, so it follows their account."""
    accounts_env.create_user("admin", "admin-password-x1", is_admin=True)
    user = accounts_env.create_user("dave", "dave-password-1234")
    record, secret = accounts_env.create_token(user.id, "ci")

    assert accounts_env.token_user(secret).username == "dave"

    accounts_env.set_disabled(user.id, True)
    assert accounts_env.token_user(secret) is None, "a disabled user's token must die"

    accounts_env.set_disabled(user.id, False)
    assert accounts_env.token_user(secret) is not None

    accounts_env.revoke_token(record.id)
    assert accounts_env.token_user(secret) is None


def test_token_secret_is_not_recoverable(accounts_env):
    """Only a hash is stored, so "show it again" is impossible by design."""
    user = accounts_env.create_user("erin", "erin-password-1234")
    record, secret = accounts_env.create_token(user.id, "mcp")

    import sqlite3

    with sqlite3.connect(accounts_env._db_path()) as conn:
        row = conn.execute("SELECT token_hash FROM api_tokens WHERE id = ?",
                           (record.id,)).fetchone()
    assert secret not in row[0]
    # Listing never carries the secret either.
    assert all(not hasattr(tk, "token") for tk in accounts_env.list_tokens())


def test_a_user_cannot_revoke_someone_elses_token(accounts_env):
    one = accounts_env.create_user("f1", "f1-password-12345")
    two = accounts_env.create_user("f2", "f2-password-12345")
    record, secret = accounts_env.create_token(one.id, "theirs")

    assert accounts_env.revoke_token(record.id, user_id=two.id) is False
    assert accounts_env.token_user(secret) is not None
    assert accounts_env.revoke_token(record.id, user_id=one.id) is True


def test_first_admin_password_is_generated_not_fixed(accounts_env, monkeypatch):
    """A fixed default would be a backdoor on every deployment."""
    monkeypatch.delenv("SAST_ADMIN_PASSWORD", raising=False)
    password = accounts_env.ensure_first_admin()
    assert password and len(password) >= 20

    # Runs once: a second call must not reset the account.
    assert accounts_env.ensure_first_admin() is None


# ------------------------------------------------------------------- MCP
def test_mcp_refuses_an_unknown_method():
    from app import mcp

    reply = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "nope"}, None)
    assert reply["error"]["code"] == mcp.METHOD_NOT_FOUND


def test_mcp_notification_gets_no_reply():
    """A JSON-RPC notification has no id and must not be answered."""
    from app import mcp

    assert mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"},
                      None) is None


def test_mcp_initialize_reports_the_protocol_version():
    from app import mcp

    reply = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, None)
    assert reply["result"]["protocolVersion"] == mcp.PROTOCOL_VERSION
    assert "tools" in reply["result"]["capabilities"]


def test_mcp_tools_have_schemas():
    """A client picks a tool from its schema; a missing one makes it unusable."""
    from app import mcp

    reply = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, None)
    for tool in reply["result"]["tools"]:
        assert tool["name"] and tool["description"]
        assert tool["inputSchema"]["type"] == "object"


def test_mcp_applies_the_same_git_url_rules_as_the_web_form():
    """An assistant is not a more trusted caller than a person."""
    from app import mcp

    reply = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "scan_git_repository",
                                   "arguments": {"git_url": "file:///etc/passwd"}}},
                       None)
    assert reply["result"]["isError"] is True
    assert "scheme" in reply["result"]["content"][0]["text"]


def test_mcp_endpoint_requires_a_token_when_auth_is_on(monkeypatch):
    from fastapi.testclient import TestClient

    from app.config import config
    from app.main import app

    monkeypatch.setattr(config, "REQUIRE_AUTH", True)
    with TestClient(app) as client:
        res = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                        "method": "tools/list"})
    assert res.status_code == 401
    # Tell the client how to authenticate rather than just refusing.
    assert res.headers.get("www-authenticate") == "Bearer"
    assert res.json()["error"]["code"] == -32001


def test_mcp_rejects_a_foreign_origin(monkeypatch):
    """The MCP spec requires this: it is what stops DNS rebinding."""
    from fastapi.testclient import TestClient

    from app.config import config
    from app.main import app

    monkeypatch.setattr(config, "REQUIRE_AUTH", False)
    with TestClient(app) as client:
        res = client.post("/mcp",
                          json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                          headers={"Origin": "http://evil.example"})
    assert res.status_code == 403


def test_mcp_get_reports_no_server_stream(monkeypatch):
    from fastapi.testclient import TestClient

    from app.config import config
    from app.main import app

    monkeypatch.setattr(config, "REQUIRE_AUTH", False)
    with TestClient(app) as client:
        res = client.get("/mcp")
    assert res.status_code == 405
    assert res.headers.get("allow") == "POST"


def test_mcp_findings_carry_the_code(accounts_env, monkeypatch, tmp_path):
    """Without the code, an assistant cannot tell a real bug from a pattern."""
    import time as _time

    from app import mcp, orchestrator
    from app.adapters.base import BaseAdapter
    from app.models import ScanTarget

    class Fake(BaseAdapter):
        name = "semgrep"
        kind = ToolKind.SAST
        binary = "semgrep"

        def probe(self):
            return True, "1.0"

        def applicability(self, target_dir):
            return True, ""

        def _execute(self, target_dir):
            return [Finding(tool="semgrep", rule_id="dangerous-eval",
                            severity=Severity.HIGH, title="eval on user input",
                            file="a.py", start_line=12, cwe=["CWE-95"],
                            extra={"snippet": "eval(request.args['q'])"})]

    monkeypatch.setattr(orchestrator, "get_adapters", lambda names: [Fake()])
    (tmp_path / "a.py").write_text("x = 1\n")
    mgr = orchestrator.JobManager()
    monkeypatch.setattr(mcp, "manager", mgr)
    job = mgr.new_job(ScanTarget(kind="path", display=str(tmp_path)), ["semgrep"])
    mgr._prepare_and_maybe_scan(job.id, {"kind": "path", "path": str(tmp_path)}, False)

    out = json.loads(mcp._read_scan({"scan_id": job.id})["content"][0]["text"])
    assert out["verdict"] == "blocked"
    assert out["findings"][0]["code"] == "eval(request.args['q'])"
    assert out["findings"][0]["cwe"] == ["CWE-95"]

    # Severity filtering keeps a large scan readable for an assistant.
    high_only = json.loads(
        mcp._read_scan({"scan_id": job.id, "severity": "critical"})["content"][0]["text"])
    assert high_only["findings"] == []


def test_every_state_changing_route_is_behind_the_auth_gate(monkeypatch):
    """Forgetting one route is how these holes appear.

    Routes rely on the middleware rather than a per-route dependency, so this
    walks the real route table instead of a hand-written list: a new endpoint
    is covered the moment it is added, or this fails.
    """
    from fastapi.testclient import TestClient

    from app.config import config
    from app.main import SESSION_COOKIE, app

    monkeypatch.setattr(config, "REQUIRE_AUTH", True)

    # These must work before anyone can sign in, or nobody ever could.
    public = {"/api/health", "/api/auth/login", "/api/auth/whoami", "/mcp"}

    reachable = []
    with TestClient(app) as client:
        client.cookies.delete(SESSION_COOKIE)
        for route in app.routes:
            path = getattr(route, "path", "")
            methods = getattr(route, "methods", set()) or set()
            if path in public or not path.startswith("/api/"):
                continue
            for method in methods & {"POST", "PUT", "PATCH", "DELETE"}:
                # Fill path params with something harmless.
                concrete = path.replace("{job_id}", "x").replace("{user_id}", "1")
                concrete = concrete.replace("{token_id}", "1")
                concrete = concrete.replace("{engine}", "semgrep").replace("{name}", "x")
                res = client.request(method, concrete, follow_redirects=False)
                if 200 <= res.status_code < 300:
                    reachable.append(f"{method} {concrete}")

    assert not reachable, f"reachable without signing in: {reachable}"


# ====================================================================
# authorisation: signing in is not the same as being allowed
# ====================================================================
@pytest.fixture()
def two_users(tmp_path, monkeypatch):
    """An administrator and an ordinary user, both signed in."""
    from fastapi.testclient import TestClient

    from app import accounts
    from app.config import config
    from app.main import app

    monkeypatch.setattr(config, "ACCOUNTS_DB", tmp_path / "accounts.db")
    monkeypatch.setattr(config, "REQUIRE_AUTH", True)
    accounts.init_db()
    accounts.create_user("admin", "admin-password-1234", is_admin=True)
    accounts.create_user("bob", "bob-password-123456")

    admin = TestClient(app)
    admin.post("/api/auth/login",
               data={"username": "admin", "password": "admin-password-1234"})
    user = TestClient(app)
    user.post("/api/auth/login",
              data={"username": "bob", "password": "bob-password-123456"})
    return admin, user


# A valid body where the endpoint requires one: FastAPI validates the body
# before the handler runs, so an empty request returns 422 and never reaches
# the authorisation check. Sending a well-formed request is what proves the
# guard is what refuses it.
@pytest.mark.parametrize("method,path,body", [
    ("GET", "/api/admin/status", None),
    ("POST", "/api/admin/update-tools", None),
    ("POST", "/api/admin/restart", None),
    ("POST", "/api/inspect", {"source_kind": "path", "local_path": "/tmp"}),
    ("POST", "/api/rules/semgrep/x", {"content": "rules: []"}),
    ("DELETE", "/api/rules/semgrep/x", None),
    ("GET", "/api/users", None),
    ("POST", "/api/users", {"username": "new", "password": "a-password-1234"}),
])
def test_operator_endpoints_need_an_administrator(two_users, method, path, body):
    """Restarting the service and reading server paths are not ordinary acts.

    The first version of this shipped with only the middleware, which answers
    "are you signed in" -- so any account could install packages and restart
    the service. Authentication is not authorisation.
    """
    _admin, user = two_users
    assert user.request(method, path, data=body).status_code == 403


def test_a_scan_belongs_to_whoever_started_it(two_users, monkeypatch):
    """Findings quote the scanned source, so a scan is not public."""
    from app import orchestrator
    from app.models import ScanTarget

    admin, user = two_users
    job = orchestrator.manager.new_job(
        ScanTarget(kind="git", display="https://github.com/x/y"),
        ["semgrep"], owner="admin")

    # 404 rather than 403: "exists but is not yours" is information.
    assert user.get(f"/api/scans/{job.id}").status_code == 404
    assert user.get(f"/api/scans/{job.id}/export.csv").status_code == 404
    assert job.id not in [j["id"] for j in user.get("/api/scans").json()["jobs"]]

    # The owner, and an administrator, can read it.
    assert admin.get(f"/api/scans/{job.id}").status_code == 200


def test_cross_site_state_changes_are_refused(two_users):
    """SameSite=Lax is one flag in the browser's hands; check server-side too."""
    _admin, user = two_users
    assert user.post("/api/tokens", data={"name": "x"},
                     headers={"Origin": "http://evil.example"}).status_code == 403
    # A same-origin request is unaffected.
    assert user.post("/api/tokens", data={"name": "ok"}).status_code == 201


def test_a_bearer_token_is_not_subject_to_csrf(two_users):
    """A token is not attached by the browser, so it cannot be abused this way."""
    _admin, user = two_users
    token = user.post("/api/tokens", data={"name": "cli"}).json()["token"]
    user.cookies.clear()
    res = user.get("/api/tools", headers={"Authorization": "Bearer " + token,
                                          "Origin": "http://elsewhere.example"})
    assert res.status_code == 200


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://localhost:8000/x",
    "http://127.0.0.1/x",
    "https://[::1]/x",
    "http://10.0.0.5/internal.git",
])
def test_git_urls_cannot_reach_the_internal_network(url):
    """Cloning is a request this server makes, so the address matters."""
    from app.source import SourceError, validate_git_url

    with pytest.raises(SourceError, match="private, loopback or link-local"):
        validate_git_url(url)


def test_a_public_git_url_is_still_accepted():
    from app.source import validate_git_url

    assert validate_git_url("https://github.com/example/repo.git")


def test_session_cookie_is_secure_behind_a_tls_proxy(two_users):
    """nginx terminates TLS and forwards http, so request.url.scheme lies."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        res = client.post("/api/auth/login",
                          data={"username": "admin", "password": "admin-password-1234"},
                          headers={"X-Forwarded-Proto": "https"})
    cookie = res.headers.get("set-cookie", "")
    assert "Secure" in cookie
    assert "HttpOnly" in cookie


def test_changing_a_password_revokes_api_tokens(accounts_env):
    """A password is changed because it leaked; a token is another way in."""
    user = accounts_env.create_user("gina", "gina-password-1234")
    _record, secret = accounts_env.create_token(user.id, "ci")
    assert accounts_env.token_user(secret) is not None

    accounts_env.set_password(user.id, "gina-new-password-99")
    assert accounts_env.token_user(secret) is None


def test_login_takes_the_same_time_for_a_missing_user(accounts_env):
    """A measurable difference is a way to enumerate accounts.

    The first version hashed a dummy and then verified it, doing two scrypt
    passes on the miss path -- twice the work, and the opposite of the intent.
    """
    import statistics
    import time

    accounts_env.create_user("realuser", "real-password-12345")

    def median_ms(username):
        samples = []
        for _ in range(7):
            start = time.perf_counter()
            accounts_env.authenticate(username, "wrong-password-xx")
            samples.append(time.perf_counter() - start)
        return statistics.median(samples) * 1000

    existing = median_ms("realuser")
    missing = median_ms("nosuchuser")
    ratio = max(existing, missing) / max(min(existing, missing), 0.001)
    assert ratio < 1.5, f"timing differs by {ratio:.2f}x, which leaks whether a user exists"


def test_mcp_scan_results_are_not_readable_by_another_token(accounts_env, monkeypatch):
    """A token reads its owner's scans, not everyone's."""
    from app import mcp, orchestrator
    from app.config import config
    from app.models import ScanTarget

    monkeypatch.setattr(config, "REQUIRE_AUTH", True)
    mgr = orchestrator.JobManager()
    monkeypatch.setattr(mcp, "manager", mgr)

    owner = accounts_env.create_user("owner", "owner-password-1234")
    other = accounts_env.create_user("other", "other-password-1234")
    job = mgr.new_job(ScanTarget(kind="git", display="https://github.com/x/y"),
                      ["semgrep"], owner="owner")

    assert mcp._read_scan({"scan_id": job.id}, owner)      # the owner may read it
    with pytest.raises(ValueError, match="no scan"):
        mcp._read_scan({"scan_id": job.id}, other)


def test_login_works_from_a_browser_behind_the_proxy(tmp_path, monkeypatch):
    """The CSRF check must not refuse the site's own login form.

    nginx rewrites Host to a fixed value on purpose, so comparing Origin
    against Host made every legitimate form post look cross-site and nobody
    could sign in. Two correct fixes collided; this pins the combination.
    """
    from fastapi.testclient import TestClient

    from app import accounts
    from app.config import config
    from app.main import app

    monkeypatch.setattr(config, "ACCOUNTS_DB", tmp_path / "accounts.db")
    monkeypatch.setattr(config, "REQUIRE_AUTH", True)
    accounts.init_db()
    accounts.create_user("admin", "admin-password-1234", is_admin=True)

    # What the backend sees behind nginx.
    proxied = {"Host": "sast-studio",
               "X-Forwarded-Host": "192.168.99.145:8080"}

    with TestClient(app, base_url="http://192.168.99.145:8080") as client:
        good = client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "admin-password-1234"},
            headers={**proxied, "Origin": "http://192.168.99.145:8080"})
        assert good.status_code == 200, "the site's own login form was refused"

        # And the protection still works: this is the attack it exists for.
        evil = client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "admin-password-1234"},
            headers={**proxied, "Origin": "http://evil.example"})
        assert evil.status_code == 403


def test_every_view_tab_has_a_section_that_showview_toggles():
    """A tab whose section is never un-hidden renders an empty page.

    The Settings tab shipped like that: the markup and the handler existed,
    but showView only toggled the three views that predated it.
    """
    import re

    root = Path(__file__).resolve().parents[1] / "app/static"
    html = (root / "index.html").read_text("utf-8")
    js = (root / "app.js").read_text("utf-8")

    tabs = set(re.findall(r'class="viewtab[^"]*"[^>]*data-view="(\w+)"', html))
    tabs |= set(re.findall(r'data-view="(\w+)"[^>]*class="viewtab', html))
    assert tabs, "no view tabs found; the selector needs updating"

    show_view = js[js.index("function showView(view)"):]
    show_view = show_view[:show_view.index("\n}")]

    for tab in sorted(tabs):
        assert f'id="view-{tab}"' in html, f"no section for the {tab} tab"
        assert f'$("#view-{tab}").classList.toggle' in show_view, (
            f"showView never un-hides #view-{tab}, so that tab renders blank")


def test_every_settings_group_has_a_subview():
    """A sub-tab with no matching panel is the blank-tab bug one level down."""
    import re

    root = Path(__file__).resolve().parents[1] / "app/static"
    html = (root / "index.html").read_text("utf-8")

    subtabs = set(re.findall(r'class="subtab[^"]*"\s+data-sub="(\w+)"', html))
    subviews = set(re.findall(r'class="subview[^"]*"\s+data-sub="(\w+)"', html))

    assert subtabs, "no settings sub-tabs found; the selector needs updating"
    assert subtabs == subviews, (
        f"sub-tabs without a panel: {subtabs - subviews}; "
        f"panels with no tab: {subviews - subtabs}"
    )


def test_settings_panels_survived_the_regrouping():
    """Every element the settings JS reaches for must still exist.

    Restructuring the markup is exactly when an id quietly disappears and the
    panel it fed goes silently empty, because $() returning null is guarded
    for everywhere.
    """
    root = Path(__file__).resolve().parents[1] / "app/static"
    html = (root / "index.html").read_text("utf-8")

    for element_id in [
        # account
        "pw-form", "pw-current", "pw-new", "pw-result", "logout-btn",
        "me-label", "pw-expired",
        # users (admin)
        "users-panel", "users-list", "new-user-form", "nu-name", "nu-pass",
        "nu-admin", "users-refresh",
        # password policy, read-only summary plus the admin form
        "pw-policy", "policy-form", "po-min", "po-history", "po-age",
        "po-idle", "po-upper", "po-lower", "po-digit", "po-symbol",
        "po-common", "policy-result",
        # tokens
        "tokens-list", "new-token-form", "nt-name", "token-secret",
        # MCP
        "api-curl", "mcp-json", "mcp-tools", "mcp-download",
        "env-template", "env-download",
        # history and matrix
        "logins-list", "logins-scope", "tool-matrix",
    ]:
        assert f'id="{element_id}"' in html, f"#{element_id} is gone"


def test_the_open_tab_is_remembered_across_a_reload():
    """Reloading dropped the user back on Scan every time."""
    js = (Path(__file__).resolve().parents[1]
          / "app/static/app.js").read_text("utf-8")

    show_view = js[js.index("function showView(view)"):]
    show_view = show_view[:show_view.index("\n}")]
    assert "rememberView(view)" in show_view, "showView does not save the tab"

    assert "localStorage.setItem(VIEW_KEY" in js
    assert "lastView()" in js, "nothing reads the saved tab back"
    # Restoring must respect the role gate, or an ordinary account reloading
    # on Monitor lands on a panel it may not see.
    assert "visibleViews().includes(wanted)" in js


def test_an_ordinary_account_is_not_offered_admin_tabs():
    """Hiding a door that only returns 403. The server still enforces it."""
    js = (Path(__file__).resolve().parents[1]
          / "app/static/app.js").read_text("utf-8")

    fn = js[js.index("function visibleViews()"):]
    fn = fn[:fn.index("\n}")]
    assert '"monitor"' in fn, "the function never mentions monitor"

    # The non-admin branch is the last return in the function.
    non_admin = fn[fn.rindex("return ["):]
    assert "monitor" not in non_admin, (
        "an ordinary account is being offered the Monitor tab"
    )
    assert "scan" in non_admin and "report" in non_admin


def test_the_scanner_matrix_states_network_behaviour():
    """The custom-rules column was replaced by what each tool sends out."""
    root = Path(__file__).resolve().parents[1] / "app/static"
    js = (root / "app.js").read_text("utf-8")
    i18n = (root / "i18n.js").read_text("utf-8")

    table = js[js.index("const TOOL_MATRIX = ["):]
    table = table[:table.index("];")]

    assert "matrix.custom" not in js, "the custom-rules column is still there"
    assert "matrix.network" in js

    # Every tool needs a network entry, in both languages.
    for tool in ["semgrep", "bearer", "trivy", "npm_audit", "osv_scanner",
                 "gitleaks"]:
        assert tool in table, f"{tool} dropped out of the matrix"
        key = f'"matrix.net.{tool.split("_")[0]}"'
        assert i18n.count(key) == 2, f"{key} is not in both languages"

    # gitleaks is the one that never leaves the host; that must not be
    # silently downgraded to "fetches rules" in a later edit.
    gitleaks_row = table[table.index('["gitleaks"'):]
    assert '"none"' in gitleaks_row[:gitleaks_row.index("]")]


# -------------------------------------------------- forgotten-password reset
def _reset_helper(monkeypatch, tmp_path, username, password, list_mode="0"):
    """Run scripts/_reset_password.py the way the shell wrapper does."""
    import runpy

    monkeypatch.setenv("RESET_USER", username)
    monkeypatch.setenv("RESET_LIST", list_mode)
    monkeypatch.setattr("sys.stdin", io.StringIO(password))

    script = Path(__file__).resolve().parents[1] / "scripts/_reset_password.py"
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        return exc.code
    return 0


def test_a_forgotten_password_can_be_reset_from_the_host(accounts_env,
                                                         monkeypatch, tmp_path,
                                                         capsys):
    """There is no reset link on the login page; shell access is the path."""
    user = accounts_env.create_user("admin", "Original-Password-1!",
                                    is_admin=True)
    accounts_env.create_token(user.id, "ci")
    accounts_env.start_session(user.id)

    rc = _reset_helper(monkeypatch, tmp_path, "admin", "Brand-New-Passw0rd!")
    assert rc == 0, capsys.readouterr().err

    assert accounts_env.authenticate("admin", "Brand-New-Passw0rd!")
    assert not accounts_env.authenticate("admin", "Original-Password-1!")
    # A reset is what you do when a password may have leaked, so anything
    # else that still speaks for the account has to stop working too.
    assert not [t for t in accounts_env.list_tokens() if not t.revoked]


def test_the_reset_still_obeys_the_password_policy(accounts_env, monkeypatch,
                                                   tmp_path, capsys):
    """Recovery is not a reason to accept a password the rules refuse."""
    accounts_env.create_user("admin", "Original-Password-1!", is_admin=True)

    rc = _reset_helper(monkeypatch, tmp_path, "admin", "short")
    assert rc == 1
    assert "at least" in capsys.readouterr().err
    assert accounts_env.authenticate("admin", "Original-Password-1!")


def test_recovery_is_not_blocked_by_the_reuse_rule(accounts_env, monkeypatch,
                                                   tmp_path):
    """Refusing every remembered password can leave an admin with no way in.

    Every other rule still applies; only the history check is relaxed, and
    the outgoing hash is still recorded so the rule keeps working afterwards.
    """
    user = accounts_env.create_user("admin", "Original-Password-1!",
                                    is_admin=True)
    accounts_env.set_password(user.id, "Second-Password-22!")

    rc = _reset_helper(monkeypatch, tmp_path, "admin", "Original-Password-1!")
    assert rc == 0
    assert accounts_env.authenticate("admin", "Original-Password-1!")

    # The history is still being kept: an ordinary change back to the
    # password we just replaced is still refused.
    fresh = accounts_env.get_user("admin")
    with pytest.raises(ValueError):
        accounts_env.set_password(fresh.id, "Second-Password-22!")


def test_resetting_re_enables_a_disabled_account(accounts_env, monkeypatch,
                                                 tmp_path):
    """A locked-out admin is often disabled as well as forgotten."""
    user = accounts_env.create_user("admin", "Original-Password-1!",
                                    is_admin=True)
    accounts_env.create_user("spare", "Spare-Password-123!", is_admin=True)
    accounts_env.set_disabled(user.id, True)

    rc = _reset_helper(monkeypatch, tmp_path, "admin", "Brand-New-Passw0rd!")
    assert rc == 0
    assert not accounts_env.get_user("admin").disabled


def test_resetting_an_unknown_account_is_refused(accounts_env, monkeypatch,
                                                 tmp_path, capsys):
    accounts_env.create_user("admin", "Original-Password-1!", is_admin=True)

    rc = _reset_helper(monkeypatch, tmp_path, "nobody", "Brand-New-Passw0rd!")
    assert rc == 1
    err = capsys.readouterr().err
    assert "no such account" in err
    assert "admin" in err, "the message should name the accounts that exist"


def test_the_reset_script_never_takes_the_password_as_an_argument():
    """Arguments show up in ps output and in shell history."""
    sh = (Path(__file__).resolve().parents[1]
          / "scripts/reset-password.sh").read_text("utf-8")

    assert "read -rs PASSWORD" in sh, "the password must be prompted for"
    # It is piped in, never interpolated into the command line.
    assert 'printf \'%s\' "${PASSWORD}" | run_py' in sh


# ------------------------------------------------------------ settings tab
def test_login_attempts_are_recorded(accounts_env):
    """Failures are the interesting ones: a run of them is somebody guessing."""
    accounts_env.create_user("hank", "hank-password-1234")
    accounts_env.record_login("hank", True, "10.0.0.1")
    accounts_env.record_login("hank", False, "10.0.0.9")

    events = accounts_env.list_login_events()
    assert [e["success"] for e in events] == [False, True]   # newest first
    assert events[0]["source"] == "10.0.0.9"


def test_login_history_is_bounded(accounts_env, monkeypatch):
    """An unbounded log on a volume is a slow way to fill a disk."""
    monkeypatch.setattr(accounts_env, "MAX_LOGIN_EVENTS", 5)
    for i in range(12):
        accounts_env.record_login(f"user{i}", True)
    assert len(accounts_env.list_login_events(limit=100)) == 5


def test_a_user_sees_only_their_own_login_history(two_users):
    """An administrator needs everyone's; a user does not."""
    admin, user = two_users
    assert admin.get("/api/auth/logins").json()["scope"] == "all"

    body = user.get("/api/auth/logins").json()
    assert body["scope"] == "bob"
    assert all(e["username"] == "bob" for e in body["events"])


def test_mcp_config_uses_the_host_the_browser_asked_for(two_users):
    """Behind nginx, Host is a fixed value, so a config built from it is wrong."""
    admin, _user = two_users
    body = admin.get("/api/mcp/config",
                     headers={"Host": "sast-studio",
                              "X-Forwarded-Host": "192.168.99.145:8080"}).json()
    assert body["url"] == "http://192.168.99.145:8080/mcp"
    # The token is never handed back: it is shown once, at creation.
    assert "YOUR_TOKEN_HERE" in json.dumps(body["config"])


def test_password_policy_is_served_not_guessed(two_users):
    """The UI states the rules; hard-coding them twice is how they drift."""
    admin, _user = two_users
    from app import accounts

    body = admin.get("/api/auth/policy").json()
    assert body["min_length"] == accounts.MIN_PASSWORD_LEN
    assert body["session_hours"] == accounts.SESSION_TTL // 3600


def test_the_scanner_matrix_covers_every_adapter():
    """A tool missing from the matrix is the question it exists to answer."""
    import re

    from app.adapters import ADAPTERS

    js = (Path(__file__).resolve().parents[1] / "app/static/app.js").read_text("utf-8")
    table = js[js.index("const TOOL_MATRIX"):]
    table = table[:table.index("];")]
    for adapter in ADAPTERS:
        assert f'"{adapter.name}"' in table, f"{adapter.name} is not in the matrix"
