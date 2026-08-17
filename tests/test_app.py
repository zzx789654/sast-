"""Test suite for SAST Studio.

Runs fully without any scanner installed: subprocess calls are faked and the
pure normalization/parsing functions are tested directly.
"""
from __future__ import annotations

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
    assert result.summary["high"] == 1


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
            return [Finding(tool="fake", severity=Severity.HIGH, title="boom")]

    monkeypatch.setattr(orchestrator, "get_adapters", lambda names: [FakeAdapter()])
    mgr = orchestrator.JobManager()
    job = mgr.new_job(ScanTarget(kind="path", display=str(tmp_path)), ["fake"])
    assert job.status.value == "queued"
    mgr._prepare_and_maybe_scan(job.id, {"kind": "path", "path": str(tmp_path)}, False)

    assert job.status.value == "done"
    assert job.summary["high"] == 1
    assert job.summary["total"] == 1
    assert job.results["fake"].status == ToolStatus.OK
    # progress + phase are populated for the live UI
    assert job.results["fake"].phase.value == "finished"
    assert job.progress["percent"] == 100
    assert job.progress["finished"] == job.progress["total"] == 1


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
            return [Finding(tool="fake", severity=Severity.HIGH, title="x")]

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
    assert job.status == JobStatus.DONE
    assert job.summary["high"] == 1


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
