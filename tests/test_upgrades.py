"""Round 45: scanner upgrades from the web panel -- the parts inside the app.

The host side (scripts/sast_updater.py) is tested in test_updater.py.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app import releases, selfcheck, upgrades
from app.models import Finding, ToolKind, ToolResult, ToolStatus

NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)


def _gh(*rels):
    return lambda url: [
        {"tag_name": tag, "published_at": when, "draft": draft, "prerelease": pre}
        for tag, when, draft, pre in rels]


# ------------------------------------------------------------------ releases
def test_github_releases_skip_drafts_prereleases_and_odd_tags():
    fetch = _gh(("v0.75.0", "2026-10-01T13:34:13Z", False, False),
                ("v0.76.0", "2026-10-10T00:00:00Z", True, False),
                ("v0.77.0-rc1", "2026-10-11T00:00:00Z", False, False),
                ("v0.78.0", "2026-10-12T00:00:00Z", False, True),
                ("v0.74.0", "2026-08-14T11:29:11Z", False, False))
    found = releases.published("trivy", fetch)
    assert [v for v, _ in found] == ["0.75.0", "0.74.0"]


def test_pypi_releases_skip_yanked_and_empty_ones():
    data = {"releases": {
        "1.179.0": [{"upload_time_iso_8601": "2026-09-01T00:00:00Z"},
                    {"upload_time_iso_8601": "2026-08-31T00:00:00Z"}],
        "1.181.0": [{"upload_time_iso_8601": "2026-10-01T00:00:00Z", "yanked": True}],
        "1.180.0": [],
        "1.182.0rc1": [{"upload_time_iso_8601": "2026-10-02T00:00:00Z"}],
    }}
    found = releases.published("semgrep", lambda url: data)
    # The newest file counts: a wheel added later restarts the wait.
    assert found == [("1.179.0", datetime(2026, 9, 1, tzinfo=timezone.utc))]


def test_a_replaced_asset_restarts_the_cooldown():
    rel = [{"tag_name": "v0.75.0", "published_at": "2026-09-01T00:00:00Z",
            "draft": False, "prerelease": False,
            "assets": [{"created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-10-18T00:00:00Z"},
                       {"created_at": "2026-09-02T00:00:00Z"}]}]
    row = releases.assess("trivy", "0.74.0", now=NOW, fetch=lambda url: rel)
    assert row["eligible"] == "" and "released 2026-10-18" in row["reason"]


def test_a_release_is_offered_only_after_the_cooldown():
    fetch = _gh(("v0.75.0", "2026-10-15T00:00:00Z", False, False))
    row = releases.assess("trivy", "0.74.0", now=NOW, fetch=fetch)
    assert row["eligible"] == "" and "eligible from 2026-10-22" in row["reason"]
    row = releases.assess("trivy", "0.74.0", now=NOW + timedelta(days=3), fetch=fetch)
    assert row["eligible"] == "0.75.0" and row["latest_published"] == "2026-10-15T00:00:00Z"


def test_nothing_is_offered_when_current_or_unknown():
    fetch = _gh(("v0.75.0", "2026-01-01T00:00:00Z", False, False))
    assert releases.assess("trivy", "0.75.0", now=NOW, fetch=fetch)["reason"] == "up to date"
    assert releases.assess("trivy", "0.76.0", now=NOW, fetch=fetch)["reason"] == "up to date"
    # An unreadable installed version still gets the newest release offered.
    assert releases.assess("trivy", "", now=NOW, fetch=fetch)["eligible"] == "0.75.0"
    assert releases.assess("trivy", "x", now=NOW, fetch=_gh())["reason"] == "no stable release found"

    def offline(url):
        raise OSError("no network")
    assert releases.assess("trivy", "0.74.0", fetch=offline)["reason"] == "could not check: OSError"


# ------------------------------------------------------------------ selfcheck
def _result(tool, status=ToolStatus.OK, cwe=None, n=1):
    findings = [Finding(tool=tool, cwe=cwe or []) for _ in range(n)]
    return ToolResult(tool=tool, kind=ToolKind.SAST, status=status, findings=findings)


def test_sample_project_has_something_for_every_scanner(tmp_path):
    root = selfcheck.write_sample(tmp_path)
    names = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    assert names == {"app.py", "static/main.js", "requirements.txt",
                     "package.json", "settings.py"}
    assert "AKIA" in (root / "settings.py").read_text("utf-8")


def test_check_result_needs_status_ok_findings_and_the_expected_one():
    assert selfcheck.check_result(_result("trivy", ToolStatus.ERROR))[0] is False
    assert selfcheck.check_result(_result("trivy", n=0)) == (False, "found nothing in the sample")
    assert selfcheck.check_result(_result("semgrep", cwe=["CWE-79"])) == \
        (False, "missed the expected finding")
    assert selfcheck.check_result(_result("semgrep", cwe=["CWE-78: OS Command"])) == \
        (True, "1 findings")
    assert selfcheck.check_result(_result("bearer", n=2)) == (True, "2 findings")


class _Adapter:
    def __init__(self, name, ok=True, result=None):
        self.name, self._ok, self._result = name, ok, result

    def probe(self):
        return self._ok, "1.0.0" if self._ok else ""

    def scan(self, target):
        assert (target / "app.py").exists()
        return self._result


def test_probe_and_sample_report_each_scanner(tmp_path):
    rows = selfcheck.probe([_Adapter("a"), _Adapter("b", ok=False)])
    assert rows == [("a", True, "1.0.0"), ("b", False, "does not start")]
    rows = selfcheck.sample([_Adapter("semgrep", result=_result("semgrep", cwe=["CWE-78"])),
                             _Adapter("gitleaks", result=_result("gitleaks", n=0))],
                            root=tmp_path)
    assert [ok for _, ok, _ in rows] == [True, False]
    assert selfcheck.sample([]) == []


def test_selfcheck_main_exit_codes(capsys):
    assert selfcheck.main([]) == 2
    assert selfcheck.main(["nope"]) == 2
    assert selfcheck.main(["probe"], run=lambda: [("a", True, "ok")]) == 0
    assert selfcheck.main(["probe"], run=lambda: [("a", False, "x")]) == 1
    assert selfcheck.main(["sample"], run=lambda: []) == 1, "checking nothing is not a pass"
    assert "FAILED" in capsys.readouterr().out


# ------------------------------------------------------------------ upgrades
@pytest.fixture
def ops(tmp_path, monkeypatch):
    from app.config import config
    monkeypatch.setattr(config, "OPS_DIR", tmp_path)
    return tmp_path


CAND = "0123456789abcdef"


def ready(ops):
    """The host has prepared and accepted a candidate."""
    (ops / "status.json").write_text(json.dumps({
        "phase": "ready", "candidate": {"id": CAND, "targets": {"trivy": "0.75.0"}}}))


def test_upgrades_are_off_without_an_ops_dir(monkeypatch):
    from app.config import config
    monkeypatch.setattr(config, "OPS_DIR", None)
    assert upgrades.enabled() is False
    assert upgrades.status() == {"enabled": False}
    assert upgrades.request_check("a")["started"] is False
    assert upgrades.request_apply(CAND, "a")["started"] is False
    assert upgrades.start_watcher(object()) is False


def test_status_reads_the_host_files(ops):
    assert upgrades.status() == {"enabled": True, "upstream_check": True, "pending": False,
                                 "status": {}, "log": ""}
    (ops / "status.json").write_text(json.dumps({"phase": "building"}))
    (ops / "update.log").write_text("x" * (upgrades.LOG_TAIL + 10) + "END")
    st = upgrades.status()
    assert st["status"] == {"phase": "building"}
    assert st["log"].endswith("END") and len(st["log"]) == upgrades.LOG_TAIL


def test_unreadable_or_odd_status_files_read_as_empty(ops):
    (ops / "status.json").write_text("not json")
    assert upgrades._read_json("status.json") == {}
    (ops / "status.json").write_text("[1, 2]")
    assert upgrades._read_json("status.json") == {}


@pytest.mark.skipif(not hasattr(__import__("os"), "O_NOFOLLOW"), reason="POSIX only")
def test_a_link_in_ops_is_never_followed(ops, tmp_path_factory):
    secret = tmp_path_factory.mktemp("elsewhere") / "secret"
    secret.write_text('{"phase": "done"}')
    (ops / "status.json").symlink_to(secret)
    assert upgrades._read_json("status.json") == {}
    upgrades._write_json("status.json", {"phase": "x"})
    assert secret.read_text() == '{"phase": "done"}', "wrote through the link"
    assert not (ops / "status.json").is_symlink()


def test_a_check_request_names_no_versions(ops):
    out = upgrades.request_check("alice")
    assert out["started"] is True
    req = json.loads((ops / "request.json").read_text())
    assert (req["action"], req["requested_by"], req["id"]) == ("check", "alice", out["id"])
    assert set(req) == {"id", "requested_by", "requested_at", "action"}


def test_only_the_candidate_on_offer_can_be_applied(ops):
    assert "no longer on offer" in upgrades.request_apply(CAND, "a")["reason"]
    ready(ops)
    assert "no longer on offer" in upgrades.request_apply("f" * 16, "a")["reason"]
    (ops / "status.json").write_text(json.dumps({"phase": "ready", "candidate": "odd"}))
    assert "no longer on offer" in upgrades.request_apply(CAND, "a")["reason"]
    ready(ops)
    out = upgrades.request_apply(CAND, "alice")
    assert out["started"] is True
    req = json.loads((ops / "request.json").read_text())
    assert (req["action"], req["candidate"]) == ("apply", CAND)


def test_one_thing_at_a_time(ops):
    ready(ops)
    (ops / "request.json").write_text("{}")
    assert "busy" in upgrades.request_check("a")["reason"]
    assert "busy" in upgrades.request_apply(CAND, "a")["reason"]
    (ops / "request.json").unlink()
    (ops / "status.json").write_text(json.dumps({"phase": "verifying"}))
    assert "busy" in upgrades.request_check("a")["reason"]
    (ops / "status.json").write_text(json.dumps({"phase": "failed"}))
    assert upgrades.request_check("a")["started"] is True


def test_with_checks_off_the_panel_cannot_ask_for_one(ops, monkeypatch):
    from app.config import config
    monkeypatch.setattr(config, "UPSTREAM_CHECK", False)
    assert "SAST_UPSTREAM_CHECK=false" in upgrades.request_check("a")["reason"]
    assert upgrades.status()["upstream_check"] is False
    ready(ops)
    assert upgrades.request_apply(CAND, "a")["started"] is True, \
        "a candidate prepared before the switch was turned off can still be applied"


def test_the_version_check_obeys_the_switch(monkeypatch):
    from app import admin, releases
    from app.config import config
    monkeypatch.setattr(config, "UPSTREAM_CHECK", False)
    monkeypatch.setattr(admin, "_upstream_cache", {"at": 0.0, "versions": {}})
    asked = []
    monkeypatch.setattr(releases, "_fetch_json", lambda url, timeout=10.0: asked.append(url))
    assert admin._latest_upstream() == {} and asked == []


def test_the_switch_is_read_from_the_environment(monkeypatch):
    from app.config import _env_bool
    for value, on in [("false", False), ("OFF", False), ("0", False), ("true", True), ("on", True)]:
        monkeypatch.setenv("SAST_UPSTREAM_CHECK", value)
        assert _env_bool("SAST_UPSTREAM_CHECK", True) is on
    monkeypatch.delenv("SAST_UPSTREAM_CHECK")
    assert _env_bool("SAST_UPSTREAM_CHECK", True) is True


class _Manager:
    def __init__(self, active=2):
        self.draining, self.active = None, active

    def set_draining(self, on):
        self.draining = on

    def active_count(self):
        return self.active


def test_scans_stop_only_while_the_host_waits_to_switch(ops):
    m = _Manager()
    assert upgrades.sync_drain(m) is False and m.draining is False
    for phase in ("waiting_for_scans", "switching"):
        (ops / "status.json").write_text(json.dumps({"phase": phase, "id": "ab" * 8}))
        assert upgrades.sync_drain(m) is True and m.draining is True
        assert json.loads((ops / "drain.json").read_text())["active"] == 2
    (ops / "status.json").write_text(json.dumps({"phase": "done"}))
    assert upgrades.sync_drain(m) is False and m.draining is False


def test_the_watcher_follows_the_host_and_survives_errors(ops, monkeypatch):
    import threading
    calls = []
    done = threading.Event()

    def fake_sync(manager):
        calls.append(manager)
        if len(calls) == 1:
            raise OSError("disk full")
        done.set()

    monkeypatch.setattr(upgrades, "sync_drain", fake_sync)
    assert upgrades.start_watcher("m", interval=0.01) is True
    assert done.wait(2), "the watcher stopped after an error"
    upgrades.stop_watcher()


# --------------------------------------------------------------- job manager
def test_draining_refuses_new_scans_and_counts_running_ones():
    from app.models import JobStatus, ScanTarget
    from app.orchestrator import Draining, JobManager

    m = JobManager()
    job = m.new_job(ScanTarget(kind="git", display="x"), ["semgrep"])
    assert m.active_count() == 1          # queued counts: it is about to run
    job.status = JobStatus.AWAITING
    assert m.active_count() == 0          # waiting for a person, not running
    m.set_draining(True)
    assert m.draining is True
    with pytest.raises(Draining):
        m.new_job(ScanTarget(kind="git", display="y"), ["semgrep"])
    with pytest.raises(Draining):
        m.confirm(job.id)
    m.set_draining(False)
    assert m.confirm(job.id) is False     # not pending in this test; no error


# ------------------------------------------------------------------- the API
@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def test_upgrades_are_refused_while_accounts_are_off(client, ops, monkeypatch):
    """With accounts off, require_admin lets anyone through. Fine for the
    in-place buttons; not for one that rebuilds and swaps the service."""
    from app.config import config
    monkeypatch.setattr(config, "REQUIRE_AUTH", False)
    ready(ops)
    assert client.get("/api/admin/upgrades").status_code == 403
    assert client.post("/api/admin/upgrades/check").status_code == 403
    assert client.post("/api/admin/upgrades/apply", data={"candidate": CAND}).status_code == 403
    assert not (ops / "request.json").exists()


@pytest.fixture
def signed_in(tmp_path, monkeypatch):
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
    admin, user = TestClient(app), TestClient(app)
    admin.post("/api/auth/login", data={"username": "admin", "password": "admin-password-1234"})
    user.post("/api/auth/login", data={"username": "bob", "password": "bob-password-123456"})
    return admin, user


def test_upgrade_endpoints(signed_in, ops):
    admin, user = signed_in
    ready(ops)
    for method, path, data in [("get", "/api/admin/upgrades", None),
                               ("post", "/api/admin/upgrades/check", {}),
                               ("post", "/api/admin/upgrades/apply", {"candidate": CAND})]:
        assert getattr(user, method)(path, **({"data": data} if data is not None else {})) \
            .status_code == 403, path

    body = admin.get("/api/admin/upgrades").json()
    assert body["enabled"] is True and body["status"]["candidate"]["id"] == CAND

    res = admin.post("/api/admin/upgrades/apply", data={"candidate": "f" * 16})
    assert res.status_code == 409 and "on offer" in res.json()["reason"]
    res = admin.post("/api/admin/upgrades/apply", data={"candidate": f" {CAND} "})
    assert res.status_code == 202
    req = json.loads((ops / "request.json").read_text())
    assert (req["action"], req["requested_by"]) == ("apply", "admin")
    res = admin.post("/api/admin/upgrades/check")
    assert res.status_code == 409 and "busy" in res.json()["reason"]
    (ops / "request.json").unlink()
    assert admin.post("/api/admin/upgrades/check").status_code == 202


def test_a_scan_started_while_draining_gets_503(client, monkeypatch):
    from app.main import manager
    manager.set_draining(True)
    try:
        res = client.post("/api/scans", data={"source_kind": "git",
                                              "git_url": "https://example.com/r.git"})
    finally:
        manager.set_draining(False)
    assert res.status_code == 503
    assert res.headers["retry-after"] == "120"
    assert "upgrade" in res.json()["detail"]


def test_mcp_says_not_now_while_draining(monkeypatch):
    from app import mcp
    from app.orchestrator import manager
    manager.set_draining(True)
    try:
        reply = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "scan_git_repository",
                                       "arguments": {"git_url": "https://example.com/r.git"}}},
                           user=None)
    finally:
        manager.set_draining(False)
    assert reply["result"]["isError"] is True
    assert "upgrade" in reply["result"]["content"][0]["text"]


def test_the_panel_strings_exist_in_both_languages():
    text = (Path(__file__).resolve().parents[1] / "app/static/i18n.js").read_text("utf-8")
    keys = [k for k in ("upg.title", "upg.failedAt", "upg.phase.waiting_for_scans",
                        "upg.overrides", "upg.off", "upg.apply", "upg.checkNow",
                        "upg.banner.ready", "upg.upstreamOff", "surface.mentionTag")
            ] + [f"upg.ev.{kind}" for kind in ("downloading", "ready", "download_failed",
                                               "updating", "updated", "update_failed",
                                               "expired", "repeat")]
    for key in keys:
        assert text.count(f'"{key}"') == 2, key


class _FakeHTTPS:
    """Stands in for http.client.HTTPSConnection; records what was asked."""
    last = None

    def __init__(self, host, timeout, context):
        self.host, self.status = host, 200
        self.verifies = context.verify_mode.name == "CERT_REQUIRED" and context.check_hostname
        _FakeHTTPS.last = self

    def request(self, method, path, headers):
        self.method, self.path, self.headers = method, path, headers

    def getresponse(self):
        import io
        resp = io.BytesIO(b'{"ok": true}')
        resp.status = _FakeHTTPS.answer
        return resp

    def close(self):
        self.closed = True


def test_release_lookups_go_only_to_the_release_hosts(monkeypatch):
    monkeypatch.setattr(releases.http.client, "HTTPSConnection", _FakeHTTPS)
    _FakeHTTPS.answer = 200
    assert releases._fetch_json("https://api.github.com/repos/a/b/releases?per_page=20") == {"ok": True}
    sent = _FakeHTTPS.last
    assert (sent.host, sent.path) == ("api.github.com", "/repos/a/b/releases?per_page=20")
    assert sent.headers["User-Agent"] == "sast-studio" and sent.closed
    assert sent.verifies, "certificates must be checked"

    assert releases._fetch_json("https://pypi.org/pypi/semgrep/json") == {"ok": True}
    assert _FakeHTTPS.last.path == "/pypi/semgrep/json"

    _FakeHTTPS.answer = 404
    with pytest.raises(OSError):
        releases._fetch_json("https://pypi.org/pypi/semgrep/json")
    for url in ("http://pypi.org/x", "file:///etc/passwd", "https://evil.example/x"):
        with pytest.raises(ValueError):
            releases._fetch_json(url)


def test_selfcheck_runs_as_a_module(monkeypatch):
    import runpy
    import sys
    monkeypatch.setattr(sys, "argv", ["selfcheck"])
    with pytest.raises(SystemExit) as exit_:
        runpy.run_module("app.selfcheck", run_name="__main__")
    assert exit_.value.code == 2


@pytest.mark.skipif(not hasattr(__import__("os"), "mkfifo"), reason="POSIX only")
def test_a_fifo_or_directory_in_ops_does_not_hang_the_app(ops):
    import os
    os.mkfifo(ops / "status.json")
    (ops / "update.log").mkdir()
    assert upgrades.status()["status"] == {} and upgrades.status()["log"] == ""
