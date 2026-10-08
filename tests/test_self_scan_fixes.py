"""Round 49: what the project's own scan (via SAST MCP) flagged, fixed in code.

Each test pins the rewrite that made a finding go away, so a later change
cannot quietly bring the pattern back.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tests.sources import STATIC, frontend_js, script_files

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


# ------------------------------------------------------- B: run_command
def test_run_command_starts_only_the_programs_it_knows():
    from app.adapters.base import PROGRAMS, run_command

    assert PROGRAMS == {"semgrep", "bearer", "trivy", "npm", "osv-scanner", "gitleaks", "git"}
    for refused in (["python3", "-c", "print(1)"], ["sh", "-c", "id"], [], ["git", 5]):
        res = run_command(refused)
        assert res.returncode == -1 and "refusing to run" in res.stderr, refused


def test_run_command_uses_the_absolute_path(monkeypatch):
    from app.adapters import base

    seen = []

    def fake_run(args, **kw):
        seen.append(args)
        return subprocess.CompletedProcess(args, 0, "ok", "")
    monkeypatch.setattr(base.shutil, "which", lambda name: f"/opt/bin/{name}")
    monkeypatch.setattr(base.subprocess, "run", fake_run)
    assert base.run_command(["git", "--version"]).stdout == "ok"
    assert seen == [["/opt/bin/git", "--version"]]


def test_run_command_reports_a_missing_or_vanishing_program(monkeypatch):
    from app.adapters import base

    monkeypatch.setattr(base.shutil, "which", lambda name: None)
    assert base.run_command(["trivy", "--version"]).stderr == "executable not found"

    def gone(args, **kw):
        raise FileNotFoundError(args[0])
    monkeypatch.setattr(base.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(base.subprocess, "run", gone)
    assert base.run_command(["trivy", "--version"]).stderr == "executable not found"


def test_git_clone_ends_its_options_before_the_url(monkeypatch, tmp_path):
    from app import source
    from app.adapters.base import CommandResult

    seen = []
    monkeypatch.setattr(source, "run_command",
                        lambda args, **kw: seen.append(args) or CommandResult(0, "", ""))
    source.clone_git("https://github.com/org/repo.git", tmp_path / "src")
    args = seen[0]
    assert args[-3:] == ["--", "https://github.com/org/repo.git", str(tmp_path / "src")]


# ------------------------------------------------------- B: job workspace
@pytest.mark.parametrize("bad", ["", "../../etc", "0123456789ab/..", "0123456789AB",
                                 "0123456789abc", "/tmp/x", None, 5])
def test_a_workspace_is_only_ever_a_job_id(bad):
    from app.orchestrator import JobManager

    with pytest.raises(ValueError):
        JobManager.job_dir(None, bad)


def test_a_job_id_names_its_workspace():
    from app.config import config
    from app.orchestrator import JobManager

    assert JobManager.job_dir(None, "0123456789ab") == config.WORKSPACE_DIR / "0123456789ab"


# ------------------------------------------------------- A: fixed SQL
def test_triage_marks_are_read_for_any_number_of_keys(tmp_path, monkeypatch):
    """One JSON parameter instead of one "?" per key: no chunking, and no
    SQLite parameter limit (999 on older builds) however big the scan."""
    from app import accounts
    from app.config import config

    monkeypatch.setattr(config, "ACCOUNTS_DB", tmp_path / "accounts.db")
    accounts.init_db()
    accounts.set_triage("k-1500", "false_positive", "alice", "")
    accounts.set_triage("k-3", "accepted", "bob", "")
    keys = [f"k-{i}" for i in range(2500)] + ["not'; DROP TABLE triage; --"]
    got = accounts.get_triage(keys)
    assert set(got) == {"k-1500", "k-3"}
    assert accounts.get_triage(["nothing"]) == {}


def test_every_log_filter_works_alone_and_together(tmp_path, monkeypatch):
    from app import accounts, events
    from app.config import config

    monkeypatch.setattr(config, "ACCOUNTS_DB", tmp_path / "accounts.db")
    accounts.init_db()
    events.init()
    events._last_sweep = None
    events.record("auth", "login", level="warn", actor="mallory", detail="wrong")
    events.record("scan", "start", actor="alice", target="github.com/a/b")
    first = events.query()["events"][-1]["at"]
    assert events.query(actor="alice")["total"] == 1
    assert events.query(since=first)["total"] == 2
    assert events.query(since="9999")["total"] == 0
    assert events.query(categories=["scan"], actor="alice", text="github")["total"] == 1
    assert events.query(categories=["scan"], actor="mallory")["total"] == 0
    page = events.query(limit=1, offset=1)
    assert (page["limit"], page["offset"], len(page["events"])) == (1, 1, 1)


def test_no_sql_is_built_from_strings():
    """The statements are fixed text: nothing is spliced into them."""
    for rel in ("app/accounts.py", "app/events.py"):
        src = (ROOT / rel).read_text("utf-8")
        assert 'f"SELECT' not in src and '" + clause' not in src and "% \",\".join" not in src


# ------------------------------------------------------- A: fixed messages
def test_ticket_refusals_carry_no_counts(monkeypatch):
    from app import mcp

    monkeypatch.setattr(mcp, "_tickets", {})
    for _ in range(mcp.UPLOAD_TICKETS_PER_USER):
        mcp.issue_upload_ticket("alice", ["semgrep"], "a.zip")
    with pytest.raises(ValueError) as exc:
        mcp.issue_upload_ticket("alice", ["semgrep"], "a.zip")
    assert str(exc.value) == mcp._TICKETS_HELD
    monkeypatch.setattr(mcp, "UPLOAD_TICKETS_TOTAL", len(mcp._tickets))
    with pytest.raises(ValueError) as exc:
        mcp.issue_upload_ticket("bob", ["semgrep"], "a.zip")
    assert str(exc.value) == mcp._TICKETS_FULL


# ------------------------------------------------------- D: whole analysis
def test_every_front_end_file_is_small_enough_to_be_analysed_whole():
    """Bearer 2.1.1 gives each file 30 s and has no setting to change it; the
    old 127 KB app.js ran out and was skipped. About 20 KB takes 2-5 s."""
    files = script_files()
    assert [f.name for f in files] == ["core.js", "rules.js", "monitor.js", "scan.js",
                                       "report.js", "surface.js"]
    assert not (STATIC / "app.js").exists()
    for f in files:
        assert f.stat().st_size <= 32 * 1024, f"{f.name} is {f.stat().st_size} bytes"
        assert f.read_text("utf-8").startswith('"use strict";')
    assert sorted(STATIC.joinpath("js").glob("*.js")) == sorted(files), \
        "a file in static/js that index.html does not load"


def test_the_split_files_are_served_without_a_login(client, monkeypatch):
    from app.config import config

    monkeypatch.setattr(config, "REQUIRE_AUTH", True)
    for f in script_files():
        res = client.get(f"/js/{f.name}")
        assert res.status_code == 200 and "no-cache" in res.headers.get("cache-control", "")


def test_deploy_sh_parses_as_plain_shell_and_warns_about_the_address():
    deploy = (ROOT / "scripts/deploy.sh").read_text("utf-8")
    assert "if [ ! -e /dev/fd/9 ]; then" in deploy, \
        "semgrep's bash parser stops at a negated brace group"
    assert "{ true >&9; }" not in deploy
    assert "SAST_PUBLIC_URL is not set" in deploy


# ------------------------------------------------------- plain wording
def test_the_surface_labels_say_it_plainly_in_both_languages():
    i18n = (STATIC / "i18n.js").read_text("utf-8")
    for key in ["surface.th.auth", "surface.th.flags", "surface.auth.admin_in_handler",
                "surface.auth.user_in_handler", "surface.tip.th.auth", "surface.tip.th.flags",
                "surface.tip.sample", "surface.tip.mention"] + [
            f"surface.tip.auth.{v}" for v in ("detected", "not_detected", "global", "public",
                                              "admin_in_handler", "user_in_handler")] + [
            f"surface.tip.flag.{f}" for f in ("auth_inferred", "no_auth_detected",
                                              "unreferenced", "undocumented",
                                              "unknown_backend", "external")]:
        assert i18n.count(f'"{key}"') == 2, key
    assert '"surface.th.auth": "要登入嗎"' in i18n and '"surface.th.flags": "提醒"' in i18n
    js = frontend_js()
    assert 'withTip(el("td", "sf-auth "' in js and '"flag." + f' in js


def test_every_element_the_page_builds_is_one_el_can_make():
    """el() makes each element from a literal name (round 49): a tag left out
    of its list would throw the moment that part of the page is drawn."""
    import re

    js = frontend_js()
    table = js[js.index("const MAKE = new Map(["):js.index("]);", js.index("const MAKE"))]
    makeable = set(re.findall(r'\["([a-z]+)", \(\) => document\.createElement\("\1"\)\]', table))
    used = set(re.findall(r'\bel\("([a-z0-9]+)"', js))
    assert used and used <= makeable, used - makeable
    assert not re.search(r"\bel\(\s*[A-Za-z_$`]", js.replace("const el = (tag", "")), \
        "el() called with a computed tag"


# ------------------------------------------------- round 49 review
@pytest.mark.parametrize("value, ok", [
    ("a:65535", True), ("a:1", True), ("a:0", False), ("a:99999", False),
    ("..", False), ("-", False), (".-.", False), ("a-1.b", True),
])
def test_a_host_needs_a_real_port_and_a_real_name(value, ok):
    from app.web import _valid_host
    assert _valid_host(value) is ok


@pytest.mark.parametrize("url, key", [
    ("https://SAST.Example.com:443/sast/", "https://sast.example.com"),
    ("HTTP://h:80", "http://h"),
    ("http://h:8080/", "http://h:8080"),
    ("ftp://h", ""), ("http://", ""), ("http://h:notaport", ""), ("null", ""),
])
def test_an_origin_is_compared_the_way_a_browser_writes_it(url, key):
    from app.web import _origin_key
    assert _origin_key(url) == key


def _request(host):
    from starlette.requests import Request
    return Request({"type": "http", "scheme": "http", "path": "/", "query_string": b"",
                    "headers": [(b"host", host.encode())]})


def test_a_public_url_written_loosely_still_matches(monkeypatch):
    from app import web
    from app.config import config
    monkeypatch.setattr(config, "PUBLIC_URL", "https://SAST.example.com:443/sast/")
    monkeypatch.setattr(config, "ALLOWED_HOSTS", [])
    monkeypatch.setattr(config, "MCP_ALLOWED_ORIGINS", [])
    assert web._origin_allowed("https://sast.example.com", _request("sast-studio"))
    assert not web._origin_allowed("null", _request("sast-studio"))
    monkeypatch.setattr(config, "MCP_ALLOWED_ORIGINS", [" * "])
    assert web._origin_allowed("null", _request("sast-studio")), "* still means anyone"


def test_allowed_hosts_without_a_port_cover_any_port(monkeypatch):
    """Round 49 review: behind nginx with only SAST_ALLOWED_HOSTS set."""
    from app import web
    from app.config import config
    monkeypatch.setattr(config, "PUBLIC_URL", "")
    monkeypatch.setattr(config, "ALLOWED_HOSTS", ["192.168.99.145"])
    monkeypatch.setattr(config, "MCP_ALLOWED_ORIGINS", [])
    behind = _request("sast-studio")
    assert web._origin_allowed("http://192.168.99.145:8080", behind)
    assert not web._origin_allowed("http://192.168.99.146:8080", behind)
    assert not web._origin_allowed("http://localhost:8080", behind)
    assert web._public_origin(behind) == ("http", "192.168.99.145"), \
        "the configured name, not localhost, when nginx hides the Host"


def test_the_gate_lets_through_only_the_named_front_end_files():
    from tests.sources import backend_py
    from app import main

    src = backend_py()
    assert 'startswith("/js/")' not in src and 'startswith("/static/")' not in src
    gate = src[src.index("async def _auth_gate"):]
    gate = gate[:gate.index("\n\n\n")]
    for name in (n for n in main._APP_ASSETS if n.startswith("/js/")):
        assert f'"{name}"' in gate, f"{name} is not let through for the login page"


# ------------------------------------------------- round 50
def test_mcp_still_logs_both_kinds_of_caller(monkeypatch):
    """The log moved after the token check (round 50); both cases still log."""
    import asyncio
    from types import SimpleNamespace

    from app import events
    from app.config import config
    from app.routes import mcp_http

    logged = []
    monkeypatch.setattr(events, "record", lambda *a, **k: logged.append(k.get("detail")))
    monkeypatch.setattr(config, "REQUIRE_AUTH", True)
    monkeypatch.setattr(mcp_http, "current_user", lambda request: None)

    class Anon:
        headers = {}
        client = SimpleNamespace(host="127.0.0.1")

    res = asyncio.run(mcp_http.mcp_endpoint(Anon()))
    assert res.status_code == 401 and logged == ["unauthenticated"]
