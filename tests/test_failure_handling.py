"""Round 46: the exception handlers narrowed from a blanket `except Exception`.

Each test raises the failure that really happens at that point and checks it
is still handled -- the risk of narrowing is an error that used to be caught
now escaping and breaking a request, a scan or a background thread.
"""
from __future__ import annotations

import io
import sqlite3
import sys
from types import SimpleNamespace

import pytest


# ------------------------------------------------------------------ docker_stats
@pytest.fixture
def docker(monkeypatch):
    from app import docker_stats
    from app.config import config
    monkeypatch.setattr(config, "ENABLE_DOCKER_STATS", True)
    monkeypatch.setattr(config, "DOCKER_PROXY", "docker-proxy:2375")
    monkeypatch.delenv("COMPOSE_PROJECT_NAME", raising=False)
    return docker_stats


def _api(answers):
    """A fake _get: a value, or an exception to raise, per path prefix."""
    def get(path, timeout=5.0):
        for prefix, answer in answers.items():
            if path.startswith(prefix):
                if isinstance(answer, BaseException):
                    raise answer
                return answer
        raise ConnectionRefusedError("no route in fake")
    return get


@pytest.mark.parametrize("error", [ConnectionRefusedError("refused"), RuntimeError("docker API returned 502"),
                                   ValueError("not JSON")])
def test_monitor_reports_an_unreachable_docker(docker, monkeypatch, error):
    monkeypatch.setattr(docker, "_get", _api({"/containers": error}))
    out = docker.collect()
    assert out["available"] is False and "cannot reach docker" in out["reason"]
    lim = docker.limits()
    assert lim["containers"] == [] and "cannot reach docker" in lim["reason"]


def test_one_containers_bad_answer_does_not_hide_the_rest(docker, monkeypatch):
    listing = [{"Names": ["/sast-studio"], "Id": "a" * 12, "State": "running"},
               {"Names": ["/sast-nginx"], "Id": "b" * 12, "State": "running"}]
    monkeypatch.setattr(docker, "_get", _api({
        "/containers/json": listing,
        "/containers/sast-studio/json": {"Config": {"Labels": {}}},
        "/containers/sast-studio/stats": {"cpu_stats": {}},        # KeyError territory
        "/containers/sast-nginx/stats": KeyError("memory_stats"),
        "/containers/sast-nginx/json": OSError("reset"),
        "/info": TypeError("odd"),
    }))
    monkeypatch.setenv("SAST_CONTAINER_NAME", "sast-studio")
    out = docker.collect()
    assert out["available"] is True and [c["name"] for c in out["containers"]] == \
        ["sast-studio", "sast-nginx"]
    assert docker._host_memory_total() is None
    # limits() needs /info too; with it failing it says so instead of raising.
    assert docker.limits()["containers"] == []


def test_containers_are_asked_about_by_name(docker, monkeypatch):
    asked = []

    def get(path, timeout=5.0):
        asked.append(path)
        return [] if path.startswith("/containers/json") else {}
    monkeypatch.setattr(docker, "_get", get)
    assert docker._ref({"Names": ["/sast-nginx"], "Id": "f" * 64}) == "sast-nginx"
    assert docker._ref({"Id": "f" * 64}) == "f" * 64
    monkeypatch.setenv("SAST_CONTAINER_NAME", "sast-studio")
    assert docker._self_id() == "sast-studio"
    docker._project_filter()
    assert asked == ["/containers/sast-studio/json"]


def test_the_change_log_survives_a_missing_events_module(docker, monkeypatch):
    monkeypatch.setitem(sys.modules, "app.events", None)       # import now fails
    docker._log_changes([{"name": "x", "state": "running"}])     # must not raise


# ------------------------------------------------------------------ rules
def test_a_validator_that_cannot_start_is_reported(monkeypatch, tmp_path):
    from app import rules

    def missing(*a, **k):
        raise FileNotFoundError("semgrep")
    monkeypatch.setattr(rules.subprocess, "run", missing)
    out = rules._run_validation("semgrep", "rules: []\n", "semgrep")
    assert out["ok"] is False and out["checked"] is True and "semgrep" in out["message"]


# ------------------------------------------------------------------ events
def test_a_broken_log_database_never_breaks_the_caller(monkeypatch):
    from app import accounts, events

    def broken():
        raise sqlite3.OperationalError("disk I/O error")
    monkeypatch.setattr(accounts, "connect", broken)
    monkeypatch.setattr(events, "_last_sweep", None)
    events.record("service", "test", detail="x")        # must not raise
    events._maybe_sweep()                                # nor this


# ------------------------------------------------------------------ main
def test_a_stamp_without_a_zone_is_read_as_utc(tmp_path, monkeypatch):
    """Subtracting it from an aware time raised TypeError inside the gate."""
    from app import accounts
    from app.config import config
    monkeypatch.setattr(config, "ACCOUNTS_DB", tmp_path / "a.db")
    accounts.init_db()
    user = accounts.create_user("old", "old-password-1234")
    monkeypatch.setattr(accounts, "get_policy", lambda: {"max_age_days": 90})
    with accounts.connect() as conn:
        conn.execute("UPDATE users SET password_changed_at = ? WHERE id = ?",
                     ("2000-01-01T00:00:00", user.id))
    assert accounts.password_expired(user) is True


def test_mcp_survives_a_client_that_hangs_up(monkeypatch):
    import asyncio
    from starlette.requests import ClientDisconnect
    from app import main
    from app.config import config
    monkeypatch.setattr(config, "REQUIRE_AUTH", False)

    class Gone:
        headers = {}
        cookies = {}
        url = SimpleNamespace(path="/mcp")
        client = SimpleNamespace(host="127.0.0.1")

        async def json(self):
            raise ClientDisconnect()
    res = asyncio.run(main.mcp_endpoint(Gone()))
    assert res.status_code == 400


def test_an_unreadable_expiry_never_locks_anyone_out(monkeypatch):
    from app import accounts, main

    def broken(user):
        raise sqlite3.OperationalError("locked")
    monkeypatch.setattr(accounts, "password_expired", broken)
    request = SimpleNamespace(url=SimpleNamespace(path="/api/scans"))
    assert main._expired_blocked(request, object()) is False


def test_mcp_answers_a_body_that_is_not_json(monkeypatch):
    from fastapi.testclient import TestClient
    from app.config import config
    from app.main import app
    monkeypatch.setattr(config, "REQUIRE_AUTH", False)
    with TestClient(app) as client:
        res = client.post("/mcp", content=b"\xff\xfe not json",
                          headers={"Content-Type": "application/json"})
    assert res.status_code == 400 or res.json().get("error")


# ------------------------------------------------------------------ orchestrator, sbom
def test_a_missing_triage_store_still_gives_a_verdict(monkeypatch):
    from app import accounts
    from app.orchestrator import _triage_marks

    def broken():
        raise sqlite3.OperationalError("no such table")
    monkeypatch.setattr(accounts, "get_triage", broken)
    assert _triage_marks() == {}


def test_a_malformed_pyproject_contributes_nothing():
    from app.sbom import _read_pyproject
    assert list(_read_pyproject("[project\nname = ")) == []
