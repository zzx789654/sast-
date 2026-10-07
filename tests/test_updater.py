"""The host updater (scripts/sast_updater.py): rounds 45 and 47.

Docker, the network and the clock are replaced by fakes, so every step and
every way it can fail is exercised without touching a real daemon.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("fcntl")      # the updater runs on the Linux host only

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("sast_updater", ROOT / "scripts/sast_updater.py")
up = importlib.util.module_from_spec(_spec)
sys.modules["sast_updater"] = up
_spec.loader.exec_module(up)

DOCKERFILE = """ARG SEMGREP_VERSION=1.179.0
ARG OSV_SCANNER_VERSION=2.6.0
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.74.0
"""
REQ_ID = "0123456789abcdef"
TRIVY_OK = json.dumps({"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL"},
                                                        {"Severity": "HIGH"}]}]})
#: Image IDs as `docker image inspect` reports them.
IDS = {up.IMAGE: "sha256:" + "a" * 64, up.CANDIDATE: "sha256:" + "c" * 64}
# 2026-10-20 09:00 in Taipei: past the 08:00 check time.
NOW = datetime(2026, 10, 20, 1, 0, tzinfo=timezone.utc)


def releases_feed(trivy="0.75.0", trivy_at="2026-01-01T00:00:00Z"):
    """GitHub/PyPI as the updater sees them: only trivy has a new release."""
    def fetch(url):
        if "pypi.org" in url:
            return {"releases": {"1.179.0": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}]}}
        tag = {"aquasecurity/trivy": trivy, "google/osv-scanner": "2.6.0",
               "gitleaks/gitleaks": "8.30.1"}[url.split("/repos/")[1].split("/releases")[0]]
        return [{"tag_name": f"v{tag}", "published_at": trivy_at,
                 "draft": False, "prerelease": False}]
    return fetch


class FakeRun:
    """Answers commands by their first matching prefix; records every call."""

    def __init__(self, answers=None):
        self.calls = []
        self.answers = answers or {}

    def __call__(self, cmd, timeout, env):
        self.calls.append((cmd, env))
        line = " ".join(cmd)
        for prefix, answer in self.answers.items():
            if line.startswith(prefix):
                return answer() if callable(answer) else answer
        if "rootfs" in cmd:
            return 0, TRIVY_OK
        if line.startswith("docker image inspect --format"):
            return 0, IDS[cmd[-1]] + "\n"
        return 0, "ok"

    def ran(self, prefix):
        return [c for c, _ in self.calls if " ".join(c).startswith(prefix)]


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


@pytest.fixture
def env(tmp_path):
    (tmp_path / "ops").mkdir()
    (tmp_path / "Dockerfile").write_text(DOCKERFILE)
    (tmp_path / ".env").write_text("DOCKER_GID=988\n")
    return tmp_path


def make(env, run=None, drain_active=0, http_ok=True, free=10 * 1024 ** 3,
         clock=None, fetch=None, now=NOW):
    ops = env / "ops"
    if drain_active is not None:
        (ops / "drain.json").write_text(json.dumps({"id": REQ_ID, "active": drain_active}))
    clock = clock or Clock()
    return up.Updater(run=run or FakeRun(), fetch=fetch or releases_feed(), sleep=clock.sleep,
                      clock=clock, free_bytes=lambda p: free, http_ok=lambda path: http_ok,
                      ops=ops, env_file=env / ".env", tmp=env / ".tmp",
                      dockerfile=env / "Dockerfile", state_file=env / "state.json",
                      wallclock=lambda: now)


def request(action="check", **over):
    body = {"id": REQ_ID, "requested_by": "alice", "action": action}
    body.update(over)
    return json.dumps(body).encode()


def status(env):
    return json.loads((env / "ops" / "status.json").read_text())


def state(env):
    return json.loads((env / "state.json").read_text())


def kinds(env):
    return [e["kind"] for e in state(env).get("events", [])]


def prepared(env, run=None):
    """A candidate built and accepted, as after a morning check."""
    u = make(env, run)
    assert u.process(request("check")) is True
    return state(env)["candidate"]["id"]


# ------------------------------------------------------------ the morning check
def test_a_check_prepares_a_verified_candidate_and_says_so(env):
    run = FakeRun()
    assert make(env, run).process(request("check")) is True

    st, cand = status(env), state(env)["candidate"]
    assert st["phase"] == "ready"
    assert cand["targets"] == {"trivy": "0.75.0"} and cand["previous"] == {"trivy": "0.74.0"}
    assert cand["critical"] == {"current": 1, "candidate": 1}
    assert st["candidate"]["id"] == cand["id"]
    assert st["candidate"]["expires_at"] == up._plus_days(cand["built_at"], up.CANDIDATE_DAYS)
    assert [r["tool"] for r in st["tools"]] == list(up.releases.SOURCES)
    assert st["last_check"] and st["upstream_check"] is True
    assert kinds(env) == ["downloading", "ready"]
    assert "TRIVY_VERSION" not in (env / ".env").read_text(), "a check must not install"
    assert not run.ran(f"docker tag {up.CANDIDATE} {up.IMAGE}"), "a check must not switch"

    (fetch_cmd, fetch_env), = [c for c in run.calls if "fetch-vendor.sh" in " ".join(c[0])]
    assert fetch_cmd[-1] == "--strict" and fetch_env["TRIVY_VERSION"] == "0.75.0"
    build, = run.ran("docker build")
    assert "TRIVY_VERSION=0.75.0" in build and "SEMGREP_VERSION=1.179.0" in build
    assert run.ran("docker run --rm --entrypoint python sast-studio:candidate -m app.selfcheck probe")
    assert any("sample" in c for c in run.ran("docker run --rm -e SAST_SEMGREP_RULES"))
    scans = run.ran("docker run --rm --entrypoint /opt/t/trivy")
    assert [c[c.index("rootfs") - 1] for c in scans] == [up.CANDIDATE, up.IMAGE]
    assert not any("docker.sock" in " ".join(c) for c, _ in run.calls)
    assert not (env / ".tmp").exists(), "the copied Trivy binary was left on disk"


def test_nothing_new_means_nothing_happens_and_nobody_is_told(env):
    run = FakeRun()
    u = make(env, run, fetch=releases_feed(trivy="0.74.0"))
    assert u.process(request("check")) is True
    assert status(env)["phase"] == "idle"
    assert kinds(env) == [] and not run.ran("docker build")


def test_a_release_still_in_its_cooldown_is_not_prepared(env):
    run = FakeRun()
    u = make(env, run, fetch=releases_feed(trivy_at="2026-10-18T00:00:00Z"))
    assert u.process(request("check")) is True
    assert status(env)["phase"] == "idle" and not run.ran("docker build")
    trivy = next(r for r in status(env)["tools"] if r["tool"] == "trivy")
    assert "eligible from 2026-10-25" in trivy["reason"]


def test_a_prepared_candidate_is_not_rebuilt_every_morning(env):
    prepared(env)
    run = FakeRun()
    assert make(env, run).process(request("check")) is True
    assert status(env)["phase"] == "ready" and not run.ran("docker build")
    assert kinds(env) == ["downloading", "ready"]


def test_a_newer_release_replaces_the_candidate(env):
    first = prepared(env)
    run = FakeRun()
    assert make(env, run, fetch=releases_feed(trivy="0.76.0")).process(request("check")) is True
    cand = state(env)["candidate"]
    assert cand["targets"] == {"trivy": "0.76.0"} and cand["id"] != first
    assert run.ran(f"docker rmi {up.CANDIDATE}")


def test_a_candidate_overtaken_by_a_deploy_is_dropped(env):
    prepared(env)
    (env / ".env").write_text("TRIVY_VERSION=0.75.0\n")      # deployed by hand meanwhile
    run = FakeRun()
    assert make(env, run).process(request("check")) is True
    assert status(env)["phase"] == "idle" and "candidate" not in state(env)
    assert run.ran(f"docker rmi {up.CANDIDATE}")


def test_with_checks_off_nothing_is_asked_of_anyone(env):
    (env / ".env").write_text("SAST_UPSTREAM_CHECK=false\n")
    asked = []
    u = make(env, fetch=lambda url: asked.append(url))
    assert u.process(request("check")) is True
    assert asked == [] and status(env)["phase"] == "idle"
    assert "SAST_UPSTREAM_CHECK=false" in status(env)["reason"]
    assert status(env)["upstream_check"] is False


@pytest.mark.parametrize("prefix, step", [
    ("bash scripts/fetch-vendor.sh", "downloading"),
    ("docker build", "building"),
    ("docker volume create", "verifying"),
    ("docker run --rm --entrypoint python sast-studio:candidate -m app.selfcheck probe", "verifying"),
    ("docker run --rm -e SAST_SEMGREP_RULES", "verifying"),
    ("docker create", "verifying"),
    ("docker cp", "verifying"),
])
def test_a_failing_step_is_a_download_failure_with_no_candidate_left(env, prefix, step):
    run = FakeRun({prefix: (1, "line1\nline2\nCHECKSUM MISMATCH\n")})
    assert make(env, run).process(request("check")) is False
    st = status(env)
    assert (st["phase"], st["step"]) == ("failed", step) and "CHECKSUM MISMATCH" in st["reason"]
    assert kinds(env) == ["downloading", "download_failed"]
    ev = state(env)["events"][-1]
    assert (ev["step"], ev["targets"]) == (step, {"trivy": "0.75.0"})
    assert "candidate" not in state(env) and run.ran(f"docker rmi {up.CANDIDATE}")


def test_a_step_with_no_output_still_says_why(env):
    make(env, FakeRun({"docker build": (2, "")})).process(request("check"))
    assert status(env)["reason"] == "exit 2"


def test_a_full_disk_stops_before_downloading(env):
    run = FakeRun()
    assert make(env, run, free=1024 ** 3).process(request("check")) is False
    assert "1.0 GB free; need 3 GB" in status(env)["reason"]
    assert kinds(env) == ["downloading", "download_failed"] and not run.ran("bash")


def test_more_critical_vulnerabilities_reject_the_candidate(env):
    worse = json.dumps({"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL"}] * 3}]})
    answers = iter([(0, "WARN noise\n" + worse), (0, TRIVY_OK)])
    run = FakeRun({"docker run --rm --entrypoint /opt/t/trivy": lambda: next(answers)})
    assert make(env, run).process(request("check")) is False
    st = status(env)
    assert st["step"] == "verifying" and "3 CRITICAL" in st["reason"]
    assert st["critical"] == {"current": 1, "candidate": 3}


def test_an_unreadable_trivy_report_is_a_failure(env):
    run = FakeRun({"docker run --rm --entrypoint /opt/t/trivy": (0, "no json here")})
    assert make(env, run).process(request("check")) is False
    assert status(env)["reason"] == "could not read Trivy's report"
    assert not (env / ".tmp").exists()


def test_a_release_changed_during_the_download_is_refused(env):
    stamps = iter(["2026-01-01T00:00:00Z", "2026-10-05T00:00:00Z"])

    def fetch(url):
        if "aquasecurity/trivy" in url:
            return [{"tag_name": "v0.75.0", "published_at": next(stamps),
                     "draft": False, "prerelease": False}]
        return releases_feed()(url)
    run = FakeRun()
    assert make(env, run, fetch=fetch).process(request("check")) is False
    st = status(env)
    assert st["step"] == "downloading" and "changed while it was being downloaded" in st["reason"]
    assert not run.ran("docker build")


def test_an_unexpected_error_in_a_check_is_reported_and_cleaned_up(env):
    (env / "Dockerfile").unlink()
    run = FakeRun()
    assert make(env, run).process(request("check")) is False
    st = status(env)
    assert st["phase"] == "failed" and "FileNotFoundError" in st["reason"]
    assert kinds(env)[-1] == "download_failed" and run.ran(f"docker rmi {up.CANDIDATE}")


def test_a_failure_while_building_is_reported_with_its_step(env):
    def boom():
        raise RuntimeError("daemon went away")
    run = FakeRun({"docker build": boom})
    assert make(env, run).process(request("check")) is False
    assert status(env)["step"] == "building" and "RuntimeError" in status(env)["reason"]


# ------------------------------------------------------------ applying
def test_applying_switches_records_and_announces(env):
    cand = prepared(env)
    run = FakeRun()
    assert make(env, run).process(request("apply", candidate=cand)) is True
    st = status(env)
    assert st["phase"] == "done" and st["targets"] == {"trivy": "0.75.0"}
    assert st["overrides"] == {"trivy": {"repo": "0.74.0", "local": "0.75.0"}}
    assert "TRIVY_VERSION=0.75.0" in (env / ".env").read_text()
    assert oct(os.stat(env / ".env").st_mode & 0o777) == "0o600"
    assert kinds(env) == ["downloading", "ready", "updating", "updated"]
    assert state(env)["events"][2]["requested_by"] == "alice"
    assert "candidate" not in state(env) and status(env)["candidate"] is None
    assert run.ran(f"docker tag {IDS[up.CANDIDATE]} {up.IMAGE}"), "switched by the ID that was verified"
    assert run.ran("docker compose exec -T sast-studio python -m app.selfcheck probe")
    assert run.ran("bash scripts/prune-rollbacks.sh")
    assert not run.ran("docker build"), "applying must not build anything"


def test_a_deploy_since_the_build_retires_the_candidate(env):
    """Round 47 review: a candidate built over older code must not bring it back."""
    prepared(env)
    first = state(env)["candidate"]
    assert first["base"] == IDS[up.IMAGE] and first["image"] == IDS[up.CANDIDATE]
    run = FakeRun({f"docker image inspect --format {{{{.Id}}}} {up.IMAGE}":
                   (0, "sha256:" + "b" * 64)})
    assert make(env, run).process(request("check")) is True
    assert run.ran(f"docker rmi {up.CANDIDATE}") and run.ran("docker build")
    assert state(env)["candidate"]["id"] != first["id"]
    assert state(env)["candidate"]["base"] == "sha256:" + "b" * 64


def test_a_candidate_whose_image_ids_cannot_be_read_is_not_offered(env):
    run = FakeRun({f"docker image inspect --format {{{{.Id}}}} {up.CANDIDATE}": (0, "odd")})
    assert make(env, run).process(request("check")) is False
    assert status(env)["step"] == "verifying" and "image IDs" in status(env)["reason"]
    assert "candidate" not in state(env)


@pytest.mark.parametrize("field, value", [
    ("id", "x"), ("targets", {}), ("targets", {"nope": "1.0.0"}),
    ("targets", {"trivy": "1.0;rm"}), ("previous", "x"), ("built_at", 5),
    ("base", None), ("image", "c" * 64),
])
def test_an_unsound_candidate_in_the_state_is_no_candidate(env, field, value):
    prepared(env)
    data = state(env)
    data["candidate"][field] = value
    (env / "state.json").write_text(json.dumps(data))
    u = make(env)
    assert u.candidate() is None
    u.status = {}
    u.report("idle")                             # once a KeyError every minute
    assert status(env)["candidate"] is None
    run = FakeRun()
    assert make(env, run).process(request("check")) is True
    assert run.ran(f"docker rmi {up.CANDIDATE}") and state(env)["candidate"]["id"] != "x"


@pytest.mark.parametrize("case, why", [
    ("never", "does not exist"),            # nothing was ever prepared
    ("other", "does not exist"),            # an id that is not the candidate's
    ("expired", "older than 14 days"),
    ("gone", "image is gone"),
    ("retagged", "not the one verified"),
    ("redeployed", "redeployed after the candidate was built"),
    ("running", "already running"),
])
def test_an_apply_that_cannot_be_honoured_says_why(env, case, why):
    cand = "f" * 16 if case == "never" else prepared(env)
    if case == "other":
        cand = "e" * 16
    if case == "running":
        (env / ".env").write_text("TRIVY_VERSION=0.75.0\n")
    answers = {
        "gone": {f"docker image inspect --format {{{{.Id}}}} {up.CANDIDATE}": (1, "No such image")},
        "retagged": {f"docker image inspect --format {{{{.Id}}}} {up.CANDIDATE}":
                     (0, "sha256:" + "d" * 64)},
        "redeployed": {f"docker image inspect --format {{{{.Id}}}} {up.IMAGE}":
                       (0, "sha256:" + "b" * 64)},
    }.get(case, {})
    run = FakeRun(answers)
    now = NOW + timedelta(days=15) if case == "expired" else NOW
    assert make(env, run, now=now).process(request("apply", candidate=cand)) is False
    st = status(env)
    assert st["phase"] == "failed" and why in st["reason"]
    assert kinds(env)[-1] == "update_failed"
    assert not run.ran(f"docker tag {IDS[up.CANDIDATE]} {up.IMAGE}")


def test_waiting_too_long_for_scans_keeps_the_candidate(env):
    cand = prepared(env)
    clock = Clock()
    assert make(env, drain_active=3, clock=clock).process(
        request("apply", candidate=cand)) is False
    st = status(env)
    assert st["step"] == "waiting_for_scans" and "60 minutes" in st["reason"]
    assert clock.t >= up.DRAIN_TIMEOUT
    assert state(env)["candidate"]["id"] == cand, "it can be applied later"
    assert kinds(env)[-2:] == ["updating", "update_failed"]


@pytest.mark.parametrize("drain", ["not json", json.dumps([0]), "[" * 100000,
                                   json.dumps({"id": "ffffffffffffffff", "active": 0}),
                                   json.dumps({"id": REQ_ID, "active": False}),
                                   json.dumps({"id": REQ_ID, "active": 0.0})])
def test_a_drain_report_for_another_request_is_not_trusted(env, drain):
    u = make(env, drain_active=None)
    (env / "ops" / "drain.json").write_text(drain)
    with pytest.raises(up.Failed):
        u.wait_for_scans(REQ_ID)


def test_switches_once_scans_finish(env):
    clock = Clock()
    u = make(env, drain_active=None, clock=clock)
    drain = env / "ops" / "drain.json"
    drain.write_text(json.dumps({"id": REQ_ID, "active": 1}))

    def sleep(s):
        clock.sleep(s)
        drain.write_text(json.dumps({"id": REQ_ID, "active": 0}))
    u.sleep = sleep
    u.wait_for_scans(REQ_ID)
    assert clock.t == up.DRAIN_POLL


UP_ONCE_FAILS = iter(())


@pytest.mark.parametrize("answers, why", [
    ({f"docker tag {IDS[up.CANDIDATE]}": (1, "no such image")}, "no such image"),
    ({"docker compose up -d --no-build": lambda: next(UP_ONCE_FAILS)}, "port in use"),
    ({"docker compose exec": (1, "semgrep NOT AVAILABLE")}, "semgrep NOT AVAILABLE"),
])
def test_a_bad_switch_brings_the_previous_image_back(env, answers, why):
    global UP_ONCE_FAILS
    cand = prepared(env)
    UP_ONCE_FAILS = iter([(1, "port in use"), (0, "ok")])
    run = FakeRun(answers)
    assert make(env, run).process(request("apply", candidate=cand)) is False
    st = status(env)
    assert st["step"] == "switching" and why in st["reason"]
    assert "previous image is back" in st["reason"]
    assert run.ran(f"docker tag {up.PREVIOUS} {up.IMAGE}")
    assert "TRIVY_VERSION" not in (env / ".env").read_text()
    assert "candidate" not in state(env), "a candidate that failed live is not offered again"
    assert kinds(env)[-1] == "update_failed"


def test_a_rollback_that_fails_says_so_plainly(env):
    cand = prepared(env)
    make(env, http_ok=False).process(request("apply", candidate=cand))
    assert "ROLLBACK FAILED" in status(env)["reason"]
    assert "did not become healthy" in status(env)["reason"]
    cand = prepared(env)
    run = FakeRun({f"docker tag {up.PREVIOUS}": (1, "gone"), "docker compose exec": (1, "broken")})
    make(env, run).process(request("apply", candidate=cand))
    assert "ROLLBACK FAILED" in status(env)["reason"]


def test_anything_unexpected_while_switching_still_rolls_back(env):
    cand = prepared(env)

    def boom():
        raise RuntimeError("daemon went away")
    assert make(env, FakeRun({"docker compose exec": boom})).process(
        request("apply", candidate=cand)) is False
    st = status(env)
    assert "RuntimeError: daemon went away" in st["reason"]
    assert "previous image is back" in st["reason"]


def test_an_unexpected_error_before_applying_is_reported(env):
    cand = prepared(env)
    (env / "Dockerfile").unlink()
    assert make(env).process(request("apply", candidate=cand)) is False
    assert "FileNotFoundError" in status(env)["reason"] and kinds(env)[-1] == "update_failed"


def test_switched_but_unrecorded_versions_are_flagged(env):
    cand = prepared(env)
    u = make(env)
    u.env_file = env / "missing-dir" / ".env"
    assert u.process(request("apply", candidate=cand)) is True
    ev = state(env)["events"][-1]
    assert ev["kind"] == "updated"
    assert "TRIVY_VERSION=0.75.0" in ev["warning"] and "next deploy goes back" in ev["warning"]


# ------------------------------------------------------------ requests
@pytest.mark.parametrize("raw, reason", [
    (b"", "no request"),
    (b"x" * (up.MAX_REQUEST + 1), "request too large"),
    (b"{nope", "request is not JSON"),
    (b"[" * 5000, "request is not JSON"),
    (b"[1]", "request is not an object"),
    (request(id="../../etc"), "bad request id"),
    (request(requested_by="a b;rm"), "bad requester name"),
    (request(action="install"), "unknown action"),
    (request(action=["check"]), "unknown action"),       # unhashable: once a TypeError
    (request(action={"a": 1}), "unknown action"),
    (request(action="apply"), "bad candidate id"),
    (request(action="apply", candidate="../x"), "bad candidate id"),
])
def test_a_bad_request_is_refused_before_anything_runs(env, raw, reason):
    run = FakeRun()
    assert make(env, run).process(raw) is False
    st = status(env)
    assert (st["phase"], st["step"], st["reason"]) == ("failed", "checking", reason)
    assert run.calls == []


def test_a_request_that_breaks_the_parser_still_ends_failed(env, monkeypatch):
    monkeypatch.setattr(up, "parse_request", lambda raw: [][1])
    assert make(env).process(request("check")) is False
    assert status(env)["reason"] == "unreadable request (IndexError)"


def test_a_request_cannot_name_versions():
    parsed = up.parse_request(request("check", targets={"trivy": "9.9.9"}))
    assert "targets" not in parsed and parsed["action"] == "check"


# ------------------------------------------------------------ schedule and expiry
@pytest.mark.parametrize("utc_hour, due", [(23, False), (0, True), (5, True)])
def test_the_daily_check_runs_once_after_eight_in_taipei(env, utc_hour, due):
    # 00:00 UTC is 08:00 in Taipei; 23:00 UTC the day before is 07:00.
    now = datetime(2026, 10, 20, utc_hour, 0, tzinfo=timezone.utc)
    u = make(env, now=now)
    assert u.scheduled_due() is due
    assert u.scheduled_due() is False, "twice in one day"


def test_the_check_time_and_zone_come_from_env(env):
    (env / ".env").write_text("SAST_UPGRADE_CHECK_AT=03:30\nSAST_UPGRADE_TZ=UTC\n")
    assert make(env, now=datetime(2026, 10, 20, 3, 0, tzinfo=timezone.utc)).scheduled_due() is False
    assert make(env, now=datetime(2026, 10, 20, 3, 31, tzinfo=timezone.utc)).scheduled_due() is True
    (env / "state.json").unlink()
    (env / ".env").write_text("SAST_UPGRADE_CHECK_AT=25:99\nSAST_UPGRADE_TZ=Nowhere/City\n")
    assert make(env, now=NOW).scheduled_due() is True        # defaults: 08:00 Taipei


def test_an_unapplied_candidate_expires_after_fourteen_days(env):
    prepared(env)
    run = FakeRun()
    make(env, run, now=NOW + timedelta(days=13)).expire()
    assert "candidate" in state(env)
    make(env, run, now=NOW + timedelta(days=15)).expire()
    assert "candidate" not in state(env) and run.ran(f"docker rmi {up.CANDIDATE}")
    last = state(env)["events"][-1]
    assert last["kind"] == "expired" and last["targets"] == {"trivy": "0.75.0"}


def test_a_candidate_with_an_unreadable_date_counts_as_expired(env):
    u = make(env)
    assert u._expired({"built_at": "yesterday"}) is True
    assert u._expired({}) is True
    assert up._plus_days("garbage", 14) == ""


def test_the_state_file_is_read_defensively(env):
    (env / "state.json").write_text("not json")
    assert make(env).state == {}
    (env / "state.json").write_text("[1]")
    assert make(env).state == {}
    u = make(env)
    u.state_file = env / "missing" / "state.json"
    u.event("ready")                                         # cannot save: no error
    assert up.env_setting("A=1\n B = 2 \n", "B") == "2" and up.env_setting("", "X") == ""


def test_events_are_capped(env):
    u = make(env)
    for i in range(up.MAX_EVENTS + 5):
        u.event("downloading", n=i)
    assert len(state(env)["events"]) == up.MAX_EVENTS
    assert state(env)["events"][0]["n"] == 5


def test_the_same_event_again_is_counted_not_repeated(env):
    """Round 47 review: a refusal every minute must not push the news out."""
    u = make(env)
    u.event("updated", targets={"trivy": "0.75.0"})
    for _ in range(up.MAX_EVENTS * 2):
        u.event("update_failed", step="checking", reason="no such candidate")
    events = state(env)["events"]
    assert [e["kind"] for e in events] == ["updated", "update_failed"]
    assert events[-1]["count"] == up.MAX_EVENTS * 2
    u.event("update_failed", step="checking", reason="something else")
    assert len(state(env)["events"]) == 3


# ------------------------------------------------------------ files the container can touch
def test_untrusted_reads_skip_links_and_fifos_and_cap_size(tmp_path):
    target = tmp_path / "real"
    target.write_text("secret")
    (tmp_path / "link").symlink_to(target)
    assert up.read_untrusted(tmp_path / "link", 100) == b""
    os.mkfifo(tmp_path / "fifo")
    assert up.read_untrusted(tmp_path / "fifo", 100) == b""
    assert up.read_untrusted(tmp_path / "missing", 100) == b""
    assert up.read_untrusted(target, 3) == b"secr"     # limit + 1: "too large" is detectable


def test_writes_replace_a_link_instead_of_following_it(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (tmp_path / "status.json").symlink_to(victim)
    up.write_replace(tmp_path / "status.json", "new")
    assert victim.read_text() == "keep"
    assert (tmp_path / "status.json").read_text() == "new"
    assert not (tmp_path / "status.json").is_symlink()


def test_version_files():
    assert up.dockerfile_versions(DOCKERFILE) == {
        "semgrep": "1.179.0", "trivy": "0.74.0", "osv_scanner": "2.6.0", "gitleaks": "8.30.1"}
    assert up.env_versions("TRIVY_VERSION=0.75.0\nSEMGREP_VERSION=bad\nX=1\n") == {"trivy": "0.75.0"}
    text = up.update_env("A=1\nTRIVY_VERSION=0.74.0\n", {"trivy": "0.75.0", "gitleaks": "8.31.0"})
    assert text == "A=1\nTRIVY_VERSION=0.75.0\nGITLEAKS_VERSION=8.31.0\n"
    assert up.count_critical('noise {"Results": null}') == 0
    assert up.count_critical('{"Results": []}\nWARN after the report {x}') == 0


def test_ops_is_tidied_of_anything_the_container_should_not_leave(env):
    ops = env / "ops"
    (ops / "request.json").write_text("{}")
    # What a compromised container could leave: a setuid executable.
    os.chmod(ops / "request.json", stat.S_ISUID | stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
    (ops / ".status.json.ab12cd34.tmp").write_text("x")      # the app's own temp file
    (ops / "status.json").mkdir()                            # would break every write
    (ops / "status.json" / "deep").write_text("x")
    (ops / "evil").write_text("#!/bin/sh")
    os.mkfifo(ops / "drain.json")
    (ops / "update.log").symlink_to("/etc/passwd")
    removed = up.tidy_ops(ops)
    assert sorted(removed) == ["drain.json", "evil", "status.json", "update.log"]
    assert sorted(p.name for p in ops.iterdir()) == [".status.json.ab12cd34.tmp", "request.json"]
    assert oct(os.stat(ops / "request.json").st_mode & 0o7777) == "0o644"
    assert os.path.exists("/etc/passwd")


def test_tidy_keeps_an_expected_file_it_may_not_chmod(env, monkeypatch):
    ops = env / "ops"
    (ops / "request.json").write_text("{}")
    (ops / "stray").write_text("x")

    def refuse(fd, mode):
        raise PermissionError("not owner")
    monkeypatch.setattr(up.os, "fchmod", refuse)
    assert up.tidy_ops(ops) == ["stray"]
    assert (ops / "request.json").exists()


def test_tidy_carries_on_when_the_container_races_it(env, monkeypatch):
    ops = env / "ops"
    (ops / "a").write_text("x")
    (ops / "b").write_text("x")
    real = up.os.unlink
    calls = []

    def flaky(path):
        calls.append(path)
        if len(calls) == 1:
            raise FileNotFoundError(path)
        real(path)
    monkeypatch.setattr(up.os, "unlink", flaky)
    assert len(up.tidy_ops(ops)) == 1 and len(calls) == 2


def test_reports_survive_an_ops_dir_the_container_broke(env):
    (env / "ops" / "status.json").mkdir()
    (env / "ops" / "update.log").mkdir()
    cand = prepared(env)
    assert make(env).process(request("apply", candidate=cand)) is True
    assert "TRIVY_VERSION=0.75.0" in (env / ".env").read_text()


# ------------------------------------------------------------ recovery and main
def cut_short(env, phase, action="check"):
    """A run that died in `phase`: its mark in the host state."""
    path = env / "state.json"
    data = json.loads(path.read_text()) if path.exists() else {}
    data["running"] = {"phase": phase, "action": action}
    path.write_text(json.dumps(data))


def test_a_run_cut_short_is_reported_on_the_next_start(env):
    cut_short(env, "building")
    make(env).recover()
    st = status(env)
    assert st["phase"] == "failed" and st["step"] == "building" and st["action"] == "check"
    assert "nothing was switched" in st["reason"] and kinds(env) == ["download_failed"]
    assert "running" not in state(env)
    cut_short(env, "switching", "apply")
    make(env).recover()
    assert "rollback-previous" in status(env)["reason"] and kinds(env)[-1] == "update_failed"
    for odd in ({"phase": "done"}, {"phase": []}, "switching", {"phase": "switching",
                                                                "action": ["x"]}):
        data = state(env)
        data["running"] = odd
        (env / "state.json").write_text(json.dumps(data))
        before = kinds(env)
        make(env).recover()
        if isinstance(odd, dict) and odd.get("action") == ["x"]:
            assert status(env)["action"] == "", "an odd action is not carried over"
        else:
            assert kinds(env) == before


def test_a_run_under_way_is_marked_in_the_host_state(env):
    u = make(env)
    u.status = {"action": "check"}
    u.report("building")
    assert state(env)["running"] == {"phase": "building", "action": "check"}
    u.report("ready")
    assert "running" not in state(env)


@pytest.mark.parametrize("leftover", [
    json.dumps({"phase": "switching", "evil": 1}),
    json.dumps({"phase": []}),                  # unhashable: once a TypeError every minute
    json.dumps({"phase": {}}),
    "garbage", "[" * 100000,
])
def test_status_json_cannot_start_a_recovery_or_carry_over(env, leftover):
    """Round 47 review: status.json is the container's to write."""
    (env / "ops" / "status.json").write_text(leftover)
    make(env).recover()
    assert (env / "ops" / "status.json").read_text() == leftover
    assert kinds(env) == [] if (env / "state.json").exists() else True
    u = make(env)
    u.status = {}
    u.report("idle")
    assert "evil" not in status(env)


def test_housekeeping_that_fails_does_not_stop_the_run(env, tmp_path, monkeypatch):
    u = make(env)
    monkeypatch.setattr(u, "recover", lambda: 1 / 0)
    monkeypatch.setattr(u, "expire", lambda: [][1])
    (env / "ops" / "request.json").write_bytes(request("check"))
    assert up.main(u, tmp_path / "lock", argv=[]) == 0
    assert status(env)["phase"] == "ready"
    log = (env / "ops" / "update.log").read_text()
    assert "housekeeping failed: ZeroDivisionError" in log and "IndexError" in log


def test_main_does_nothing_without_ops_or_anything_due(env, tmp_path):
    lock = tmp_path / "lock"
    missing = make(env)
    missing.ops = tmp_path / "nowhere"
    assert up.main(missing, lock, argv=[]) == 0
    early = make(env, now=datetime(2026, 10, 19, 22, 0, tzinfo=timezone.utc))   # 06:00 Taipei
    assert up.main(early, lock, argv=[]) == 0
    assert not (env / "ops" / "status.json").exists()


def test_a_failed_scheduled_check_is_tried_again_later(env, tmp_path):
    run = FakeRun({"docker build": (1, "no")})
    assert up.main(make(env, run), tmp_path / "lock", argv=[]) == 1
    retry = state(env)["retry_at"]
    assert retry == (NOW + timedelta(hours=up.RETRY_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    soon = make(env, now=NOW + timedelta(hours=1))
    assert soon.scheduled_due() is False
    later = make(env, now=NOW + timedelta(hours=up.RETRY_HOURS, minutes=1))
    assert later.scheduled_due() is True and "retry_at" not in state(env)
    assert make(env, now=NOW + timedelta(hours=up.RETRY_HOURS, minutes=2)).scheduled_due() \
        is False, "one retry per failure"
    # A failure from the button does not schedule anything.
    (env / "state.json").unlink()
    make(env, FakeRun({"docker build": (1, "no")})).process(request("check"))
    assert "retry_at" not in state(env)


def test_a_state_that_cannot_be_saved_is_not_a_check_every_minute(env):
    u = make(env)
    u.state_file = env / "no-such-dir" / "state.json"
    assert u.scheduled_due() is False
    assert "could not save state.json" in (env / "ops" / "update.log").read_text()


def test_main_runs_the_daily_check_when_it_is_due(env, tmp_path):
    assert up.main(make(env), tmp_path / "lock", argv=[]) == 0
    assert status(env)["phase"] == "ready" and status(env)["trigger"] == "schedule"
    run = FakeRun({"docker build": (1, "no")})
    (env / "state.json").unlink()
    assert up.main(make(env, run), tmp_path / "lock", argv=[]) == 1


def test_main_check_flag_and_requests(env, tmp_path):
    lock = tmp_path / "lock"
    assert up.main(make(env, now=datetime(2026, 10, 19, 22, 0, tzinfo=timezone.utc)),
                   lock, argv=["--check"]) == 0
    assert status(env)["trigger"] == "manual"
    cand = state(env)["candidate"]["id"]
    (env / "ops" / "request.json").write_text(request("apply", candidate=cand).decode())
    (env / "ops" / "stray").write_text("x")
    assert up.main(make(env), lock, argv=[]) == 0
    assert not (env / "ops" / "request.json").exists(), "the request would run again"
    assert not (env / "ops" / "stray").exists(), "main did not tidy ops/"
    assert status(env)["phase"] == "done"
    (env / "ops" / "request.json").write_text(request("apply", candidate="a" * 16).decode())
    assert up.main(make(env), lock, argv=[]) == 1
    run = FakeRun({"docker build": (1, "no")})
    assert up.main(make(env, run), lock, argv=["--check"]) == 0     # already at 0.75.0


def test_main_expires_an_old_candidate(env, tmp_path):
    prepared(env)
    run = FakeRun()
    late = NOW + timedelta(days=20)
    up.main(make(env, run, now=late, fetch=releases_feed(trivy="0.75.0")), tmp_path / "lock", argv=[])
    assert run.ran(f"docker rmi {up.CANDIDATE}")


def test_main_steps_aside_while_another_run_holds_the_lock(env, tmp_path):
    import fcntl
    lock = tmp_path / "lock"
    (env / "ops" / "request.json").write_text(request().decode())
    with open(lock, "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        assert up.main(make(env), lock, argv=[]) == 0
    assert (env / "ops" / "request.json").exists(), "a held lock still consumed the request"


@pytest.mark.skipif((ROOT / "ops").exists(), reason="a real ops/ here would be processed")
def test_the_script_runs_as_a_program(monkeypatch):
    import runpy
    monkeypatch.setattr(sys, "argv", ["sast_updater.py"])
    with pytest.raises(SystemExit) as exit_:
        runpy.run_path(str(ROOT / "scripts/sast_updater.py"), run_name="__main__")
    assert exit_.value.code == 0


# ------------------------------------------------------------ the real helpers
def test_run_starts_only_its_own_programs():
    assert up._run(["bash", "-c", "echo hi"], 30) == (0, "hi\n")
    assert up._run(["bash", "-c", "exit 3"], 30)[0] == 3
    assert up._run(["bash", "-c", "sleep 5"], 1) == (124, "timed out after 1s")
    assert up._run([sys.executable, "-c", "print(1)"], 5)[0] == 126
    assert up._run([], 5)[0] == 126


def test_run_reports_a_program_that_is_not_installed(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    assert up._run(["docker", "ps"], 5)[0] == 127


class _FakeHTTP:
    answer = 200

    def __init__(self, host, port, timeout):
        assert (host, port) == ("localhost", 8080)

    def request(self, method, path):
        if _FakeHTTP.answer is None:
            raise ConnectionRefusedError("refused")

    def getresponse(self):
        return type("R", (), {"status": _FakeHTTP.answer})()

    def close(self):
        pass


def test_http_and_disk_helpers(monkeypatch, tmp_path):
    monkeypatch.setattr(up.http.client, "HTTPConnection", _FakeHTTP)
    _FakeHTTP.answer = 200
    assert up._http_ok("/api/health") is True
    _FakeHTTP.answer = 502
    assert up._http_ok("/api/health") is False
    _FakeHTTP.answer = None
    assert up._http_ok("/api/health") is False
    assert up._free_bytes(tmp_path) > 0


def test_missing_pins_and_env_file_are_not_errors(env):
    assert up.dockerfile_versions("FROM python:3.11-slim\n") == {}
    (env / ".env").unlink()
    u = make(env)
    assert u.overrides() == {}
    assert u.current_versions()["trivy"] == "0.74.0"


@pytest.mark.parametrize("value, on", [("", True), ("true", True), ("ON", True), ("1", True),
                                       ("false", False), ("off", False), ("garbage", False)])
def test_the_switch_reads_like_the_app_reads_it(env, value, on):
    (env / ".env").write_text(f"SAST_UPSTREAM_CHECK={value}\n" if value else "")
    assert make(env).upstream_enabled() is on
