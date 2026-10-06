"""Round 45: the host updater (scripts/sast_updater.py).

Docker, the network and the clock are replaced by fakes, so every step and
every way it can fail is exercised without touching a real daemon.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
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


def _fetch(url):
    # trivy 0.75.0 has been out for long enough; nothing else is asked about.
    return [{"tag_name": "v0.75.0", "published_at": "2026-01-01T00:00:00Z",
             "draft": False, "prerelease": False}]


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
    ops = tmp_path / "ops"
    ops.mkdir()
    (tmp_path / "Dockerfile").write_text(DOCKERFILE)
    envf = tmp_path / ".env"
    envf.write_text("DOCKER_GID=988\n")
    return tmp_path


def make(env, run=None, drain_active=0, http_ok=True, free=10 * 1024 ** 3, clock=None):
    ops = env / "ops"
    if drain_active is not None:
        (ops / "drain.json").write_text(json.dumps({"id": REQ_ID, "active": drain_active}))
    clock = clock or Clock()
    return up.Updater(run=run or FakeRun(), fetch=_fetch, sleep=clock.sleep, clock=clock,
                      free_bytes=lambda p: free, http_ok=lambda url: http_ok,
                      ops=ops, env_file=env / ".env", tmp=env / ".tmp",
                      dockerfile=env / "Dockerfile")


def request(**over):
    body = {"id": REQ_ID, "requested_by": "alice", "targets": {"trivy": "0.75.0"}}
    body.update(over)
    return json.dumps(body).encode()


def status(env):
    return json.loads((env / "ops" / "status.json").read_text())


# ------------------------------------------------------------ the happy path
def test_an_upgrade_runs_every_step_and_records_the_version(env):
    run = FakeRun()
    u = make(env, run)
    assert u.process(request()) is True

    st = status(env)
    assert st["phase"] == "done" and st["targets"] == {"trivy": "0.75.0"}
    assert st["critical"] == {"current": 1, "candidate": 1}
    assert st["overrides"] == {"trivy": {"repo": "0.74.0", "local": "0.75.0"}}
    envtext = (env / ".env").read_text()
    assert "DOCKER_GID=988" in envtext and "TRIVY_VERSION=0.75.0" in envtext
    assert oct(os.stat(env / ".env").st_mode & 0o777) == "0o600"

    # Checksums verified strictly, with the new version, before the build.
    (fetch_cmd, fetch_env), = [c for c in run.calls if "fetch-vendor.sh" in " ".join(c[0])]
    assert fetch_cmd[-1] == "--strict" and fetch_env["TRIVY_VERSION"] == "0.75.0"
    build, = run.ran("docker build")
    assert "TRIVY_VERSION=0.75.0" in build and "SEMGREP_VERSION=1.179.0" in build
    assert run.ran("docker run --rm --entrypoint python sast-studio:candidate -m app.selfcheck probe")
    assert any("sample" in c for c in run.ran("docker run --rm -e SAST_SEMGREP_RULES"))
    # The candidate's own Trivy judges both images, without the socket.
    scans = [c for c in run.ran("docker run --rm --entrypoint /opt/t/trivy")]
    assert [c[c.index("rootfs") - 1] for c in scans] == [up.CANDIDATE, up.IMAGE]
    assert not any("docker.sock" in " ".join(c) for c, _ in run.calls)
    assert run.ran(f"docker tag {up.CANDIDATE} {up.IMAGE}")
    assert run.ran("docker compose exec -T sast-studio python -m app.selfcheck probe")
    assert not (env / ".tmp").exists(), "the copied Trivy binary was left on disk"
    log = (env / "ops" / "update.log").read_text()
    assert "phase: done" in log and "$ docker build" in log


# ------------------------------------------------------------ refusals
@pytest.mark.parametrize("raw, reason", [
    (b"", "no request"),
    (b"x" * (up.MAX_REQUEST + 1), "request too large"),
    (b"{nope", "request is not JSON"),
    (b"[1]", "request is not an object"),
    (request(id="../../etc"), "bad request id"),
    (request(requested_by="a b;rm"), "bad requester name"),
    (request(targets={}), "bad target list"),
    (request(targets=[]), "bad target list"),
    (request(targets={"bearer": "1.0.0"}), "cannot upgrade 'bearer'"),
    (request(targets={"trivy": "0.75.0; rm -rf /"}), "bad version for trivy"),
    (request(targets={"trivy": 75}), "bad version for trivy"),
    (b"[" * 5000, "request is not JSON"),
])
def test_a_bad_request_is_refused_before_anything_runs(env, raw, reason):
    run = FakeRun()
    assert make(env, run).process(raw) is False
    st = status(env)
    assert (st["phase"], st["step"], st["reason"]) == ("failed", "checking", reason)
    assert run.calls == []


def test_a_version_not_on_offer_is_refused(env):
    run = FakeRun()
    assert make(env, run).process(request(targets={"trivy": "0.76.0"})) is False
    assert "not the version on offer" in status(env)["reason"]
    assert not run.ran("docker build")


def test_a_full_disk_is_refused_before_building(env):
    run = FakeRun()
    assert make(env, run, free=1024 ** 3).process(request()) is False
    assert "1.0 GB free; need 3 GB" in status(env)["reason"]
    assert not run.ran("bash")


@pytest.mark.parametrize("prefix, step", [
    ("bash scripts/fetch-vendor.sh", "downloading"),
    ("docker build", "building"),
    ("docker volume create", "verifying"),
    ("docker run --rm --entrypoint python sast-studio:candidate -m app.selfcheck probe", "verifying"),
    ("docker run --rm -e SAST_SEMGREP_RULES", "verifying"),
    ("docker create", "verifying"),
    ("docker cp", "verifying"),
])
def test_a_failing_step_stops_the_upgrade_and_removes_the_candidate(env, prefix, step):
    run = FakeRun({prefix: (1, "line1\nline2\nCHECKSUM MISMATCH\n")})
    assert make(env, run).process(request()) is False
    st = status(env)
    assert (st["phase"], st["step"]) == ("failed", step)
    assert "CHECKSUM MISMATCH" in st["reason"]
    assert run.ran(f"docker rmi {up.CANDIDATE}")
    assert not run.ran(f"docker tag {up.CANDIDATE}"), "a failed candidate was switched in"
    assert "TRIVY_VERSION" not in (env / ".env").read_text()


def test_a_step_with_no_output_still_says_why(env):
    run = FakeRun({"docker build": (2, "")})
    make(env, run).process(request())
    assert status(env)["reason"] == "exit 2"


def test_more_critical_vulnerabilities_block_the_switch(env):
    worse = json.dumps({"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL"}] * 3}]})
    run = FakeRun()
    answers = iter([(0, "WARN noise\n" + worse), (0, TRIVY_OK)])
    run.answers = {"docker run --rm --entrypoint /opt/t/trivy": lambda: next(answers)}
    assert make(env, run).process(request()) is False
    st = status(env)
    assert st["step"] == "verifying" and "3 CRITICAL" in st["reason"]
    assert st["critical"] == {"current": 1, "candidate": 3}


def test_an_unreadable_trivy_report_is_a_failure(env):
    run = FakeRun({"docker run --rm --entrypoint /opt/t/trivy": (0, "no json here")})
    assert make(env, run).process(request()) is False
    assert status(env)["reason"] == "could not read Trivy's report"
    assert not (env / ".tmp").exists()


# ------------------------------------------------------------ waiting and switching
def test_waits_for_running_scans_then_gives_up_after_an_hour(env):
    clock = Clock()
    run = FakeRun()
    u = make(env, run, drain_active=3, clock=clock)
    assert u.process(request()) is False
    st = status(env)
    assert st["step"] == "waiting_for_scans" and "60 minutes" in st["reason"]
    assert clock.t >= up.DRAIN_TIMEOUT
    assert not run.ran(f"docker tag {up.CANDIDATE}")


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
    real_sleep = clock.sleep

    def sleep(s):
        real_sleep(s)
        drain.write_text(json.dumps({"id": REQ_ID, "active": 0}))
    u.sleep = sleep
    u.wait_for_scans(REQ_ID)
    assert clock.t == up.DRAIN_POLL


@pytest.mark.parametrize("answers, why", [
    ({f"docker tag {up.CANDIDATE}": (1, "no such image")}, "no such image"),
    ({"docker compose up -d --no-build": lambda: next(UP_ONCE_FAILS)}, "port in use"),
    ({"docker compose exec": (1, "semgrep NOT AVAILABLE")}, "semgrep NOT AVAILABLE"),
])
def test_a_bad_switch_brings_the_previous_image_back(env, answers, why):
    global UP_ONCE_FAILS
    UP_ONCE_FAILS = iter([(1, "port in use"), (0, "ok")])
    run = FakeRun(answers)
    assert make(env, run).process(request()) is False
    st = status(env)
    assert st["step"] == "switching" and why in st["reason"]
    assert "previous image is back" in st["reason"]
    assert run.ran(f"docker tag {up.PREVIOUS} {up.IMAGE}")
    assert "TRIVY_VERSION" not in (env / ".env").read_text()


def test_a_rollback_that_fails_says_so_plainly(env):
    """Saying "the previous image is back" when it is not would send nobody
    to look at a service that is down."""
    make(env, http_ok=False).process(request())
    assert "ROLLBACK FAILED" in status(env)["reason"]
    assert "did not become healthy" in status(env)["reason"]
    run = FakeRun({f"docker tag {up.PREVIOUS}": (1, "gone"),
                   "docker compose exec": (1, "broken")})
    make(env, run).process(request())
    assert "ROLLBACK FAILED" in status(env)["reason"]


def test_anything_unexpected_while_switching_still_rolls_back(env):
    def boom():
        raise RuntimeError("daemon went away")
    run = FakeRun({"docker compose exec": boom})
    assert make(env, run).process(request()) is False
    st = status(env)
    assert "RuntimeError: daemon went away" in st["reason"]
    assert "previous image is back" in st["reason"]


def test_an_unexpected_error_elsewhere_is_reported_and_cleaned_up(env):
    (env / "Dockerfile").unlink()
    run = FakeRun()
    assert make(env, run).process(request()) is False
    st = status(env)
    assert st["phase"] == "failed" and st["step"] == "checking"
    assert "FileNotFoundError" in st["reason"]
    assert run.ran(f"docker rmi {up.CANDIDATE}")


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


def test_reports_survive_an_ops_dir_the_container_broke(env):
    """A directory named status.json makes every write fail. The upgrade must
    carry on (and finish) rather than stop half-way."""
    (env / "ops" / "status.json").mkdir()
    (env / "ops" / "update.log").mkdir()
    assert make(env).process(request()) is True
    assert "TRIVY_VERSION=0.75.0" in (env / ".env").read_text()


# ------------------------------------------------------------ recovery and main
def test_a_run_cut_short_is_reported_on_the_next_start(env):
    u = make(env)
    (env / "ops" / "status.json").write_text(json.dumps({"id": REQ_ID, "phase": "building"}))
    u.recover()
    st = status(env)
    assert st["phase"] == "failed" and st["step"] == "building"
    assert "nothing was switched" in st["reason"]
    (env / "ops" / "status.json").write_text(json.dumps({"id": REQ_ID, "phase": "switching"}))
    make(env).recover()
    assert "rollback-previous" in status(env)["reason"]
    for leftover in ("garbage", "[" * 100000, json.dumps({"phase": "done"})):
        (env / "ops" / "status.json").write_text(leftover)
        make(env).recover()
        assert (env / "ops" / "status.json").read_text() == leftover


def test_main_does_nothing_without_ops_or_a_request(env, tmp_path):
    lock = tmp_path / "lock"
    missing = make(env)
    missing.ops = tmp_path / "nowhere"
    assert up.main(missing, lock) == 0
    assert up.main(make(env), lock) == 0


def test_main_takes_the_request_once_and_reports_the_outcome(env, tmp_path):
    lock = tmp_path / "lock"
    (env / "ops" / "request.json").write_text(request().decode())
    (env / "ops" / "stray").write_text("x")
    assert up.main(make(env), lock) == 0
    assert not (env / "ops" / "request.json").exists(), "the request would run again"
    assert not (env / "ops" / "stray").exists(), "main did not tidy ops/"
    assert status(env)["phase"] == "done"
    (env / "ops" / "request.json").write_text(request(targets={"trivy": "9.9.9"}).decode())
    assert up.main(make(env), lock) == 1


def test_main_steps_aside_while_another_run_holds_the_lock(env, tmp_path):
    import fcntl
    lock = tmp_path / "lock"
    (env / "ops" / "request.json").write_text(request().decode())
    with open(lock, "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        assert up.main(make(env), lock) == 0
    assert (env / "ops" / "request.json").exists(), "a held lock still consumed the request"


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


@pytest.mark.skipif((ROOT / "ops").exists(), reason="a real ops/ here would be processed")
def test_the_script_runs_as_a_program():
    import runpy
    with pytest.raises(SystemExit) as exit_:
        runpy.run_path(str(ROOT / "scripts/sast_updater.py"), run_name="__main__")
    assert exit_.value.code == 0


def test_tidy_keeps_an_expected_file_it_may_not_chmod(env, monkeypatch):
    """ops/ is sticky when the app runs as another uid: its files cannot be
    chmod-ed by the host user. The request must survive that; strays go."""
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


def test_a_release_changed_during_the_download_is_refused(env):
    # First answer for the check, second for the look after the download.
    answers = iter(["2026-01-01T00:00:00Z", "2026-10-05T00:00:00Z"])

    def fetch(url):
        return [{"tag_name": "v0.75.0", "published_at": next(answers),
                 "draft": False, "prerelease": False}]
    run = FakeRun()
    u = make(env, run)
    u.fetch = fetch
    assert u.process(request()) is False
    st = status(env)
    assert st["step"] == "downloading" and "changed while it was being downloaded" in st["reason"]
    assert not run.ran("docker build")


def test_switched_but_unrecorded_versions_are_flagged(env):
    u = make(env)
    u.env_file = env / "missing-dir" / ".env"
    assert u.process(request()) is True
    st = status(env)
    assert st["phase"] == "done"
    assert "TRIVY_VERSION=0.75.0" in st["warning"] and "next deploy goes back" in st["warning"]
