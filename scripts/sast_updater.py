#!/usr/bin/env python3
"""Prepare scanner upgrades every morning; apply one when an admin says so.

Runs on the host, every minute, from cron, as the deployment's user. The web
app cannot rebuild its own image (that takes control of the Docker daemon,
and the rebuild replaces the app's own container); it can only ask, through
ops/, for one of two things: check now, or apply the prepared candidate.

Check (each day at SAST_UPGRADE_CHECK_AT in SAST_UPGRADE_TZ, default 08:00
Asia/Taipei, or when asked):
    every scanner's newest release that has been out for COOLDOWN_DAYS ->
    download, verified against the published checksums, checked again ->
    a candidate image, built while the service keeps running -> accepted
    only if every scanner starts, each finds what it must in a sample
    project, and it has no more CRITICAL vulnerabilities than the running
    image. Nothing new: nothing happens and nobody is told.

Apply (only a candidate this script built and accepted, by its id):
    wait for running scans -> switch -> healthy and scanners up, or the
    previous image comes back -> versions recorded in .env.

Each step is an event the web panel shows: downloading, ready,
download_failed, updating, updated, update_failed. A candidate nobody
applies is removed after CANDIDATE_DAYS.

ops/ is writable by the container, so everything read from it is untrusted:
size-limited, never followed through a link, validated field by field. What
this script must believe -- the candidate, the events -- lives in a file
the container cannot reach (STATE_FILE).

    python3 scripts/sast_updater.py           requests, schedule, expiry
    python3 scripts/sast_updater.py --check   check now
"""
from __future__ import annotations

import fcntl
import http.client
import importlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ROOT = Path(__file__).resolve().parents[1]
# The same release rules the web app shows, from the same file. It is
# standard-library only, so the host needs nothing installed to load it.
sys.path.insert(0, str(ROOT))
releases = importlib.import_module("app.releases")

OPS = ROOT / "ops"
ENV_FILE = ROOT / ".env"
LOCK_FILE = ROOT / ".updater.lock"
TMP = ROOT / ".updater-tmp"
STATE_FILE = ROOT / ".updater-state.json"     # host only: candidate, events

IMAGE = "sast-studio:latest"
CANDIDATE = "sast-studio:candidate"
PREVIOUS = "sast-studio:rollback-previous"
CACHE_VOLUME = "sast-selfcheck-cache"
HEALTH_PATH = "/api/health"

MIN_FREE_BYTES = 3 * 1024 ** 3
DRAIN_TIMEOUT = 60 * 60
DRAIN_POLL = 5
MAX_REQUEST = 8 * 1024
MAX_LOG = 1024 * 1024
CANDIDATE_DAYS = 14
#: A scheduled check that failed is tried again this many hours later.
RETRY_HOURS = 3
MAX_EVENTS = 50
DEFAULT_CHECK_AT = "08:00"
DEFAULT_TZ = "Asia/Taipei"
EVENTS = {"downloading", "ready", "download_failed", "updating", "updated", "update_failed"}

ID_RE = re.compile(r"^[0-9a-f]{16}$")
NAME_RE = re.compile(r"^[A-Za-z0-9._@-]{0,64}$")
BUSY = {"queued", "checking", "downloading", "building", "verifying",
        "waiting_for_scans", "switching"}
ACTIONS = {"check", "apply"}


class Failed(Exception):
    def __init__(self, step: str, reason: str):
        super().__init__(f"{step}: {reason}")
        self.step, self.reason = step, reason


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


#: The only programs this script starts. Everything it runs is built here
#: from constants and validated versions, never from the request's text.
PROGRAMS = {"docker", "bash"}


def _run(cmd: list[str], timeout: int, env: dict | None = None) -> tuple[int, str]:
    if not cmd or cmd[0] not in PROGRAMS:
        return 126, f"refusing to run {cmd[:1]}"
    try:
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              timeout=timeout, env={**os.environ, **(env or {})})
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except OSError as exc:
        return 127, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _http_ok(path: str) -> bool:
    """The local service answers `path` with 200."""
    conn = http.client.HTTPConnection("localhost", 8080, timeout=5)
    try:
        conn.request("GET", path)
        return conn.getresponse().status == 200
    except OSError:
        return False
    finally:
        conn.close()


def _free_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


# ------------------------------------------------------------- ops/ files
def read_untrusted(path: Path, limit: int) -> bytes:
    """Bytes of a regular file the container may have written, or b""."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return b""
    # Checked on the raw descriptor: a FIFO would block the read, a device is
    # not a file anyone wrote, and Python refuses to wrap a directory at all.
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return b""
    with os.fdopen(fd, "rb") as fh:
        return fh.read(limit + 1)


def write_replace(path: Path, text: str, mode: int = 0o644) -> None:
    # Rename over the name rather than open it: a link the container left
    # there is replaced, not written through. Created with its final mode, so
    # a private file is never readable even for a moment.
    tmp = path.parent / f".{path.name}.{secrets.token_hex(4)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
        # On the descriptor, not the name: the name is in a directory the
        # container can write, and could be a link by now.
        os.fchmod(fh.fileno(), mode)
    os.replace(tmp, path)


#: The only names that belong in ops/. Temporary files from the app's
#: write-then-rename (".<name>.<hex>.tmp") are tolerated while regular.
OPS_FILES = {"request.json", "status.json", "drain.json", "update.log"}


def tidy_ops(ops: Path) -> list[str]:
    """Remove anything in ops/ that is not one of its plain files.

    The container can create whatever it likes there: a directory or a FIFO
    named status.json would break every later run, and an executable left
    behind is owned on the host by the deployment's user -- setuid included.
    So only the expected regular files stay, and they lose any exec or setid
    bits. Returns what was removed.
    """
    removed = []
    for entry in os.scandir(ops):
        expected = entry.name in OPS_FILES or (
            entry.name.startswith(".") and entry.name.endswith(".tmp"))
        try:
            if expected and _strip_mode(entry.path):
                continue
            if entry.is_dir(follow_symlinks=False):
                shutil.rmtree(entry.path, ignore_errors=True)
            else:
                os.unlink(entry.path)
            removed.append(entry.name)
        except OSError:
            # Gone already (the container raced us), or not ours to touch.
            # Either way this run carries on; the next one looks again.
            continue
    return removed


def _strip_mode(path: str) -> bool:
    """Make a regular file 0644 through its descriptor. False if it is not a
    regular file. A file owned by someone else (ops/ is sticky when the app
    runs as another uid) cannot be chmod-ed; an expected one is kept anyway --
    it is read as data, never run -- and anything else is removed."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False
        try:
            os.fchmod(fd, 0o644)
        except PermissionError:
            pass
        return True
    finally:
        os.close(fd)


def _load(raw: bytes):
    """JSON from untrusted bytes, or None. Deep nesting raises RecursionError,
    which is not a ValueError, so both are caught."""
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        return None


def parse_request(raw: bytes) -> dict:
    """The request, or Failed. Every field is checked; nothing else is kept.

    Two actions only: "check", and "apply" with the id of a candidate. No
    versions: what to install is decided here, never by the request.
    """
    if not raw:
        raise Failed("checking", "no request")
    if len(raw) > MAX_REQUEST:
        raise Failed("checking", "request too large")
    data = _load(raw)
    if data is None:
        raise Failed("checking", "request is not JSON")
    if not isinstance(data, dict):
        raise Failed("checking", "request is not an object")
    req_id = data.get("id")
    who = data.get("requested_by", "")
    action = data.get("action")
    if not isinstance(req_id, str) or not ID_RE.match(req_id):
        raise Failed("checking", "bad request id")
    if not isinstance(who, str) or not NAME_RE.match(who):
        raise Failed("checking", "bad requester name")
    if not isinstance(action, str) or action not in ACTIONS:
        raise Failed("checking", "unknown action")
    out = {"id": req_id, "requested_by": who, "action": action}
    if action == "apply":
        cand = data.get("candidate")
        if not isinstance(cand, str) or not ID_RE.match(cand):
            raise Failed("checking", "bad candidate id")
        out["candidate"] = cand
    return out


def env_setting(text: str, key: str) -> str:
    """A plain KEY=value from .env, or ""."""
    for line in text.splitlines():
        k, _, v = line.strip().partition("=")
        if k.strip() == key:
            return v.strip()
    return ""


# ------------------------------------------------------------- versions
def dockerfile_versions(text: str) -> dict:
    """{tool: version} from the Dockerfile's ARG defaults (the repository's pins)."""
    out = {}
    for tool, arg in releases.BUILD_ARGS.items():
        match = re.search(rf"^ARG {arg}=([0-9.]+)$", text, re.M)
        if match:
            out[tool] = match.group(1)
    return out


def env_versions(text: str) -> dict:
    """{tool: version} overridden in .env by an earlier upgrade."""
    by_arg = {arg: tool for tool, arg in releases.BUILD_ARGS.items()}
    out = {}
    for line in text.splitlines():
        key, _, value = line.strip().partition("=")
        if key in by_arg and releases.VERSION_RE.match(value):
            out[by_arg[key]] = value
    return out


def update_env(text: str, versions: dict) -> str:
    """.env with each tool's version set, other lines untouched."""
    wanted = {releases.BUILD_ARGS[t]: v for t, v in versions.items()}
    lines = []
    for line in text.splitlines():
        key = line.partition("=")[0].strip()
        if key in wanted:
            line = f"{key}={wanted.pop(key)}"
        lines.append(line)
    lines += [f"{k}={v}" for k, v in sorted(wanted.items())]
    return "\n".join(lines) + "\n"


def count_critical(trivy_json: str) -> int:
    # The output mixes stdout and stderr; read the first JSON value and ignore
    # whatever trails it rather than failing on "extra data".
    data, _ = json.JSONDecoder().raw_decode(trivy_json[trivy_json.index("{"):])
    return sum(1 for r in data.get("Results") or []
               for v in r.get("Vulnerabilities") or []
               if v.get("Severity") == "CRITICAL")


# ------------------------------------------------------------- the run
class Updater:
    def __init__(self, run=_run, fetch=releases._fetch_json, sleep=time.sleep,
                 clock=time.monotonic, free_bytes=_free_bytes, http_ok=_http_ok,
                 ops: Path = OPS, env_file: Path = ENV_FILE, tmp: Path = TMP,
                 dockerfile: Path = ROOT / "Dockerfile", state_file: Path = STATE_FILE,
                 wallclock=lambda: datetime.now(timezone.utc)):
        self.run_cmd, self.fetch, self.sleep, self.clock = run, fetch, sleep, clock
        self.free_bytes, self.http_ok = free_bytes, http_ok
        self.ops, self.env_file, self.tmp, self.dockerfile = ops, env_file, tmp, dockerfile
        self.state_file, self.wallclock = state_file, wallclock
        self.status: dict = {}
        self.checked: dict = {}
        self.state: dict = self._load_state()

    # -- host-only state: the candidate and the events
    def _load_state(self) -> dict:
        try:
            data = json.loads(self.state_file.read_text("utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def save_state(self) -> bool:
        try:
            write_replace(self.state_file, json.dumps(self.state), mode=0o600)
        except OSError as exc:
            self.log(f"could not save {self.state_file.name}: {exc}")
            return False
        return True

    def stamp(self) -> str:
        """Now, by this run's clock (the one expiry and the schedule use)."""
        return self.wallclock().strftime("%Y-%m-%dT%H:%M:%SZ")

    def event(self, kind: str, **detail) -> None:
        events = self.state.setdefault("events", [])
        last = events[-1] if events and isinstance(events[-1], dict) else {}
        same = {k: v for k, v in last.items() if k not in ("at", "count")}
        if same == {"kind": kind, **detail}:
            # The same thing again (a request refused every minute): one
            # line with a count, not fifty that push the real news out.
            last.update(at=self.stamp(), count=int(last.get("count", 1)) + 1)
        else:
            events.append({"at": self.stamp(), "kind": kind, **detail})
        del events[:-MAX_EVENTS]
        self.save_state()
        self.log(f"event: {kind} {json.dumps(detail, sort_keys=True)}")

    def candidate(self) -> dict | None:
        """The candidate in the host state, if every field of it is sound."""
        cand = self.state.get("candidate")
        if not isinstance(cand, dict):
            return None
        targets, cid = cand.get("targets"), cand.get("id")
        sound = (isinstance(cid, str) and ID_RE.match(cid)
                 and isinstance(targets, dict) and targets
                 and all(t in releases.BUILD_ARGS and isinstance(v, str)
                         and releases.VERSION_RE.match(v) for t, v in targets.items())
                 and isinstance(cand.get("previous", {}), dict)
                 and _plus_days(cand.get("built_at"), 0) != ""
                 and all(isinstance(cand.get(k), str) and cand[k].startswith("sha256:")
                         for k in ("base", "image")))
        return cand if sound else None

    def drop_candidate(self) -> None:
        self.run_cmd(["docker", "rmi", CANDIDATE], 120, None)
        self.state.pop("candidate", None)
        self.save_state()

    # -- reporting
    # Reporting is best effort. ops/ is the container's to break (a directory
    # where status.json should be, a full disk), and a failed write must never
    # stop the upgrade half-way -- above all not between tagging and rollback.
    def log(self, text: str) -> None:
        path = self.ops / "update.log"
        old = read_untrusted(path, MAX_LOG).decode("utf-8", "replace")
        stamped = "".join(f"[{_now()}] {line}\n" for line in text.rstrip().splitlines())
        try:
            write_replace(path, (old + stamped)[-MAX_LOG:])
        except OSError:
            pass

    def report(self, phase: str, **extra) -> None:
        running = {"phase": phase, "action": self.status.get("action", "")} \
            if phase in BUSY else None
        if self.state.get("running") != running:
            # What recover() reads after a restart. Kept here, where the
            # container cannot write, never taken from status.json.
            if running is None:
                self.state.pop("running", None)
            else:
                self.state["running"] = running
            self.save_state()
        self.status.update(phase=phase, updated_at=_now(), **extra)
        self.status["overrides"] = self.overrides()
        # What the panel shows comes from the host's own state, written whole
        # each time: nothing the container put in status.json survives.
        cand = self.candidate()
        self.status["candidate"] = None if cand is None else {
            **cand, "expires_at": _plus_days(cand["built_at"], CANDIDATE_DAYS)}
        self.status["events"] = self.state.get("events", [])
        self.status["tools"] = self.state.get("tools", [])
        self.status["last_check"] = self.state.get("last_check", "")
        self.status["upstream_check"] = self.upstream_enabled()
        try:
            write_replace(self.ops / "status.json", json.dumps(self.status))
        except OSError:
            pass
        self.log(f"phase: {phase}")

    def overrides(self) -> dict:
        # Called while reporting a failure too, so it must not raise one.
        try:
            repo = dockerfile_versions(self.dockerfile.read_text("utf-8"))
        except OSError:
            repo = {}
        local = env_versions(self._env_text())
        return {t: {"repo": repo.get(t, ""), "local": v}
                for t, v in local.items() if v != repo.get(t)}

    def upstream_enabled(self) -> bool:
        """SAST_UPSTREAM_CHECK=false in .env turns every outside query off."""
        # Read as the app reads it (config._env_bool): unset is on.
        value = env_setting(self._env_text(), "SAST_UPSTREAM_CHECK").lower()
        return value == "" or value in ("1", "true", "yes", "on")

    def scheduled_due(self) -> bool:
        """Past today's check time, and today's check not yet done. Judged
        every minute, so a check missed while the host was off still runs."""
        text = self._env_text()
        try:
            zone = ZoneInfo(env_setting(text, "SAST_UPGRADE_TZ") or DEFAULT_TZ)
        except (ZoneInfoNotFoundError, ValueError):
            zone = ZoneInfo(DEFAULT_TZ)
        at = env_setting(text, "SAST_UPGRADE_CHECK_AT") or DEFAULT_CHECK_AT
        if not re.match(r"^([01][0-9]|2[0-3]):[0-5][0-9]$", at):
            at = DEFAULT_CHECK_AT
        local = self.wallclock().astimezone(zone)
        today = local.strftime("%Y-%m-%d")
        if local.strftime("%H:%M") < at:
            return False
        if self.state.get("last_scheduled") == today:
            retry = self.state.get("retry_at")
            if not isinstance(retry, str) or self.stamp() < retry:
                return False
        self.state["last_scheduled"] = today
        self.state.pop("retry_at", None)
        # Not saved, it would be due again next minute: skip rather than
        # ask GitHub every minute while the disk is full.
        return self.save_state()

    def image_id(self, ref: str) -> str:
        rc, out = self.run_cmd(["docker", "image", "inspect", "--format", "{{.Id}}", ref],
                               60, None)
        out = out.strip()
        return out if rc == 0 and re.match(r"^sha256:[0-9a-f]{64}$", out) else ""

    def _env_text(self) -> str:
        try:
            return self.env_file.read_text("utf-8")
        except OSError:
            return ""

    def sh(self, step: str, cmd: list[str], timeout: int, env: dict | None = None) -> str:
        self.log("$ " + " ".join(cmd))
        rc, out = self.run_cmd(cmd, timeout, env)
        self.log(out[-4000:] or "(no output)")
        if rc != 0:
            tail = " | ".join(out.strip().splitlines()[-3:]) or f"exit {rc}"
            raise Failed(step, tail[:300])
        return out

    # -- steps
    def current_versions(self) -> dict:
        versions = dockerfile_versions(self.dockerfile.read_text("utf-8"))
        versions.update(env_versions(self._env_text()))
        return versions

    def disk_ok(self) -> None:
        free = self.free_bytes(ROOT)
        if free < MIN_FREE_BYTES:
            raise Failed("checking", f"{free / 1024 ** 3:.1f} GB free; need 3 GB "
                         "(remove old images or grow the disk)")

    def recheck(self) -> None:
        """The same release, unchanged, after the download as before it.

        The check and the download are minutes apart. A file swapped into the
        release in between moves its "last changed" time, so asking again
        catches it -- instead of installing something nobody waited 7 days on.
        """
        for tool, (installed, version, when) in self.checked.items():
            row = releases.assess(tool, installed, fetch=self.fetch)
            if row["eligible"] != version or row["latest_published"] != when:
                raise Failed("downloading", f"{tool}: the release changed while it "
                             "was being downloaded; try again later")

    def build(self, versions: dict) -> None:
        args = {releases.BUILD_ARGS[t]: v for t, v in versions.items()}
        self.report("downloading")
        self.sh("downloading", ["bash", "scripts/fetch-vendor.sh", "--strict"], 1800, args)
        self.recheck()
        self.report("building")
        cmd = ["docker", "build", "-t", CANDIDATE]
        for key, value in sorted(args.items()):
            cmd += ["--build-arg", f"{key}={value}"]
        self.sh("building", cmd + ["."], 4 * 3600)

    def verify(self) -> None:
        self.report("verifying")
        self.sh("verifying", ["docker", "volume", "create", CACHE_VOLUME], 60)
        self.sh("verifying", ["docker", "run", "--rm", "--entrypoint", "python",
                              CANDIDATE, "-m", "app.selfcheck", "probe"], 600)
        self.sh("verifying", ["docker", "run", "--rm", "-e", "SAST_SEMGREP_RULES=p/default",
                              "-v", f"{CACHE_VOLUME}:/home/appuser/.cache",
                              "--entrypoint", "python", CANDIDATE,
                              "-m", "app.selfcheck", "sample"], 1800)
        new, old = self.criticals()
        self.status["critical"] = {"current": old, "candidate": new}
        if new > old:
            raise Failed("verifying", f"candidate has {new} CRITICAL vulnerabilities; "
                         f"the running image has {old}")

    def criticals(self) -> tuple[int, int]:
        """CRITICAL counts of candidate and current image, by the same Trivy.

        Each image's own Trivy could disagree just because it is a different
        version -- the very thing an upgrade changes. So the candidate's
        binary is copied out and run inside both, without the docker socket.
        """
        self.tmp.mkdir(exist_ok=True)
        name = f"sast-updater-{secrets.token_hex(4)}"
        self.sh("verifying", ["docker", "create", "--name", name, CANDIDATE], 120)
        try:
            self.sh("verifying", ["docker", "cp", f"{name}:/usr/local/bin/trivy",
                                  str(self.tmp / "trivy")], 300)
        finally:
            self.run_cmd(["docker", "rm", "-f", name], 60, None)
        counts = []
        try:
            for image in (CANDIDATE, IMAGE):
                out = self.sh("verifying", [
                    "docker", "run", "--rm", "--entrypoint", "/opt/t/trivy",
                    "-v", f"{self.tmp}:/opt/t:ro",
                    "-v", f"{CACHE_VOLUME}:/home/appuser/.cache", image,
                    "rootfs", "--quiet", "--scanners", "vuln", "--severity", "CRITICAL",
                    "--format", "json",
                    "--skip-dirs", "/proc,/sys,/dev,/opt/t,/home/appuser/.cache", "/"],
                    1800)
                try:
                    counts.append(count_critical(out))
                except ValueError:
                    raise Failed("verifying", "could not read Trivy's report") from None
        finally:
            # The binary is ~150 MB, on a disk that has run nearly full.
            shutil.rmtree(self.tmp, ignore_errors=True)
        return counts[0], counts[1]

    def wait_for_scans(self, req_id: str) -> None:
        self.report("waiting_for_scans")
        deadline = self.clock() + DRAIN_TIMEOUT
        while self.clock() < deadline:
            drain = _load(read_untrusted(self.ops / "drain.json", 4096) or b"{}")
            active = drain.get("active") if isinstance(drain, dict) else None
            # An int and nothing else: JSON false and 0.0 also compare equal to 0.
            if isinstance(drain, dict) and drain.get("id") == req_id \
                    and type(active) is int and active == 0:
                return
            self.sleep(DRAIN_POLL)
        raise Failed("waiting_for_scans", "scans still running after 60 minutes; "
                     "nothing was switched -- try again later")

    def switch(self, image: str) -> None:
        self.report("switching")
        stamp = format(int(time.time()), "x")
        self.sh("switching", ["docker", "tag", IMAGE, PREVIOUS], 60)
        self.sh("switching", ["docker", "tag", IMAGE, f"sast-studio:rollback-{stamp}"], 60)
        try:
            self.sh("switching", ["docker", "tag", image, IMAGE], 60)
            self.sh("switching", ["docker", "compose", "up", "-d", "--no-build"], 600)
            self.wait_healthy()
            self.sh("switching", ["docker", "compose", "exec", "-T", "sast-studio",
                                  "python", "-m", "app.selfcheck", "probe"], 600)
        except BaseException as exc:
            # Anything at all once latest may point at the candidate -- not
            # only a failed command -- puts the previous image back.
            why = exc.reason if isinstance(exc, Failed) else f"{type(exc).__name__}: {exc}"
            raise Failed("switching", f"{why} -- {self.roll_back()}") from None

    def roll_back(self) -> str:
        """Previous image back as latest and running. Says whether it worked."""
        tagged = self.run_cmd(["docker", "tag", PREVIOUS, IMAGE], 60, None)[0] == 0
        started = self.run_cmd(["docker", "compose", "up", "-d", "--no-build"],
                               600, None)[0] == 0
        if tagged and started:
            try:
                self.wait_healthy()
                return "the previous image is back"
            except Failed:
                pass
        return ("ROLLBACK FAILED: the service may be down; "
                "run ./scripts/deploy.sh --rollback on the host")

    def wait_healthy(self) -> None:
        for _ in range(60):
            if self.http_ok(HEALTH_PATH):
                return
            self.sleep(5)
        raise Failed("switching", "the new image did not become healthy")

    def finish(self, versions: dict) -> None:
        warning = ""
        try:
            write_replace(self.env_file, update_env(self._env_text(), versions), mode=0o600)
        except OSError as exc:
            # Already switched: the new versions are serving. Say plainly that
            # the next deploy.sh would quietly go back unless this is fixed.
            lines = ", ".join(f"{releases.BUILD_ARGS[t]}={v}" for t, v in sorted(versions.items()))
            warning = (f"switched, but could not record the versions in .env ({exc}); "
                       f"add {lines} to .env by hand or the next deploy goes back")
        self.run_cmd(["docker", "rmi", CANDIDATE], 120, None)
        # Same retention as deploy.sh: each switch leaves the old image behind.
        self.run_cmd(["bash", "scripts/prune-rollbacks.sh"], 300, None)
        self.status["warning"] = warning

    def run_check(self, trigger: str, req_id: str = "") -> bool:
        """Look for new versions; if there are, prepare and accept a candidate."""
        self.status = {"id": req_id, "action": "check", "trigger": trigger,
                       "started_at": _now()}
        if not self.upstream_enabled():
            self.report("idle", reason="SAST_UPSTREAM_CHECK=false: version checks are off")
            return True
        self.report("checking")
        current = self.current_versions()
        rows = [releases.assess(t, current.get(t, ""), fetch=self.fetch)
                for t in releases.SOURCES]
        self.state["tools"], self.state["last_check"] = rows, _now()
        self.save_state()
        targets = {r["tool"]: r["eligible"] for r in rows if r["eligible"]}
        base = self.image_id(IMAGE)
        cand = self.candidate()
        if cand is not None and cand["targets"] == targets and cand["base"] == base \
                and self.image_id(CANDIDATE) == cand["image"]:
            self.report("ready")                    # prepared already
            return True
        if "candidate" in self.state:
            # A newer set, a deploy since (the code it was built from is
            # gone), or an image that is not the one verified.
            self.drop_candidate()
        if not targets:
            self.report("idle")
            return True
        from_versions = {t: current.get(t, "") for t in targets}
        self.event("downloading", targets=targets, previous=from_versions)
        try:
            self.checked = {r["tool"]: (current.get(r["tool"], ""), r["eligible"],
                                        r["latest_published"]) for r in rows if r["eligible"]}
            self.disk_ok()
            self.build({**current, **targets})
            self.verify()
            image = self.image_id(CANDIDATE)
            if not base or not image:
                raise Failed("verifying", "could not read the image IDs")
        except Exception as exc:
            step, reason = (exc.step, exc.reason) if isinstance(exc, Failed) else \
                (self.status.get("phase", "checking"), f"{type(exc).__name__}: {exc}")
            self.drop_candidate()
            if trigger == "schedule":
                self.state["retry_at"] = (self.wallclock() + timedelta(hours=RETRY_HOURS)) \
                    .strftime("%Y-%m-%dT%H:%M:%SZ")
            self.event("download_failed", targets=targets, step=step, reason=reason)
            self.report("failed", step=step, reason=reason, finished_at=_now())
            return False
        self.state["candidate"] = {
            "id": secrets.token_hex(8), "targets": targets, "previous": from_versions,
            "built_at": self.stamp(), "critical": self.status.get("critical", {}),
            "base": base, "image": image}
        self.save_state()
        self.event("ready", targets=targets, previous=from_versions,
                   critical=self.status.get("critical", {}))
        self.report("ready", finished_at=_now())
        return True

    def run_apply(self, req: dict) -> bool:
        """Switch to the candidate this script built, if it is still good."""
        self.status = {"id": req["id"], "action": "apply",
                       "requested_by": req["requested_by"], "started_at": _now()}
        cand = self.candidate()
        why = ""
        if cand is None or cand["id"] != req["candidate"]:
            why = "that candidate does not exist (check again)"
        elif self._expired(cand):
            why = f"the candidate is older than {CANDIDATE_DAYS} days; check again"
        elif self.image_id(IMAGE) != cand["base"]:
            why = "the service was redeployed after the candidate was built; check again"
        elif self.image_id(CANDIDATE) != cand["image"]:
            why = "the candidate image is gone or not the one verified; check again"
        elif all(self.current_versions().get(t) == v for t, v in cand["targets"].items()):
            why = "these versions are already running"
        if why:
            if cand is not None and cand["id"] == req["candidate"]:
                self.drop_candidate()
            self.event("update_failed", step="checking", reason=why)
            self.report("failed", step="checking", reason=why, finished_at=_now())
            return False
        self.status["targets"] = cand["targets"]
        self.event("updating", targets=cand["targets"], previous=cand.get("previous", {}),
                   requested_by=req["requested_by"])
        try:
            self.wait_for_scans(req["id"])
            self.switch(cand["image"])
            self.finish(cand["targets"])
        except Exception as exc:
            step, reason = (exc.step, exc.reason) if isinstance(exc, Failed) else \
                (self.status.get("phase", "switching"), f"{type(exc).__name__}: {exc}")
            if step != "waiting_for_scans":
                self.drop_candidate()           # it failed live: do not offer it again
            self.event("update_failed", targets=cand["targets"], step=step, reason=reason)
            self.report("failed", step=step, reason=reason, finished_at=_now())
            return False
        self.state.pop("candidate", None)
        self.save_state()
        self.event("updated", targets=cand["targets"], previous=cand.get("previous", {}),
                   warning=self.status.get("warning", ""))
        self.report("done", finished_at=_now())
        return True

    def _expired(self, cand: dict) -> bool:
        try:
            built = datetime.fromisoformat(cand["built_at"].replace("Z", "+00:00"))
        except (KeyError, ValueError, AttributeError):
            return True
        return self.wallclock() - built > timedelta(days=CANDIDATE_DAYS)

    def expire(self) -> None:
        """A candidate nobody applied within CANDIDATE_DAYS is removed."""
        cand = self.candidate()
        if cand is not None and self._expired(cand):
            self.drop_candidate()
            self.event("expired", targets=cand["targets"], previous=cand.get("previous", {}))

    def process(self, raw: bytes) -> bool:
        try:
            req = parse_request(raw)
        except Exception as exc:
            step, reason = (exc.step, exc.reason) if isinstance(exc, Failed) else \
                ("checking", f"unreadable request ({type(exc).__name__})")
            self.status = {"id": "", "started_at": _now()}
            self.report("failed", step=step, reason=reason, finished_at=_now())
            return False
        flow = (lambda: self.run_check("request", req["id"])) if req["action"] == "check" \
            else (lambda: self.run_apply(req))
        try:
            return flow()
        except Exception as exc:
            # The flows report their own expected failures; this is a bug or
            # a broken host, and must still end in a failed phase, an event
            # and no half-built candidate -- not a crash every minute.
            reason = f"{type(exc).__name__}: {exc}"
            if req["action"] == "check":
                self.drop_candidate()
            self.event("download_failed" if req["action"] == "check" else "update_failed",
                       step=self.status.get("phase", "checking"), reason=reason)
            self.report("failed", step=self.status.get("phase", "checking"),
                        reason=reason, finished_at=_now())
            return False

    def recover(self) -> None:
        """A run that died part-way (a reboot) left its mark behind.

        The mark is in the host state. status.json is the container's to
        write, so nothing in it can start this -- or carry over.
        """
        running = self.state.get("running")
        phase = running.get("phase") if isinstance(running, dict) else None
        if isinstance(phase, str) and phase in BUSY:
            action = running.get("action")
            self.status = {"id": "", "action": action if isinstance(action, str)
                           and action in ACTIONS else "",
                           "started_at": _now()}
            reason = ("the updater stopped while switching (a restart?); check the "
                      "service -- the image it replaced is sast-studio:rollback-previous"
                      if phase == "switching" else
                      "the updater stopped part-way (a restart?); nothing was switched")
            applying = phase in ("waiting_for_scans", "switching")
            self.event("update_failed" if applying else "download_failed",
                       step=phase, reason=reason)
            self.report("failed", step=phase, reason=reason, finished_at=_now())


def _plus_days(stamp: str, days: int) -> str:
    try:
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return ""
    return (when + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(updater: Updater | None = None, lock_file: Path = LOCK_FILE,
         argv: list[str] | None = None) -> int:
    updater = updater or Updater()
    argv = sys.argv[1:] if argv is None else argv
    if not updater.ops.is_dir():
        return 0
    with open(lock_file, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0              # an upgrade (or deploy.sh) is already running
        for step in (lambda: tidy_ops(updater.ops), updater.recover, updater.expire):
            try:
                step()
            except Exception as exc:          # logged; the request still runs
                updater.log(f"housekeeping failed: {type(exc).__name__}: {exc}")
        if "--check" in argv:
            return 0 if updater.run_check("manual") else 1
        request = updater.ops / "request.json"
        raw = read_untrusted(request, MAX_REQUEST)
        if raw:
            request.unlink(missing_ok=True)
            return 0 if updater.process(raw) else 1
        if updater.scheduled_due():
            return 0 if updater.run_check("schedule") else 1
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
