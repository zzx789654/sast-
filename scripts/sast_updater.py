#!/usr/bin/env python3
"""Upgrade scanners when the web panel asks for it. Runs on the host.

The web app cannot rebuild its own image (that takes control of the Docker
daemon, and the rebuild replaces the app's own container), so it writes a
request into ops/ and this script, started every minute by cron as the
deployment's user, does the work:

    checking           the request is well formed; each version is still the
                       newest release and has been out for COOLDOWN_DAYS --
                       checked again here, not taken from the request
    downloading        scanner binaries into vendor/, verified against the
                       checksums each project publishes
    building           a candidate image; the running service is untouched
    verifying          every scanner starts; on a small sample project each
                       finds what it must; the image has no more CRITICAL
                       vulnerabilities than the one it would replace
    waiting_for_scans  the app stops taking scans; wait for running ones
    switching          candidate becomes latest; healthy and scanners up, or
                       the previous image comes back
    done / failed      versions recorded in .env, which deploy.sh keeps

ops/ is writable by the container, so everything read from it is untrusted:
size-limited, never followed through a link, and validated field by field.

    python3 scripts/sast_updater.py      process a pending request, if any
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
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The same release rules the web app shows, from the same file. It is
# standard-library only, so the host needs nothing installed to load it.
sys.path.insert(0, str(ROOT))
releases = importlib.import_module("app.releases")

OPS = ROOT / "ops"
ENV_FILE = ROOT / ".env"
LOCK_FILE = ROOT / ".updater.lock"
TMP = ROOT / ".updater-tmp"

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

ID_RE = re.compile(r"^[0-9a-f]{16}$")
NAME_RE = re.compile(r"^[A-Za-z0-9._@-]{0,64}$")
BUSY = {"queued", "checking", "downloading", "building", "verifying",
        "waiting_for_scans", "switching"}


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
    """The request, or Failed. Every field is checked; nothing else is kept."""
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
    targets = data.get("targets")
    if not isinstance(req_id, str) or not ID_RE.match(req_id):
        raise Failed("checking", "bad request id")
    if not isinstance(who, str) or not NAME_RE.match(who):
        raise Failed("checking", "bad requester name")
    if not isinstance(targets, dict) or not 1 <= len(targets) <= len(releases.SOURCES):
        raise Failed("checking", "bad target list")
    for tool, version in targets.items():
        if tool not in releases.SOURCES:
            raise Failed("checking", f"cannot upgrade {tool!r}")
        if not isinstance(version, str) or not releases.VERSION_RE.match(version):
            raise Failed("checking", f"bad version for {tool}")
    return {"id": req_id, "requested_by": who, "targets": dict(sorted(targets.items()))}


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
                 dockerfile: Path = ROOT / "Dockerfile"):
        self.run_cmd, self.fetch, self.sleep, self.clock = run, fetch, sleep, clock
        self.free_bytes, self.http_ok = free_bytes, http_ok
        self.ops, self.env_file, self.tmp, self.dockerfile = ops, env_file, tmp, dockerfile
        self.status: dict = {}
        self.checked: dict = {}

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
        self.status.update(phase=phase, updated_at=_now(), **extra)
        self.status["overrides"] = self.overrides()
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

    def check(self, req: dict) -> dict:
        current = self.current_versions()
        self.checked = {}
        for tool, version in req["targets"].items():
            row = releases.assess(tool, current.get(tool, ""), fetch=self.fetch)
            if row["eligible"] != version:
                raise Failed("checking", f"{tool} {version}: "
                             f"{row['reason'] or 'not the version on offer'}")
            self.checked[tool] = (current.get(tool, ""), version, row["latest_published"])
        free = self.free_bytes(ROOT)
        if free < MIN_FREE_BYTES:
            raise Failed("checking", f"{free / 1024 ** 3:.1f} GB free; need 3 GB "
                         "(remove old images or grow the disk)")
        return {**current, **req["targets"]}

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

    def switch(self) -> None:
        self.report("switching")
        stamp = format(int(time.time()), "x")
        self.sh("switching", ["docker", "tag", IMAGE, PREVIOUS], 60)
        self.sh("switching", ["docker", "tag", IMAGE, f"sast-studio:rollback-{stamp}"], 60)
        try:
            self.sh("switching", ["docker", "tag", CANDIDATE, IMAGE], 60)
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
        self.report("done", finished_at=_now(), warning=warning)

    def process(self, raw: bytes) -> bool:
        try:
            req = parse_request(raw)
        except Failed as exc:
            self.status = {"id": "", "started_at": _now()}
            self.report("failed", step=exc.step, reason=exc.reason, finished_at=_now())
            return False
        self.status = {"id": req["id"], "requested_by": req["requested_by"],
                       "targets": req["targets"], "started_at": _now()}
        try:
            self.report("checking")
            versions = self.check(req)
            self.build(versions)
            self.verify()
            self.wait_for_scans(req["id"])
            self.switch()
            self.finish({t: versions[t] for t in req["targets"]})
            return True
        except Exception as exc:
            # Failed is the expected way out; anything else is a bug or a
            # broken host, and still must not leave a candidate or a busy
            # phase behind. (switch() has already rolled back by now.)
            step, reason = (exc.step, exc.reason) if isinstance(exc, Failed) else \
                (self.status.get("phase", "checking"), f"{type(exc).__name__}: {exc}")
            self.run_cmd(["docker", "rmi", CANDIDATE], 120, None)
            self.report("failed", step=step, reason=reason, finished_at=_now())
            return False

    def recover(self) -> None:
        """A run that died part-way (a reboot) left a busy phase behind."""
        last = _load(read_untrusted(self.ops / "status.json", 64 * 1024) or b"{}")
        if isinstance(last, dict) and last.get("phase") in BUSY:
            phase = last.get("phase")
            self.status = last
            reason = ("the updater stopped while switching (a restart?); check the "
                      "service -- the image it replaced is sast-studio:rollback-previous"
                      if phase == "switching" else
                      "the updater stopped part-way (a restart?); nothing was switched")
            self.report("failed", step=phase, reason=reason, finished_at=_now())


def main(updater: Updater | None = None, lock_file: Path = LOCK_FILE) -> int:
    updater = updater or Updater()
    if not updater.ops.is_dir():
        return 0
    with open(lock_file, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0              # an upgrade (or deploy.sh) is already running
        tidy_ops(updater.ops)
        updater.recover()
        request = updater.ops / "request.json"
        raw = read_untrusted(request, MAX_REQUEST)
        if not raw:
            return 0
        request.unlink(missing_ok=True)
        return 0 if updater.process(raw) else 1


if __name__ == "__main__":
    raise SystemExit(main())
