"""Operator actions: update the scanners, restart the app.

These run commands on the server, so the module keeps them narrow on purpose:
every command is a fixed argument list (never a shell string, never anything
taken from the request), only one job may run at a time, and the output is
capped before it is handed back to the UI.

There is no authentication in front of these endpoints. That is a deliberate
project decision (CoreMain: no account system), which means anyone who can
reach the page can trigger them. Keep this deployment on a trusted network.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from .adapters import ADAPTERS
from .config import config

# How much command output to keep. Updates are chatty and the UI only needs
# enough to see what happened.
MAX_LOG_CHARS = 20_000
UPDATE_TIMEOUT = 1800  # installing several scanners over a slow link is slow


class _JobState:
    """The single in-flight operator job, guarded by a lock.

    One at a time: two concurrent pip/npm installs would fight over the same
    files, and the UI has no way to show two progress streams anyway.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running = False
        self.kind = ""
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None
        self.ok: Optional[bool] = None
        self.log = ""
        self.tools: list[str] = []
        # Per-tool result of the last update, so the panel can say whether a
        # restart is actually needed rather than making the user read the log.
        self.outcomes: dict[str, str] = {}

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "running": self.running,
                "kind": self.kind,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "ok": self.ok,
                "log": self.log[-MAX_LOG_CHARS:],
                "tools": list(self.tools),
                "outcomes": dict(self.outcomes),
                "restart_required": any(v == "upgraded"
                                        for v in self.outcomes.values()),
            }


state = _JobState()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# /api/admin/status sits behind no login, so anything in this log is readable
# by anyone who can reach the page. Package managers are chatty about their
# surroundings, so scrub on the way in rather than hoping nobody looks.
_SCRUB = (
    # credentials embedded in an index or proxy URL
    (re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1***:***@"),
    # Authorization: <scheme> <credential>  /  bare "Bearer <token>"
    (re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic|token|digest)?"
                r"|\bbearer)\s+\S+"), r"\1 ***"),
    # netrc style, where the value is separated by a space rather than = or :
    (re.compile(r"(?i)\b(password|passwd)\s+\S+"), r"\1 ***"),
    # token/secret/password/api-key in a KEY=value or KEY: value pair
    (re.compile(r"(?i)\b([\w-]*(?:token|secret|password|api[_-]?key)[\w-]*)\s*[=:]\s*\S+"),
     r"\1=***"),
    # absolute container paths expose the image layout; keep the tail only
    (re.compile(r"/(?:home|root|opt|etc|var|data|srv)/[^\s'\")]+"), "<path>"),
    (re.compile(r"/usr/local/(?:bin|lib|share)/[^\s'\")]+"), "<path>"),
    (re.compile(r"/tmp/[^\s'\")]+"), "<path>"),
)


def _scrub(text: str) -> str:
    for pattern, repl in _SCRUB:
        text = pattern.sub(repl, text)
    return text


def _collapse_progress(text: str) -> str:
    """Keep only the final state of each progress bar.

    Downloaders redraw a bar by returning to the start of the line with a
    carriage return. Stored as plain text every redraw survives, so one
    114 MB download leaves dozens of near-identical lines. Keeping the last
    segment of each line is what a terminal would have shown anyway.
    """
    if "\r" not in text:
        return text
    return "\n".join(line.split("\r")[-1] for line in text.split("\n"))


def _append(text: str) -> None:
    with state.lock:
        state.log = (state.log + _scrub(_collapse_progress(text)))[-MAX_LOG_CHARS:]


# --------------------------------------------------------------- update tools

def _update_commands(tools: list[str]) -> list[tuple[str, list[str]]]:
    """Build the update command for each requested tool.

    Only tools we integrate can be named, and each maps to a fixed argument
    list, so a request cannot introduce a command of its own.
    """
    cmds: list[tuple[str, list[str]]] = []
    for name in tools:
        if name == "semgrep":
            cmds.append((name, ["python", "-m", "pip", "install", "--no-cache-dir",
                                "--upgrade", "semgrep"]))
        elif name == "trivy" and shutil.which("trivy"):
            # Trivy ships its own database updater; refreshing it is the part
            # that actually matters between releases.
            cmds.append((name, ["trivy", "image", "--download-db-only"]))
        # npm is deliberately not updated here: the image runs as a non-root
        # user so "npm install -g" always fails on /usr/local/lib, and npm
        # audit reads its advisories from the registry, not from local npm.
        # bearer, gitleaks, npm_audit and osv-scanner are pinned in the
        # image: updating them means rebuilding, not installing in place.
    return cmds


def updatable_tools() -> list[dict]:
    """Which tools can be updated from here, and which need an image rebuild."""
    out = []
    for adapter in ADAPTERS:
        name = adapter.name
        in_place = bool(_update_commands([name]))
        out.append({
            "name": name,
            "in_place": in_place,
            "note": "" if in_place else "pinned binary — rebuild the image to change its version",
        })
    return out


def _run_update(tools: list[str]) -> None:
    """Run the updates, then always release the job slot.

    Without the finally, an unexpected error would leave running=True and
    every later update *and* restart would be refused - including the
    restart that would clear it.
    """
    try:
        _run_updates(tools)
    except Exception as exc:  # noqa: BLE001
        _mark_failed()
        _append("\nupdate aborted: {}\n".format(exc))
    finally:
        with state.lock:
            state.running = False
            state.kind = ""
            state.finished_at = _now()
            if state.ok is None:
                state.ok = True


def _mark_failed() -> None:
    with state.lock:
        state.ok = False


def _classify(name: str, output: str) -> str:
    """What actually happened, so the UI can say whether a restart is needed.

    Reading this off the output is the only option: pip and trivy both exit 0
    whether or not they changed anything, and leaving the user to spot
    "Successfully installed" in a few hundred lines of pip chatter is how you
    get people restarting for no reason, or not restarting when it matters.
    """
    if "Successfully installed" in output:
        return "upgraded"        # new code on disk; the process must reload it
    if "Artifact successfully downloaded" in output or "Downloading vulnerability DB" in output:
        return "data_updated"    # read per scan, so no restart needed
    if "already satisfied" in output or "DB is the latest" in output:
        return "already_current"
    return "unknown"


def _run_updates(tools: list[str]) -> None:
    """Run each command, recording a failure without skipping the rest."""
    for name, cmd in _update_commands(tools):
        _append(f"\n$ {' '.join(cmd)}\n")
        outcome = "failed"
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False
                cmd, capture_output=True, text=True,
                timeout=UPDATE_TIMEOUT, shell=False,
            )
            combined = (proc.stdout or "") + (proc.stderr or "")
            _append(combined)
            if proc.returncode != 0:
                _mark_failed()
                _append(f"\n[{name}] exited with {proc.returncode}\n")
            else:
                outcome = _classify(name, combined)
        except subprocess.TimeoutExpired:
            _mark_failed()
            _append(f"\n[{name}] timed out after {UPDATE_TIMEOUT}s\n")
        except Exception as exc:  # noqa: BLE001 - surface, never crash the worker
            _mark_failed()
            _append(f"\n[{name}] failed: {exc}\n")
        with state.lock:
            state.outcomes[name] = outcome


def start_update(tools: list[str]) -> dict:
    """Begin an update in the background. Returns the new state."""
    known = {a.name for a in ADAPTERS}
    wanted = [t for t in tools if t in known] or sorted(known)
    if not _update_commands(wanted):
        return {"started": False,
                "reason": "none of the selected tools can be updated in place"}

    with state.lock:
        if state.running:
            return {"started": False, "reason": "an operator job is already running"}
        state.running = True
        state.kind = "update"
        state.started_at = _now()
        state.finished_at = None
        state.ok = None
        state.log = ""
        state.tools = wanted
        state.outcomes = {}

    threading.Thread(target=_run_update, args=(wanted,), daemon=True).start()
    return {"started": True}


# ------------------------------------------------------------------- restart

# Two restarts in quick succession do nothing useful and, with the container's
# restart policy, can keep the service bouncing. Nothing here authenticates the
# caller, so the limit is on the action rather than on who asked for it.
RESTART_MIN_INTERVAL = 60.0

# The marker has to outlive the process: an in-memory timestamp is erased by
# the very restart it is meant to rate-limit, so every request would look like
# the first one. It lives on the workspace volume, which survives a restart.
RESTART_MARKER = Path(config.WORKSPACE_DIR) / ".last-restart"


def _last_restart_age() -> Optional[float]:
    """Seconds since the last restart was requested, or None if unknown."""
    try:
        return max(0.0, time.time() - RESTART_MARKER.stat().st_mtime)
    except OSError:
        return None


def _mark_restart() -> None:
    try:
        RESTART_MARKER.parent.mkdir(parents=True, exist_ok=True)
        RESTART_MARKER.write_text(_now(), encoding="utf-8")
    except OSError:
        # A read-only or missing volume only costs us the throttle, so carry on
        # rather than refusing to restart at all.
        pass

# How long to wait for SIGTERM to actually end the process before deciding it
# did not work and handing the panel back to the operator.
RESTART_GRACE = 15.0


def restart_app(delay: float = 0.5) -> dict:
    """Restart the application process.

    The reply has to reach the browser before the process goes away, so the
    signal is sent from a short-lived timer rather than inline. Uvicorn exits
    on SIGTERM and the container's restart policy brings it back; in-memory
    scan history is lost, which the UI warns about.
    """
    # Claim the restart inside the lock. Doing it after releasing would leave a
    # window where an update could start and then be killed mid-install.
    with state.lock:
        if state.running:
            return {"restarting": False,
                    "reason": "an operator job is running; wait for it to finish"}
        age = _last_restart_age()
        if age is not None and age < RESTART_MIN_INTERVAL:
            return {"restarting": False,
                    "reason": f"a restart was requested {int(age)}s ago; "
                              f"wait {int(RESTART_MIN_INTERVAL - age)}s"}
        state.running = True
        state.kind = "restart"
        state.started_at = _now()
        state.finished_at = None
        state.ok = None
        _mark_restart()

    def _stop() -> None:
        time.sleep(delay)
        os.kill(os.getpid(), signal.SIGTERM)
        # Normally the process is gone here and nothing below runs. If SIGTERM
        # does not take -- a graceful shutdown waiting on an in-flight request,
        # or no restart policy to bring us back -- the claimed job slot would
        # stay claimed forever and lock the panel out of both updating and
        # restarting, with no way back in. So give it a grace period and then
        # release the slot, leaving a note about what happened.
        time.sleep(RESTART_GRACE)
        with state.lock:
            state.running = False
            state.kind = ""
            state.ok = False
            state.finished_at = _now()
        _append("\nrestart signal did not take effect after "
                "{:.0f}s; the service is still running\n".format(RESTART_GRACE))

    threading.Thread(target=_stop, daemon=True).start()
    return {"restarting": True, "delay_seconds": delay}


def status() -> dict:
    """Everything the Monitor tab needs to render the operator panel."""
    snap = state.snapshot()
    snap["tools_available"] = updatable_tools()
    snap["restart_note"] = "restarting clears scan history (jobs are kept in memory)"
    return snap
