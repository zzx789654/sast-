"""The web side of a scanner upgrade.

This process cannot rebuild its own image: that needs control of the Docker
daemon, which is control of the host, and the rebuild ends by replacing this
very container. So it only asks. scripts/sast_updater.py, on the host,
prepares a candidate every morning on its own; from here an administrator
can only ask it to check now, or to apply the candidate it prepared. No
versions are chosen here.

Files in OPS_DIR (the only things either side reads or writes there):
    request.json  written here: "check", or "apply" a candidate id; who asked
    status.json   written by the host: phase, per-step results, overrides
    drain.json    written here: how many scans are still running
    update.log    written by the host: the tail of what it ran

While the host waits to switch images, this side stops taking new scans and
reports how many are still running, so the switch never cuts one off.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
import threading
from datetime import datetime, timezone

from .config import config

REQUEST, STATUS, DRAIN, LOG = "request.json", "status.json", "drain.json", "update.log"
MAX_READ = 64 * 1024
LOG_TAIL = 16 * 1024

#: Phases in which an upgrade is under way and another must not start.
BUSY = {"queued", "checking", "downloading", "building", "verifying",
        "waiting_for_scans", "switching"}
#: Phases in which no new scan may start.
DRAIN_PHASES = {"waiting_for_scans", "switching"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def enabled() -> bool:
    return config.OPS_DIR is not None and config.OPS_DIR.is_dir()


def _read(name: str, limit: int = MAX_READ, tail: bool = False) -> bytes:
    """A file in OPS_DIR, never following a link, at most `limit` bytes."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(config.OPS_DIR / name, flags)
    except OSError:
        return b""
    # On the raw descriptor: a FIFO would hang this thread on the read, and
    # Python refuses to wrap a directory at all.
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return b""
    with os.fdopen(fd, "rb") as fh:
        if tail:
            size = os.fstat(fh.fileno()).st_size
            fh.seek(max(0, size - limit))
        return fh.read(limit)


def _read_json(name: str) -> dict:
    try:
        data = json.loads(_read(name) or b"{}")
    except (ValueError, RecursionError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(name: str, data: dict) -> None:
    # Write beside it and rename over it: the rename replaces whatever is at
    # the name, even a link, instead of writing through it.
    tmp = config.OPS_DIR / f".{name}.{secrets.token_hex(4)}.tmp"
    tmp.write_text(json.dumps(data), "utf-8")
    os.replace(tmp, config.OPS_DIR / name)


def status() -> dict:
    if not enabled():
        return {"enabled": False}
    return {
        "enabled": True,
        "upstream_check": config.UPSTREAM_CHECK,
        "pending": bool(_read(REQUEST)),
        "status": _read_json(STATUS),
        "log": _read(LOG, LOG_TAIL, tail=True).decode("utf-8", "replace"),
    }


def _refusal() -> "str | None":
    if not enabled():
        return "upgrades are not set up on this host"
    if _read_json(STATUS).get("phase") in BUSY or _read(REQUEST):
        return "the updater is busy; try again when it finishes"
    return None


def _ask(action: str, requested_by: str, **extra) -> dict:
    request = {"id": secrets.token_hex(8), "requested_by": requested_by,
               "requested_at": _now(), "action": action, **extra}
    _write_json(REQUEST, request)
    return {"started": True, "id": request["id"]}


def request_check(requested_by: str) -> dict:
    """Ask the host to check for new versions now (the 08:00 check, early)."""
    why = _refusal()
    if why is None and not config.UPSTREAM_CHECK:
        why = "version checks are off (SAST_UPSTREAM_CHECK=false)"
    if why:
        return {"started": False, "reason": why}
    return _ask("check", requested_by)


def request_apply(candidate_id: str, requested_by: str) -> dict:
    """Ask the host to switch to the candidate it prepared and accepted.

    The id must be the one the panel shows now -- what the administrator
    saw. The host checks it against its own record again, so this is the
    first of two gates.
    """
    why = _refusal()
    cand = (_read_json(STATUS).get("candidate") or {}) if why is None else {}
    if why is None and (not isinstance(cand, dict) or cand.get("id") != candidate_id):
        why = "that update is no longer on offer; reload the panel"
    if why:
        return {"started": False, "reason": why}
    return _ask("apply", requested_by, candidate=candidate_id)


def sync_drain(manager) -> bool:
    """Follow the host: stop new scans while it waits to switch, and say how
    many are still running. Returns whether this side is draining."""
    current = _read_json(STATUS)
    draining = current.get("phase") in DRAIN_PHASES
    manager.set_draining(draining)
    if draining:
        _write_json(DRAIN, {"id": current.get("id", ""),
                            "active": manager.active_count(), "at": _now()})
    return draining


_stop = threading.Event()


def start_watcher(manager, interval: float = 3.0) -> bool:
    if not enabled():
        return False
    _stop.clear()

    def loop() -> None:
        while not _stop.wait(interval):
            try:
                sync_drain(manager)
            except OSError:
                # A full disk or a vanished directory: try again next tick.
                continue

    threading.Thread(target=loop, name="upgrade-watch", daemon=True).start()
    return True


def stop_watcher() -> None:
    _stop.set()
