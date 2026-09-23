"""The activity log: one table for everything worth looking back at.

Five kinds of thing end up here -- scans, logins, service state, docker state
and API/MCP calls -- because the questions people actually ask cross all of
them. "What happened around the time it went down?" is unanswerable if the
restart is in one place and the scans that preceded it in another.

Retention is by age, not by row count. A rolling window of 500 rows sounds
bounded until a busy afternoon of API calls pushes out last week's failed
logins, which is exactly the record you wanted to keep. Days are also what a
retention policy is actually written in.

Stored in the same SQLite file as accounts, on the same volume, so the log
survives a rebuild along with the users it describes.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from . import accounts

#: The five categories. The UI builds its filter from this, so adding one here
#: is enough -- there is no second list to keep in step.
CATEGORIES = ("scan", "auth", "service", "docker", "api")

#: How a row is judged at a glance. Deliberately small: anything finer turns
#: into a taxonomy nobody maintains.
LEVELS = ("info", "warn", "error")

_RETENTION_KEY = "log_retention_days"
DEFAULT_RETENTION_DAYS = 30
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 3650

#: An upper bound that exists only so a runaway caller cannot fill the disk
#: before the age-based sweep next runs. Not the retention policy.
HARD_ROW_CAP = 200_000

_lock = threading.Lock()
_sweep_lock = threading.Lock()
_last_sweep: Optional[float] = None


def _connect() -> sqlite3.Connection:
    return accounts._connect()  # noqa: SLF001 - one database, one connector


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init() -> None:
    """Create the table. Safe to call repeatedly."""
    with _lock, _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                at       TEXT    NOT NULL,
                category TEXT    NOT NULL,
                action   TEXT    NOT NULL,
                level    TEXT    NOT NULL DEFAULT 'info',
                actor    TEXT    NOT NULL DEFAULT '',
                source   TEXT    NOT NULL DEFAULT '',
                target   TEXT    NOT NULL DEFAULT '',
                detail   TEXT    NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_events_at ON events(at);
            CREATE INDEX IF NOT EXISTS idx_events_cat ON events(category, at);
            """
        )


def retention_days() -> int:
    with _connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?",
                           (_RETENTION_KEY,)).fetchone()
    if not row:
        return DEFAULT_RETENTION_DAYS
    try:
        days = int(row["value"])
    except (TypeError, ValueError):
        return DEFAULT_RETENTION_DAYS
    return max(MIN_RETENTION_DAYS, min(days, MAX_RETENTION_DAYS))


def set_retention_days(days: int) -> int:
    """Set how many days of log to keep, and apply it immediately.

    Applying it here rather than on the next sweep is the point: someone who
    lowers this has usually just decided the older rows should not be sitting
    on disk, and "it will take effect eventually" is not that.
    """
    try:
        value = int(days)
    except (TypeError, ValueError) as exc:
        raise ValueError("retention must be a number of days") from exc
    if not MIN_RETENTION_DAYS <= value <= MAX_RETENTION_DAYS:
        raise ValueError(
            f"retention must be between {MIN_RETENTION_DAYS} and "
            f"{MAX_RETENTION_DAYS} days")
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (_RETENTION_KEY, str(value)))
    purge(value)
    return value


def purge(days: Optional[int] = None) -> int:
    """Delete anything older than the retention window. Returns rows removed."""
    keep = retention_days() if days is None else days
    cutoff = (datetime.now(timezone.utc) - timedelta(days=keep)).isoformat()
    with _lock, _connect() as conn:
        removed = conn.execute(
            "DELETE FROM events WHERE at < ?", (cutoff,)).rowcount or 0
        # The cap is a backstop for a burst inside the window, not the policy.
        removed += conn.execute(
            "DELETE FROM events WHERE id NOT IN "
            "(SELECT id FROM events ORDER BY id DESC LIMIT ?)",
            (HARD_ROW_CAP,)).rowcount or 0
    return removed


def _maybe_sweep() -> None:
    """Purge at most once an hour, off the back of ordinary writes.

    No scheduler: a background thread is another thing to start, supervise and
    shut down cleanly, and this log only grows when something writes to it.
    """
    global _last_sweep
    import time
    now = time.time()
    with _sweep_lock:
        if _last_sweep is not None and now - _last_sweep < 3600:
            return
        _last_sweep = now
    try:
        purge()
    except Exception:  # noqa: BLE001 - logging must never break the caller
        pass


def record(category: str, action: str, *, level: str = "info",
           actor: str = "", source: str = "", target: str = "",
           detail: object = "") -> None:
    """Write one row. Never raises: a failure to log is not a failure to work.

    That is a deliberate asymmetry. Losing a log line is a gap in the record;
    letting the write throw would turn it into a failed scan or a refused
    login, which is a far worse outcome for the person using this.
    """
    try:
        if category not in CATEGORIES:
            category = "api"
        if level not in LEVELS:
            level = "info"
        if not isinstance(detail, str):
            try:
                detail = json.dumps(detail, ensure_ascii=False, default=str)
            except (TypeError, ValueError):
                detail = str(detail)
        with _lock, _connect() as conn:
            conn.execute(
                "INSERT INTO events (at, category, action, level, actor, "
                "source, target, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (_now(), category, str(action)[:64], level,
                 str(actor or "")[:64], str(source or "")[:64],
                 str(target or "")[:256], str(detail or "")[:1024]))
    except Exception:  # noqa: BLE001
        return
    _maybe_sweep()


def query(*, categories: Optional[list[str]] = None,
          level: str = "", actor: str = "", text: str = "",
          since: str = "", limit: int = 200, offset: int = 0) -> dict:
    """Filtered slice of the log, newest first, with the total that matched.

    The total is separate from the returned rows so the UI can say "showing
    200 of 4,312" rather than implying the filter found exactly a pageful.
    """
    where: list[str] = []
    args: list = []

    wanted = [c for c in (categories or []) if c in CATEGORIES]
    if wanted:
        where.append("category IN (%s)" % ",".join("?" * len(wanted)))
        args.extend(wanted)
    if level in LEVELS:
        where.append("level = ?")
        args.append(level)
    if actor:
        where.append("actor = ?")
        args.append(actor[:64])
    if since:
        where.append("at >= ?")
        args.append(since[:40])
    if text:
        # A parameterised LIKE, with the wildcards in the value rather than
        # the SQL, so the pattern cannot escape into the statement.
        like = f"%{text[:120]}%"
        where.append("(action LIKE ? OR target LIKE ? OR detail LIKE ? "
                     "OR actor LIKE ? OR source LIKE ?)")
        args.extend([like] * 5)

    clause = (" WHERE " + " AND ".join(where)) if where else ""
    limit = max(1, min(int(limit or 200), 1000))
    offset = max(0, int(offset or 0))

    with _connect() as conn:
        total = conn.execute(
            "SELECT COUNT(*) AS n FROM events" + clause, args).fetchone()["n"]
        rows = conn.execute(
            "SELECT at, category, action, level, actor, source, target, detail "
            "FROM events" + clause + " ORDER BY id DESC LIMIT ? OFFSET ?",
            args + [limit, offset]).fetchall()

    return {
        "events": [dict(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "categories": list(CATEGORIES),
        "levels": list(LEVELS),
        "retention_days": retention_days(),
    }


def counts_by_category() -> dict:
    """Row counts per category, for the filter chips."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT category, COUNT(*) AS n FROM events GROUP BY category"
        ).fetchall()
    return {r["category"]: r["n"] for r in rows}
