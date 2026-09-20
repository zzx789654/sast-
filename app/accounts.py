"""User accounts and sessions.

Small on purpose. The job here is to know who is using the tool -- so that
restarting it, updating the scanners, or marking a finding as a false positive
can be attributed to a person -- not to grow into an identity system.

Passwords are hashed with scrypt from the standard library. No new dependency,
and scrypt is memory-hard, so a stolen database is expensive to attack. The
parameters and the salt are stored next to the hash, which is what lets them
be raised later without invalidating existing passwords.

Storage is SQLite on the data volume: accounts have to outlive a restart, and
sqlite3 ships with Python. Scan history stays in memory by design; this does
not change that.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import config

# scrypt parameters. n is the cost: raising it makes both a login and an
# offline attack proportionally slower. 2**14 keeps a login around 50-100ms,
# which a person does not notice and an attacker does.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32

# A session is a random token, not a signed blob: revoking it has to be
# immediate, and a server-side row is the simplest way to guarantee that.
SESSION_BYTES = 32
SESSION_TTL = 12 * 3600

MIN_PASSWORD_LEN = 12          # length beats complexity rules
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}\Z")

_lock = threading.Lock()


@dataclass
class User:
    id: int
    username: str
    is_admin: bool
    disabled: bool
    created_at: str
    last_login: Optional[str]


def _db_path() -> Path:
    return Path(config.ACCOUNTS_DB)


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    # WAL keeps a reader from blocking the writer, which matters because the
    # UI polls while someone may be editing accounts.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with _lock, _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT    NOT NULL UNIQUE,
                password    TEXT    NOT NULL,
                is_admin    INTEGER NOT NULL DEFAULT 0,
                disabled    INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    NOT NULL,
                last_login  TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token       TEXT    PRIMARY KEY,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at  REAL    NOT NULL,
                expires_at  REAL    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE TABLE IF NOT EXISTS api_tokens (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name        TEXT    NOT NULL,
                prefix      TEXT    NOT NULL,
                token_hash  TEXT    NOT NULL,
                created_at  TEXT    NOT NULL,
                last_used   TEXT,
                revoked     INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_tokens_user ON api_tokens(user_id);
            CREATE INDEX IF NOT EXISTS idx_tokens_prefix ON api_tokens(prefix);
            CREATE TABLE IF NOT EXISTS login_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT    NOT NULL,
                success     INTEGER NOT NULL,
                source      TEXT    NOT NULL DEFAULT '',
                at          TEXT    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_login_at ON login_events(at);
            """
        )


# ------------------------------------------------------------------ hashing

def hash_password(password: str) -> str:
    """scrypt$n$r$p$salt$key -- parameters travel with the hash.

    Storing them means the cost can be raised later and old passwords still
    verify, instead of every account breaking on a parameter change.
    """
    salt = os.urandom(SALT_BYTES)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                         n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_BYTES)
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.hex(), key.hex())


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check against a stored hash."""
    try:
        scheme, n, r, p, salt_hex, key_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        key = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                             n=int(n), r=int(r), p=int(p),
                             dklen=len(bytes.fromhex(key_hex)))
    except (ValueError, TypeError):
        return False
    # compare_digest, not ==: a byte-by-byte comparison leaks how much of the
    # hash matched through its timing.
    return hmac.compare_digest(key, bytes.fromhex(key_hex))


# Rules a password must satisfy. Length does most of the work: a long
# passphrase beats a short one with a symbol bolted on, and character-class
# rules mostly teach people to write "Password1!".
COMMON_PASSWORDS = {"password", "administrator", "changeme", "sast-studio",
                    "letmein", "12345678", "qwertyuiop", "password123"}


def password_policy() -> dict:
    """The rules, so the UI can state them instead of guessing."""
    return {
        "min_length": MIN_PASSWORD_LEN,
        "rejects_common": True,
        "session_hours": int(SESSION_TTL // 3600),
        "notes": [
            "length matters more than mixing character classes",
            "changing a password ends every session and revokes that "
            "account's API tokens",
        ],
    }


def check_password_policy(password: str) -> Optional[str]:
    """Return why this password is refused, or None when it is acceptable."""
    if len(password) < MIN_PASSWORD_LEN:
        return f"password must be at least {MIN_PASSWORD_LEN} characters"
    if password.lower() in COMMON_PASSWORDS:
        return "password is too common"
    return None


# One fixed hash, computed once, for logins naming a user that does not
# exist. Its value is irrelevant; what matters is that checking it costs the
# same as checking a real one.
_DECOY_HASH = hash_password(secrets.token_urlsafe(16))


# -------------------------------------------------------------------- users

def _row_to_user(row: sqlite3.Row) -> User:
    return User(id=row["id"], username=row["username"],
                is_admin=bool(row["is_admin"]), disabled=bool(row["disabled"]),
                created_at=row["created_at"], last_login=row["last_login"])


def create_user(username: str, password: str, is_admin: bool = False) -> User:
    username = (username or "").strip().lower()
    if not USERNAME_RE.match(username):
        raise ValueError("username must be 2-32 characters: lower-case "
                         "letters, digits, dot, dash or underscore")
    problem = check_password_policy(password)
    if problem:
        raise ValueError(problem)

    now = _now()
    with _lock, _connect() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users (username, password, is_admin, created_at) "
                "VALUES (?, ?, ?, ?)",
                (username, hash_password(password), int(is_admin), now))
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"user '{username}' already exists") from exc
        row = conn.execute("SELECT * FROM users WHERE id = ?",
                           (cur.lastrowid,)).fetchone()
    return _row_to_user(row)


def list_users() -> list[User]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    return [_row_to_user(r) for r in rows]


def get_user(username: str) -> Optional[User]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?",
                           ((username or "").strip().lower(),)).fetchone()
    return _row_to_user(row) if row else None


def count_admins(exclude_id: Optional[int] = None) -> int:
    """Enabled admins, optionally ignoring one. Used to refuse lock-out."""
    sql = "SELECT COUNT(*) AS c FROM users WHERE is_admin = 1 AND disabled = 0"
    args: tuple = ()
    if exclude_id is not None:
        sql += " AND id != ?"
        args = (exclude_id,)
    with _connect() as conn:
        return conn.execute(sql, args).fetchone()["c"]


def set_password(user_id: int, password: str) -> None:
    problem = check_password_policy(password)
    if problem:
        raise ValueError(problem)
    with _lock, _connect() as conn:
        conn.execute("UPDATE users SET password = ? WHERE id = ?",
                     (hash_password(password), user_id))
        # Changing a password ends every session for that user: if it was
        # changed because it leaked, leaving the old sessions alive defeats
        # the point. The same argument applies to API tokens, which are
        # credentials for the same account and outlive sessions.
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("UPDATE api_tokens SET revoked = 1 WHERE user_id = ?",
                     (user_id,))


def set_disabled(user_id: int, disabled: bool) -> None:
    if disabled and count_admins(exclude_id=user_id) == 0:
        raise ValueError("cannot disable the last enabled administrator")
    with _lock, _connect() as conn:
        conn.execute("UPDATE users SET disabled = ? WHERE id = ?",
                     (int(disabled), user_id))
        if disabled:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def set_admin(user_id: int, is_admin: bool) -> None:
    if not is_admin and count_admins(exclude_id=user_id) == 0:
        raise ValueError("cannot remove the last administrator")
    with _lock, _connect() as conn:
        conn.execute("UPDATE users SET is_admin = ? WHERE id = ?",
                     (int(is_admin), user_id))


def delete_user(user_id: int) -> None:
    if count_admins(exclude_id=user_id) == 0:
        raise ValueError("cannot delete the last administrator")
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ----------------------------------------------------------------- sessions

def authenticate(username: str, password: str) -> Optional[User]:
    """Check a login. Returns the user, or None for any failure."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?",
                           ((username or "").strip().lower(),)).fetchone()

    # Verify against a fixed decoy when the user does not exist, so both
    # paths do exactly one scrypt. Hashing a dummy *and then* verifying it
    # did two, which made a missing user measurably slower -- the opposite of
    # what the check was for.
    stored = row["password"] if row else _DECOY_HASH
    ok = verify_password(password or "", stored)

    if not row or not ok or row["disabled"]:
        return None
    with _lock, _connect() as conn:
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?",
                     (_now(), row["id"]))
    return _row_to_user(row)


MAX_LOGIN_EVENTS = 500      # a rolling window, not an archive


def record_login(username: str, success: bool, source: str = "") -> None:
    """Note an attempt, successful or not.

    Failures matter more than successes here: a run of them against one
    account is what somebody guessing looks like, and without a record there
    is nothing to notice it in.
    """
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO login_events (username, success, source, at) "
            "VALUES (?, ?, ?, ?)",
            ((username or "")[:64], int(success), (source or "")[:64], _now()))
        # Keep the table bounded: this is for looking at recent activity, and
        # an unbounded log on a volume is a slow way to fill a disk.
        conn.execute(
            "DELETE FROM login_events WHERE id NOT IN "
            "(SELECT id FROM login_events ORDER BY id DESC LIMIT ?)",
            (MAX_LOGIN_EVENTS,))


def list_login_events(limit: int = 50, username: Optional[str] = None) -> list[dict]:
    sql = "SELECT username, success, source, at FROM login_events"
    args: list = []
    if username is not None:
        sql += " WHERE username = ?"
        args.append(username)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(max(1, min(limit, MAX_LOGIN_EVENTS)))
    with _connect() as conn:
        return [{"username": r["username"], "success": bool(r["success"]),
                 "source": r["source"], "at": r["at"]}
                for r in conn.execute(sql, args).fetchall()]


def start_session(user_id: int) -> str:
    token = secrets.token_urlsafe(SESSION_BYTES)
    now = time.time()
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)", (token, user_id, now, now + SESSION_TTL))
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    return token


def session_user(token: Optional[str]) -> Optional[User]:
    if not token:
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token = ? AND s.expires_at > ? AND u.disabled = 0",
            (token, time.time())).fetchone()
    return _row_to_user(row) if row else None


def end_session(token: Optional[str]) -> None:
    if not token:
        return
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


# --------------------------------------------------------------- API tokens
# A token is how a script or an MCP client calls the API without a password.
# It belongs to a user: whatever it does is that person's doing, and disabling
# them disables their tokens too.
TOKEN_PREFIX = "sast_"
TOKEN_BYTES = 32
PREFIX_LEN = 8          # stored in clear, only to find the row to compare


@dataclass
class ApiToken:
    id: int
    user_id: int
    username: str
    name: str
    prefix: str
    created_at: str
    last_used: Optional[str]
    revoked: bool


def _hash_token(token: str) -> str:
    """Tokens are high-entropy already, so a plain SHA-256 is enough.

    scrypt exists to make *guessable* secrets expensive to attack; against 256
    random bits it only makes every API call slow. What matters is that the
    database never holds anything usable, which a one-way hash gives us.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(user_id: int, name: str) -> tuple[ApiToken, str]:
    """Return the record and the secret. The secret is shown exactly once."""
    name = (name or "").strip() or "api token"
    if len(name) > 64:
        raise ValueError("token name is too long")

    secret = TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)
    prefix = secret[:PREFIX_LEN]
    now = _now()
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO api_tokens (user_id, name, prefix, token_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, name, prefix, _hash_token(secret), now))
        row = conn.execute(
            "SELECT t.*, u.username FROM api_tokens t JOIN users u ON u.id = t.user_id "
            "WHERE t.id = ?", (cur.lastrowid,)).fetchone()
    return _row_to_token(row), secret


def _row_to_token(row: sqlite3.Row) -> ApiToken:
    return ApiToken(id=row["id"], user_id=row["user_id"],
                    username=row["username"], name=row["name"],
                    prefix=row["prefix"], created_at=row["created_at"],
                    last_used=row["last_used"], revoked=bool(row["revoked"]))


def list_tokens(user_id: Optional[int] = None) -> list[ApiToken]:
    sql = ("SELECT t.*, u.username FROM api_tokens t "
           "JOIN users u ON u.id = t.user_id WHERE t.revoked = 0")
    args: tuple = ()
    if user_id is not None:
        sql += " AND t.user_id = ?"
        args = (user_id,)
    sql += " ORDER BY t.created_at DESC"
    with _connect() as conn:
        return [_row_to_token(r) for r in conn.execute(sql, args).fetchall()]


def revoke_token(token_id: int, user_id: Optional[int] = None) -> bool:
    """Revoke a token. Pass user_id to refuse revoking someone else's."""
    sql = "UPDATE api_tokens SET revoked = 1 WHERE id = ? AND revoked = 0"
    args: list = [token_id]
    if user_id is not None:
        sql += " AND user_id = ?"
        args.append(user_id)
    with _lock, _connect() as conn:
        return conn.execute(sql, args).rowcount > 0


def token_user(token: Optional[str]) -> Optional[User]:
    """The user a token belongs to, or None.

    A disabled account's tokens stop working immediately, which is the whole
    reason tokens are tied to a user rather than standing alone.
    """
    if not token or not token.startswith(TOKEN_PREFIX):
        return None
    prefix = token[:PREFIX_LEN]
    with _connect() as conn:
        rows = conn.execute(
            "SELECT t.id, t.token_hash, u.* FROM api_tokens t "
            "JOIN users u ON u.id = t.user_id "
            "WHERE t.prefix = ? AND t.revoked = 0 AND u.disabled = 0",
            (prefix,)).fetchall()

    given = _hash_token(token)
    for row in rows:
        if hmac.compare_digest(given, row["token_hash"]):
            with _lock, _connect() as conn:
                conn.execute("UPDATE api_tokens SET last_used = ? WHERE id = ?",
                             (_now(), row["id"]))
            return _row_to_user(row)
    return None


# ------------------------------------------------------------------ startup

def ensure_first_admin() -> Optional[str]:
    """Create the first administrator if there are no users at all.

    Returns a generated password when it made one, so the caller can print it
    once to the log. A fixed default like admin/admin would be a backdoor on
    every deployment that never got around to changing it.
    """
    init_db()
    with _connect() as conn:
        if conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]:
            return None

    username = os.environ.get("SAST_ADMIN_USER", "admin").strip().lower()
    password = os.environ.get("SAST_ADMIN_PASSWORD", "").strip()
    generated = False
    if not password:
        password = secrets.token_urlsafe(18)
        generated = True

    create_user(username, password, is_admin=True)
    return password if generated else None


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
