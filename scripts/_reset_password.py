"""Reset an account's password from inside the container.

Run through scripts/reset-password.sh rather than directly: it works out
whether there is a container to run in and passes the password on stdin.

This bypasses the current password because the person running it has a shell
on the host, which is strictly more access than the web login gives. What it
does not bypass is the password policy -- a recovery password that breaks the
deployment's own rules is a bad password.
"""
import os
import sys

from app import accounts


def main() -> int:
    username = os.environ.get("RESET_USER", "").strip().lower()

    if os.environ.get("RESET_LIST") == "1":
        accounts.init_db()
        users = accounts.list_users()
        if not users:
            print("no accounts yet; one is created when the service starts")
            return 0
        for u in users:
            flags = []
            if u.is_admin:
                flags.append("administrator")
            if u.disabled:
                flags.append("disabled")
            print(f"  {u.username}" + (f"  ({', '.join(flags)})" if flags else ""))
        return 0

    # On stdin, never argv: arguments show up in ps output and shell history.
    password = sys.stdin.read().rstrip("\n")

    if not username:
        print("no username given", file=sys.stderr)
        return 2
    if not password:
        print("no password given", file=sys.stderr)
        return 2

    accounts.init_db()

    user = accounts.get_user(username)
    if user is None:
        known = ", ".join(u.username for u in accounts.list_users()) or "none"
        print(f"no such account: {username}", file=sys.stderr)
        print(f"accounts on this deployment: {known}", file=sys.stderr)
        return 1

    # The reuse check exists to stop someone cycling back to a password that
    # may have leaked. Recovery is the one case where insisting on it can
    # leave a locked-out administrator with no way in, so it is relaxed here
    # and every other rule still applies.
    problem = accounts.check_password_policy(password)
    if problem:
        print(f"refused: {problem}", file=sys.stderr)
        return 1

    # set_password re-checks the policy *with* the account's history, so it
    # can still refuse for reuse alone. Everything else was just checked
    # above, so anything it refuses now is the history rule -- write the hash
    # directly rather than matching on the wording of an error message.
    try:
        accounts.set_password(user.id, password)
    except ValueError:
        _force(user.id, password)

    notes = []
    if user.disabled:
        accounts.set_disabled(user.id, False)
        notes.append("re-enabled the account")
    if not user.is_admin:
        notes.append("note: this account is not an administrator")

    print(f"password reset for {user.username}")
    for note in notes:
        print(f"  {note}")
    print("  existing sessions and API tokens for this account were revoked")
    return 0


def _force(user_id: int, password: str) -> None:
    """Set the password past the reuse check, keeping every other guarantee.

    Same writes as accounts.set_password, minus the history check: the
    outgoing hash is still recorded, so the reuse rule keeps working for
    ordinary changes made after this recovery.
    """
    now = accounts._now()
    with accounts._lock, accounts._connect() as conn:
        previous = conn.execute("SELECT password FROM users WHERE id = ?",
                                (user_id,)).fetchone()
        if previous:
            conn.execute(
                "INSERT INTO password_history (user_id, password, changed_at) "
                "VALUES (?, ?, ?)", (user_id, previous["password"], now))
        conn.execute(
            "UPDATE users SET password = ?, password_changed_at = ? "
            "WHERE id = ?",
            (accounts.hash_password(password), now, user_id))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("UPDATE api_tokens SET revoked = 1 WHERE user_id = ?",
                     (user_id,))


if __name__ == "__main__":
    sys.exit(main())
