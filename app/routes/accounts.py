"""Signing in and out, passwords, accounts, API tokens and the password
policy.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from ..config import config
from ..web import (SESSION_COOKIE, _client_ip, _human_wait, _parse_bool, _request_is_https,
                   current_user, require_admin, require_user)


router = APIRouter()


@router.post("/api/auth/change-expired")
async def change_expired_password(request: Request,
                                  username: str = Form(...),
                                  current: str = Form(...),
                                  new_password: str = Form(...)) -> dict:
    """Change a password that has expired, from the login screen.

    Without this an expired account is simply locked out: it cannot sign in
    to reach the settings page, and the page is where the change lives. The
    current password is still required, so this is not a way in -- it is the
    same authentication, with the one action it is allowed to take.
    """
    from .. import accounts

    source = _client_ip(request)
    # This endpoint checks a password too, so without the same throttle it
    # would be an unlimited guessing oracle sitting next to a limited one.
    wait = accounts.login_blocked(username, source)
    if wait:
        raise HTTPException(
            429, f"too many failed attempts; try again in {_human_wait(wait)}",
            headers={"Retry-After": str(wait)})

    user = accounts.authenticate(username, password=current)
    if user is None:
        accounts.record_login(username, False, source)
        raise HTTPException(401, "invalid username or password")

    if not accounts.password_expired(user):
        # Not expired: the ordinary change-password endpoint applies, and it
        # requires a session. Refusing here keeps one path for one job.
        raise HTTPException(400, "this password has not expired")

    try:
        accounts.set_password(user.id, new_password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.post("/api/auth/login")
async def login(request: Request, response: Response,
                username: str = Form(...), password: str = Form(...)) -> dict:
    from .. import accounts

    source = _client_ip(request)

    # Checked before the password, so a locked-out attacker cannot keep
    # measuring how long a hash takes, and cannot keep guessing at all.
    wait = accounts.login_blocked(username, source)
    if wait:
        raise HTTPException(
            429, f"too many failed attempts; try again in {_human_wait(wait)}",
            headers={"Retry-After": str(wait)})

    user = accounts.authenticate(username, password)
    accounts.record_login(username, user is not None, source)
    if user is None:
        # One message for every failure: saying which part was wrong tells an
        # attacker which usernames exist.
        raise HTTPException(401, "invalid username or password")
    # Signing in clears the failures, so an earlier typo does not count
    # towards a lockout days later.
    accounts.clear_failures(username, source)
    token = accounts.start_session(user.id)
    response.set_cookie(
        SESSION_COOKIE, token,
        httponly=True,          # not readable from JavaScript, so an XSS bug
                                # cannot walk off with the session
        samesite="lax",         # blocks the cross-site form-post case
        # X-Forwarded-Proto, not request.url.scheme: nginx terminates TLS and
        # forwards over http, so the scheme here is always http and the flag
        # would never be set on exactly the deployment that needs it.
        secure=(config.COOKIE_SECURE
                if config.COOKIE_SECURE is not None
                else _request_is_https(request)),
        max_age=accounts.SESSION_TTL,
        path="/",
    )
    return {"username": user.username, "is_admin": user.is_admin}


@router.post("/api/auth/logout")
async def logout(request: Request, response: Response) -> dict:
    from .. import accounts
    accounts.end_session(request.cookies.get(SESSION_COOKIE))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/api/auth/whoami")
async def whoami(request: Request) -> dict:
    """Who is signed in, and whether signing in is required at all.

    The UI asks this first so it knows whether to show a login form, a user
    menu, or neither.
    """
    from .. import accounts

    user = current_user(request)
    return {
        "auth_required": config.REQUIRE_AUTH,
        "user": None if user is None else {
            "username": user.username,
            "is_admin": user.is_admin,
            # The UI shows a change-password prompt rather than letting the
            # person discover the expiry by being refused.
            "password_expired": accounts.password_expired(user),
        },
    }


@router.post("/api/auth/password")
async def change_own_password(request: Request,
                              current: str = Form(...),
                              new_password: str = Form(...)) -> dict:
    """Change your own password, proving you know the current one."""
    from .. import accounts

    user = require_user(request)
    if user is None:
        raise HTTPException(400, "authentication is disabled")
    if accounts.authenticate(user.username, current) is None:
        raise HTTPException(403, "current password is incorrect")
    try:
        accounts.set_password(user.id, new_password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True, "note": "all sessions for this account were ended"}


# ------------------------------------------------------------ user admin
@router.get("/api/users")
async def list_users(request: Request) -> dict:
    from .. import accounts

    require_admin(request)
    return {"users": [
        {"id": u.id, "username": u.username, "is_admin": u.is_admin,
         "disabled": u.disabled, "created_at": u.created_at,
         "last_login": u.last_login}
        for u in accounts.list_users()
    ]}


@router.post("/api/users")
async def add_user(request: Request, username: str = Form(...),
                   password: str = Form(...),
                   is_admin: Optional[str] = Form(None)) -> JSONResponse:
    from .. import accounts

    require_admin(request)
    try:
        user = accounts.create_user(username, password,
                                    is_admin=_parse_bool(is_admin, False))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return JSONResponse({"id": user.id, "username": user.username},
                        status_code=201)


@router.post("/api/users/{user_id}/password")
async def reset_password(request: Request, user_id: int,
                         password: str = Form(...)) -> dict:
    from .. import accounts

    require_admin(request)
    try:
        accounts.set_password(user_id, password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.post("/api/users/{user_id}/state")
async def update_user_state(request: Request, user_id: int,
                            disabled: Optional[str] = Form(None),
                            is_admin: Optional[str] = Form(None)) -> dict:
    from .. import accounts

    require_admin(request)
    try:
        if disabled is not None:
            accounts.set_disabled(user_id, _parse_bool(disabled, False))
        if is_admin is not None:
            accounts.set_admin(user_id, _parse_bool(is_admin, False))
    except ValueError as exc:
        # Refusing to remove the last administrator lands here.
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.delete("/api/users/{user_id}")
async def remove_user(request: Request, user_id: int) -> dict:
    from .. import accounts

    admin = require_admin(request)
    if admin is not None and admin.id == user_id:
        raise HTTPException(400, "you cannot delete your own account")
    try:
        accounts.delete_user(user_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


# ------------------------------------------------------------- API tokens
@router.get("/api/tokens")
async def list_api_tokens(request: Request) -> dict:
    """Your own tokens. Administrators see everyone's, to audit them."""
    from .. import accounts

    user = require_user(request)
    if user is None:
        raise HTTPException(400, "authentication is disabled")
    scope = None if user.is_admin else user.id
    return {"tokens": [
        {"id": tk.id, "name": tk.name, "prefix": tk.prefix,
         "username": tk.username, "created_at": tk.created_at,
         "last_used": tk.last_used}
        for tk in accounts.list_tokens(scope)
    ]}


@router.post("/api/tokens")
async def create_api_token(request: Request, name: str = Form(...)) -> JSONResponse:
    """Create a token for the caller. The secret is returned once, here."""
    from .. import accounts

    user = require_user(request)
    if user is None:
        raise HTTPException(400, "authentication is disabled")
    try:
        token, secret = accounts.create_token(user.id, name)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return JSONResponse({
        "id": token.id, "name": token.name, "prefix": token.prefix,
        # Shown once and never stored in a readable form. Saying so here is
        # what stops someone assuming they can look it up again later.
        "token": secret,
        "note": "copy this now; it cannot be shown again",
    }, status_code=201)


@router.delete("/api/tokens/{token_id}")
async def revoke_api_token(request: Request, token_id: int) -> dict:
    from .. import accounts

    user = require_user(request)
    if user is None:
        raise HTTPException(400, "authentication is disabled")
    # A non-admin may only revoke their own.
    scope = None if user.is_admin else user.id
    if not accounts.revoke_token(token_id, scope):
        raise HTTPException(404, "token not found")
    return {"ok": True}


@router.get("/api/auth/policy")
async def auth_policy() -> dict:
    """The password rules, so the UI states them rather than guessing."""
    from .. import accounts
    return accounts.password_policy()


@router.post("/api/auth/policy")
async def update_auth_policy(request: Request,
                             min_length: Optional[str] = Form(None),
                             require_upper: Optional[str] = Form(None),
                             require_lower: Optional[str] = Form(None),
                             require_digit: Optional[str] = Form(None),
                             require_symbol: Optional[str] = Form(None),
                             reject_common: Optional[str] = Form(None),
                             history_count: Optional[str] = Form(None),
                             max_age_days: Optional[str] = Form(None),
                             idle_minutes: Optional[str] = Form(None),
                             max_attempts: Optional[str] = Form(None),
                             lockout_minutes: Optional[str] = Form(None),
                             token_days: Optional[str] = Form(None)) -> dict:
    """Change the password rules. Administrators only: it applies to everyone."""
    from .. import accounts

    require_admin(request)
    changes: dict = {}
    for key, raw in (("min_length", min_length),
                     ("history_count", history_count),
                     ("max_age_days", max_age_days),
                     ("idle_minutes", idle_minutes),
                     ("max_attempts", max_attempts),
                     ("lockout_minutes", lockout_minutes),
                     ("token_days", token_days)):
        if raw is not None and raw != "":
            changes[key] = raw
    for key, raw in (("require_upper", require_upper),
                     ("require_lower", require_lower),
                     ("require_digit", require_digit),
                     ("require_symbol", require_symbol),
                     ("reject_common", reject_common)):
        if raw is not None:
            changes[key] = _parse_bool(raw, False)
    try:
        return accounts.set_policy(changes)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/api/auth/logins")
async def login_history(request: Request, limit: int = 50) -> dict:
    """Recent sign-in attempts.

    Your own by default. An administrator sees everyone's, because a run of
    failures against one account is the thing worth noticing and nobody can
    notice it from inside that account.
    """
    from .. import accounts

    user = require_user(request)
    if user is None:
        raise HTTPException(400, "authentication is disabled")
    scope = None if user.is_admin else user.username
    return {"events": accounts.list_login_events(limit, scope),
            "scope": "all" if user.is_admin else user.username}
