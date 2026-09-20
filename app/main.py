"""FastAPI application: REST API + static single-page UI for SAST Studio."""
from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import csv
import io
import json
import os
from contextlib import asynccontextmanager
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import (FileResponse, JSONResponse, RedirectResponse,
                               Response)
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from .adapters import ADAPTERS
from .config import config
from .inventory import inventory
from .models import ScanTarget
from .orchestrator import manager
from .source import SourceError, resolve_local_path, validate_git_url

@asynccontextmanager
async def _lifespan(_app: FastAPI):
    """Prepare the account store and make sure someone can sign in.

    Only runs when auth is enabled, so an existing deployment that has not
    turned it on keeps working exactly as before.
    """
    await _prepare_accounts()
    yield



app = FastAPI(title="SAST Studio", version="1.0.0", lifespan=_lifespan)

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/api/system")
async def system_status() -> dict:
    """Docker container performance for the Monitor tab."""
    from . import docker_stats
    return {"docker": await run_in_threadpool(docker_stats.collect)}


@app.get("/api/admin/status")
async def admin_status(request: Request) -> dict:
    """State of the operator panel: any job running, and what can be updated."""
    from . import admin

    require_admin(request)
    return admin.status()


@app.post("/api/admin/update-tools")
async def admin_update_tools(request: Request,
                             tools: Optional[str] = Form(None)) -> JSONResponse:
    """Update the scanners that can be updated in place.

    Returns immediately; the Monitor tab polls /api/admin/status for progress.
    """
    from . import admin

    # Installing packages on the host is an administrator's job. Being signed
    # in only says who you are, not that you may do this.
    require_admin(request)
    wanted = [t.strip() for t in (tools or "").split(",") if t.strip()]
    # An update is the one thing that changes a version, so the cached probe
    # is wrong from here on. A stale version after an update would look like
    # the update failed, which is worse than the second it costs to re-probe.
    _tool_cache.clear()
    result = admin.start_update(wanted)
    return JSONResponse(result, status_code=202 if result.get("started") else 409)


@app.post("/api/admin/restart")
async def admin_restart(request: Request) -> JSONResponse:
    """Restart the application process so updated scanners are picked up."""
    from . import admin

    require_admin(request)
    result = admin.restart_app()
    return JSONResponse(result, status_code=202 if result.get("restarting") else 409)


# The published rulesets we offer for Semgrep. "auto" is deliberately absent:
# semgrep refuses to build it while metrics are off, and we always scan with
# --metrics=off so nothing about the scanned code leaves this host.
SEMGREP_RULESETS = [
    {"id": "p/default", "recommended": True},
    {"id": "p/owasp-top-ten", "recommended": True},
    {"id": "p/security-audit", "recommended": True},
    {"id": "p/python", "recommended": True},
    {"id": "p/javascript", "recommended": True},
    {"id": "p/java", "recommended": True},
    {"id": "p/golang", "recommended": True},
    {"id": "p/secrets", "recommended": True},
]


SESSION_COOKIE = "sast_session"

# Endpoints that must work before anyone is logged in, plus the static assets
# needed to render the login form itself.
_PUBLIC_PATHS = {"/api/health", "/api/auth/login", "/api/auth/whoami"}


def current_user(request: Request):
    """Whoever is making this request: a signed-in person or an API token.

    Both resolve to a User, so everything downstream -- permissions, the name
    attached to an action -- works the same whether it came from the browser
    or from a script.
    """
    from . import accounts

    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        user = accounts.token_user(auth[7:].strip())
        if user is not None:
            return user
    return accounts.session_user(request.cookies.get(SESSION_COOKIE))


def require_user(request: Request):
    """The signed-in user, or 401. Used by every protected endpoint."""
    if not config.REQUIRE_AUTH:
        return None
    user = current_user(request)
    if user is None:
        raise HTTPException(401, "sign in to continue")
    return user


def require_admin(request: Request):
    """Administrators only. Managing accounts is not an ordinary action."""
    from . import accounts

    if not config.REQUIRE_AUTH:
        return None
    user = current_user(request)
    if user is None:
        raise HTTPException(401, "sign in to continue")
    if not user.is_admin:
        raise HTTPException(403, "administrator access required")
    return user


def _owner_name(request: Request) -> Optional[str]:
    """Who to record as the owner of a scan, or None when auth is off."""
    user = current_user(request)
    return user.username if user else None


def _may_see_scan(request: Request, job) -> bool:
    """A scan's findings quote the scanned source, so it is not public.

    With auth off nothing changes: there are no users to tell apart. With auth
    on, an administrator can already read everything on the host, so
    restricting them would be theatre rather than a boundary.
    """
    if not config.REQUIRE_AUTH:
        return True
    user = current_user(request)
    if user is None:
        return False
    if user.is_admin or job.owner is None:
        return True
    return job.owner == user.username


def _request_is_https(request: Request) -> bool:
    forwarded = request.headers.get("x-forwarded-proto", "")
    if forwarded:
        # A comma-separated list means several proxies; the first is the one
        # the client actually spoke to.
        return forwarded.split(",")[0].strip().lower() == "https"
    return request.url.scheme == "https"


def _same_site_request(request: Request) -> bool:
    """Whether this request came from our own page.

    An absent Origin is a non-browser client (curl, a CI job), which cannot be
    tricked into making this request by a page the user is visiting -- the
    thing CSRF is. A present but foreign Origin is exactly that attack.
    """
    origin = request.headers.get("origin")
    if not origin:
        return True
    return _origin_allowed(origin, request)


@app.middleware("http")
async def _auth_gate(request: Request, call_next):
    """Refuse unauthenticated requests when auth is on.

    A gate here rather than a dependency on each route, because forgetting one
    route is how these holes appear -- the default has to be "protected".
    """
    if not config.REQUIRE_AUTH:
        return await call_next(request)

    path = request.url.path
    public = (path in _PUBLIC_PATHS
              or path == "/mcp"          # answers 401 itself, in JSON-RPC
              or path == "/login"
              or path.startswith("/static/")
              or path in {"/i18n.js", "/app.js", "/style.css", "/login.js"})
    # A state-changing request authenticated by a cookie is the CSRF case:
    # the browser attaches the cookie whoever asked for the request. A bearer
    # token is not attached automatically, so it is not affected.
    if (request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and not request.headers.get("authorization")
            and not _same_site_request(request)):
        return JSONResponse({"detail": "cross-site request refused"},
                            status_code=403)

    if public or current_user(request) is not None:
        return await call_next(request)

    if path.startswith("/api/"):
        return JSONResponse({"detail": "sign in to continue"}, status_code=401)
    return RedirectResponse("/login", status_code=302)


@app.post("/api/auth/login")
async def login(request: Request, response: Response,
                username: str = Form(...), password: str = Form(...)) -> dict:
    from . import accounts

    user = accounts.authenticate(username, password)
    # The client address as the proxy saw it; "unknown" rather than a guess
    # when there is no proxy header to read.
    source = (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
              or (request.client.host if request.client else "unknown"))
    accounts.record_login(username, user is not None, source)
    if user is None:
        # One message for every failure: saying which part was wrong tells an
        # attacker which usernames exist.
        raise HTTPException(401, "invalid username or password")
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


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response) -> dict:
    from . import accounts
    accounts.end_session(request.cookies.get(SESSION_COOKIE))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.get("/api/auth/whoami")
async def whoami(request: Request) -> dict:
    """Who is signed in, and whether signing in is required at all.

    The UI asks this first so it knows whether to show a login form, a user
    menu, or neither.
    """
    from . import accounts

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


@app.post("/api/auth/password")
async def change_own_password(request: Request,
                              current: str = Form(...),
                              new_password: str = Form(...)) -> dict:
    """Change your own password, proving you know the current one."""
    from . import accounts

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
@app.get("/api/users")
async def list_users(request: Request) -> dict:
    from . import accounts

    require_admin(request)
    return {"users": [
        {"id": u.id, "username": u.username, "is_admin": u.is_admin,
         "disabled": u.disabled, "created_at": u.created_at,
         "last_login": u.last_login}
        for u in accounts.list_users()
    ]}


@app.post("/api/users")
async def add_user(request: Request, username: str = Form(...),
                   password: str = Form(...),
                   is_admin: Optional[str] = Form(None)) -> JSONResponse:
    from . import accounts

    require_admin(request)
    try:
        user = accounts.create_user(username, password,
                                    is_admin=_parse_bool(is_admin, False))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return JSONResponse({"id": user.id, "username": user.username},
                        status_code=201)


@app.post("/api/users/{user_id}/password")
async def reset_password(request: Request, user_id: int,
                         password: str = Form(...)) -> dict:
    from . import accounts

    require_admin(request)
    try:
        accounts.set_password(user_id, password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@app.post("/api/users/{user_id}/state")
async def update_user_state(request: Request, user_id: int,
                            disabled: Optional[str] = Form(None),
                            is_admin: Optional[str] = Form(None)) -> dict:
    from . import accounts

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


@app.delete("/api/users/{user_id}")
async def remove_user(request: Request, user_id: int) -> dict:
    from . import accounts

    admin = require_admin(request)
    if admin is not None and admin.id == user_id:
        raise HTTPException(400, "you cannot delete your own account")
    try:
        accounts.delete_user(user_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


# ------------------------------------------------------------- API tokens
@app.get("/api/tokens")
async def list_api_tokens(request: Request) -> dict:
    """Your own tokens. Administrators see everyone's, to audit them."""
    from . import accounts

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


@app.post("/api/tokens")
async def create_api_token(request: Request, name: str = Form(...)) -> JSONResponse:
    """Create a token for the caller. The secret is returned once, here."""
    from . import accounts

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


@app.delete("/api/tokens/{token_id}")
async def revoke_api_token(request: Request, token_id: int) -> dict:
    from . import accounts

    user = require_user(request)
    if user is None:
        raise HTTPException(400, "authentication is disabled")
    # A non-admin may only revoke their own.
    scope = None if user.is_admin else user.id
    if not accounts.revoke_token(token_id, scope):
        raise HTTPException(404, "token not found")
    return {"ok": True}


# ------------------------------------------------------------------- MCP
# One endpoint, Streamable HTTP. A token identifies the caller, so a scan an
# assistant starts belongs to the person whose token it used.
@app.post("/mcp")
async def mcp_endpoint(request: Request) -> Response:
    from . import mcp

    # The spec requires validating Origin: without it a web page could drive
    # this endpoint from a victim's browser (DNS rebinding). A browser always
    # sends Origin on a cross-origin request; a CLI or an assistant sends none,
    # which is why absent is allowed and mismatched is not.
    origin = request.headers.get("origin")
    if origin and not _origin_allowed(origin, request):
        raise HTTPException(403, "origin not allowed")

    user = current_user(request)
    if config.REQUIRE_AUTH and user is None:
        # 401 with the scheme, so a client knows what to send.
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None,
             "error": {"code": -32001, "message": "authentication required"}},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        message = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None,
             "error": {"code": mcp.PARSE_ERROR, "message": "invalid JSON"}},
            status_code=400)

    # A batch is a list. Notifications inside it produce no reply, which is
    # why the responses are filtered rather than mapped one-to-one.
    if isinstance(message, list):
        replies = [r for r in (await run_in_threadpool(mcp.handle, m, user)
                               for m in message) if r is not None]
        if not replies:
            return Response(status_code=202)
        return JSONResponse(replies)

    if not isinstance(message, dict):
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None,
             "error": {"code": mcp.INVALID_REQUEST,
                       "message": "expected a JSON-RPC object"}},
            status_code=400)

    reply = await run_in_threadpool(mcp.handle, message, user)
    if reply is None:
        # A notification: accepted, nothing to say back.
        return Response(status_code=202)
    return JSONResponse(reply)


@app.get("/mcp")
async def mcp_stream() -> Response:
    """No server-initiated stream.

    The spec lets a server answer GET with 405 when it never pushes messages
    to the client, which is our case: every answer belongs to a request.
    """
    return Response(status_code=405, headers={"Allow": "POST"})


def _origin_allowed(origin: str, request: Request) -> bool:
    """Whether this Origin is our own site.

    Host alone is not enough: nginx rewrites it to a fixed value on purpose
    (so nothing downstream builds links from a header the client controls),
    which meant every browser form post looked cross-site and logging in was
    refused. X-Forwarded-Host carries what the browser actually asked for.

    Both are compared, not trusted: an attacker can set X-Forwarded-Host, but
    doing so only ever makes their Origin match the value they also chose --
    and a browser will not let a page on evil.example set either header. What
    this check catches is the browser attaching our cookie to a form on
    somebody else's page, and for that the browser's own Origin is honest.
    """
    allowed = {o.strip().rstrip("/") for o in config.MCP_ALLOWED_ORIGINS if o.strip()}
    if "*" in allowed:
        return True

    hosts = {request.headers.get("host", "")}
    forwarded = request.headers.get("x-forwarded-host", "")
    if forwarded:
        # Several proxies produce a list; the first is the client's own.
        hosts.add(forwarded.split(",")[0].strip())
    hosts.discard("")

    same_site = {f"{scheme}://{host}"
                 for host in hosts for scheme in ("http", "https")}
    return origin.rstrip("/") in (allowed | same_site)


@app.get("/api/auth/policy")
async def auth_policy() -> dict:
    """The password rules, so the UI states them rather than guessing."""
    from . import accounts
    return accounts.password_policy()


@app.post("/api/auth/policy")
async def update_auth_policy(request: Request,
                             min_length: Optional[str] = Form(None),
                             require_upper: Optional[str] = Form(None),
                             require_lower: Optional[str] = Form(None),
                             require_digit: Optional[str] = Form(None),
                             require_symbol: Optional[str] = Form(None),
                             reject_common: Optional[str] = Form(None),
                             history_count: Optional[str] = Form(None),
                             max_age_days: Optional[str] = Form(None),
                             idle_minutes: Optional[str] = Form(None)) -> dict:
    """Change the password rules. Administrators only: it applies to everyone."""
    from . import accounts

    require_admin(request)
    changes: dict = {}
    for key, raw in (("min_length", min_length),
                     ("history_count", history_count),
                     ("max_age_days", max_age_days),
                     ("idle_minutes", idle_minutes)):
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


@app.get("/api/auth/logins")
async def login_history(request: Request, limit: int = 50) -> dict:
    """Recent sign-in attempts.

    Your own by default. An administrator sees everyone's, because a run of
    failures against one account is the thing worth noticing and nobody can
    notice it from inside that account.
    """
    from . import accounts

    user = require_user(request)
    if user is None:
        raise HTTPException(400, "authentication is disabled")
    scope = None if user.is_admin else user.username
    return {"events": accounts.list_login_events(limit, scope),
            "scope": "all" if user.is_admin else user.username}


@app.get("/api/mcp/config")
async def mcp_config(request: Request) -> dict:
    """A ready-to-paste MCP client entry for this deployment.

    The token is left as a placeholder: it is shown once at creation and
    handing it out again from an endpoint would undo that.
    """
    require_user(request)
    host = (request.headers.get("x-forwarded-host", "").split(",")[0].strip()
            or request.headers.get("host", "localhost:8080"))
    scheme = "https" if _request_is_https(request) else "http"
    from . import mcp
    return {
        "url": f"{scheme}://{host}/mcp",
        "protocol_version": mcp.PROTOCOL_VERSION,
        "tools": [{"name": t["name"], "description": t["description"]}
                  for t in mcp.TOOLS],
        "config": {
            "mcpServers": {
                "sast-studio": {
                    "url": f"{scheme}://{host}/mcp",
                    "headers": {"Authorization": "Bearer YOUR_TOKEN_HERE"},
                }
            }
        },
        # A .env alongside the client config, because that is where a token
        # belongs: a file you do not commit, rather than pasted into a
        # config that often ends up in a repository.
        "env_template": (
            "# SAST Studio\n"
            "# Create the token in Settings -> API tokens. It is shown once.\n"
            "# Keep this file out of version control.\n"
            f"SAST_STUDIO_URL={scheme}://{host}\n"
            f"SAST_STUDIO_MCP_URL={scheme}://{host}/mcp\n"
            "SAST_STUDIO_TOKEN=paste-your-token-here\n"
        ),
    }


@app.get("/api/rulesets")
async def list_rulesets() -> dict:
    """Published rulesets the scan form can offer, plus the current default."""
    return {"semgrep": SEMGREP_RULESETS,
            "default": config.SEMGREP_RULESETS}


@app.get("/api/rules")
async def list_custom_rules(engine: Optional[str] = None) -> dict:
    """Every rule the scan form can offer, built-in templates included."""
    from . import rules as rules_mod
    return {"rules": rules_mod.list_rules(engine),
            "engines": list(rules_mod.ENGINES)}


@app.get("/api/rules/{engine}/{name}")
async def read_custom_rule(engine: str, name: str) -> dict:
    from . import rules as rules_mod
    try:
        rule = rules_mod.read_rule(engine, name)
    except FileNotFoundError:
        raise HTTPException(404, "rule not found") from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"engine": rule.engine, "name": rule.name,
            "builtin": rule.builtin, "content": rule.content}


@app.post("/api/rules/validate")
async def validate_custom_rule(request: Request, engine: str = Form(...),
                               content: str = Form(...)) -> dict:
    """Ask the scanner whether this rule compiles, without saving it."""
    from . import rules as rules_mod

    # Validating runs the scanner, so this spends CPU on the host.
    require_user(request)
    return await run_in_threadpool(rules_mod.validate_rule, engine, content)


@app.post("/api/rules/{engine}/{name}")
async def save_custom_rule(request: Request, engine: str, name: str,
                           content: str = Form(...)) -> JSONResponse:
    """Save a rule. It is validated first, so a broken rule is never stored."""
    from . import rules as rules_mod

    # A saved rule is executed by a scanner on every later scan, so writing
    # one changes what everybody else's scans run.
    require_admin(request)
    try:
        saved = await run_in_threadpool(rules_mod.save_rule, engine, name, content)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return JSONResponse(saved, status_code=201)


@app.delete("/api/rules/{engine}/{name}")
async def delete_custom_rule(request: Request, engine: str, name: str) -> dict:
    from . import rules as rules_mod

    require_admin(request)
    try:
        rules_mod.delete_rule(engine, name)
    except FileNotFoundError:
        raise HTTPException(404, "rule not found") from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"deleted": name}


class _ToolCache:
    """Remembers the probe result until something could have changed it.

    Guarded by a lock because several browsers can hit /api/tools at once, and
    two of them racing would run twelve subprocesses to learn the same thing.
    """

    TTL = 300.0     # a version can also change from outside the app

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value: Optional[dict] = None
        self._at = 0.0

    def get(self) -> Optional[dict]:
        with self._lock:
            if self._value is None or time.monotonic() - self._at > self.TTL:
                return None
            return self._value

    def set(self, value: dict) -> None:
        with self._lock:
            self._value = value
            self._at = time.monotonic()

    def clear(self) -> None:
        with self._lock:
            self._value = None


_tool_cache = _ToolCache()


@app.get("/api/tools")
async def list_tools() -> dict:
    """Availability + metadata for every integrated tool."""
    def describe(adapter) -> dict:
        available, version = adapter.probe()
        return {
            "name": adapter.name,
            "kind": adapter.kind.value,
            "available": available,
            "version": version,
            "install_hint": adapter.install_hint,
            "languages": adapter.languages,
            "requirement": adapter.requirement,
        }

    def probe_all() -> list[dict]:
        # Each probe spawns a "--version" process, and semgrep and bearer take
        # about 900ms each, so running the six in sequence cost ~2.4s on every
        # page load. They do not depend on each other, so run them together and
        # keep the original order in the response.
        with ThreadPoolExecutor(max_workers=len(ADAPTERS)) as pool:
            return list(pool.map(describe, ADAPTERS))

    # A scanner's version only changes when someone updates it, which happens
    # from the Maintenance panel and clears this cache. Re-probing on every
    # page load spent a second re-learning something that had not changed.
    #
    # Cache the whole payload, not just the tools: returning a different shape
    # on a hit than on a miss broke the Monitor tab, because the client read a
    # field that only existed on a miss. A cache must be invisible to callers.
    cached = _tool_cache.get()
    if cached is not None:
        return cached

    tools = await run_in_threadpool(probe_all)
    payload = {
        "tools": tools,
        "config": {
            "allow_local_path": config.ALLOW_LOCAL_PATH,
            "allowed_git_schemes": sorted(config.ALLOWED_GIT_SCHEMES),
            "max_upload_bytes": config.MAX_UPLOAD_BYTES,
        },
    }
    _tool_cache.set(payload)
    return payload


@app.get("/api/policies")
async def policies() -> dict:
    """The fixed rule used to judge every scan (shown in the UI, not chosen)."""
    from .policies import RULE_CATALOG
    return {"rules": RULE_CATALOG}


@app.post("/api/inspect")
async def inspect_project(
    request: Request,
    source_kind: str = Form(...),
    local_path: Optional[str] = Form(None),
) -> dict:
    """Pre-scan look at a project: file/size/language inventory plus, for each
    tool, whether it applies to this project and why not. Available for local
    paths only (uploads/git aren't on disk until a scan starts)."""
    # Reading server-local paths is an operator capability, not an ordinary
    # one: it exposes every file this container can read.
    require_admin(request)
    if source_kind != "path":
        raise HTTPException(400, "inspection is available for local paths only")
    if not config.ALLOW_LOCAL_PATH:
        raise HTTPException(403, "local path scanning is disabled")
    if not local_path:
        raise HTTPException(400, "local_path is required")
    try:
        root = resolve_local_path(local_path)
    except SourceError as exc:
        raise HTTPException(400, str(exc)) from exc

    def analyse() -> dict:
        inv = inventory(root)
        tools = []
        for adapter in ADAPTERS:
            applicable, reason = adapter.applicability(root)
            tools.append({
                "name": adapter.name,
                "applicable": applicable,
                "reason": reason,
                "requirement": adapter.requirement,
            })
        return {"inventory": inv, "tools": tools}

    return await run_in_threadpool(analyse)


@app.post("/api/scans")
async def create_scan(
    request: Request,
    source_kind: str = Form(...),
    tools: str = Form(""),
    git_url: Optional[str] = Form(None),
    local_path: Optional[str] = Form(None),
    confirm: Optional[str] = Form(None),
    custom_rules: Optional[str] = Form(None),
    rulesets: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
) -> JSONResponse:
    requested = [t.strip() for t in tools.split(",") if t.strip()]
    # {engine: [rule name, ...]}; names are re-checked when they are read, so
    # a bad one here cannot reach the filesystem.
    try:
        chosen_rules = json.loads(custom_rules) if custom_rules else {}
        if not isinstance(chosen_rules, dict):
            raise ValueError("custom_rules must be an object")
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, f"custom_rules: {exc}") from exc

    # {tool: [ruleset, ...]}. Only ids we publish are accepted, so a request
    # cannot point semgrep at an arbitrary location.
    known = {r["id"] for r in SEMGREP_RULESETS}
    try:
        chosen_sets = json.loads(rulesets) if rulesets else {}
        if not isinstance(chosen_sets, dict):
            raise ValueError("rulesets must be an object")
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, f"rulesets: {exc}") from exc
    chosen_sets = {tool: [r for r in names if r in known]
                   for tool, names in chosen_sets.items()}
    chosen_sets = {k: v for k, v in chosen_sets.items() if v}

    # upload/git are prepared server-side, so pause for confirmation by default
    # (the user reviews the inventory before tools run). A local path is already
    # inspectable up front, so it runs directly. Clients may override.
    want_confirm = _parse_bool(confirm, default=(source_kind in ("upload", "git")))

    if source_kind == "git":
        if not git_url:
            raise HTTPException(400, "git_url is required for source_kind=git")
        try:
            validate_git_url(git_url)
        except SourceError as exc:
            raise HTTPException(400, str(exc)) from exc
        target = ScanTarget(kind="git", display=git_url)
        job = manager.new_job(target, requested, chosen_rules, chosen_sets,
                              owner=_owner_name(request))
        manager.start(job.id, {"kind": "git", "url": git_url}, confirm=want_confirm)

    elif source_kind == "path":
        if not config.ALLOW_LOCAL_PATH:
            raise HTTPException(403, "local path scanning is disabled")
        if not local_path:
            raise HTTPException(400, "local_path is required for source_kind=path")
        target = ScanTarget(kind="path", display=local_path)
        job = manager.new_job(target, requested, chosen_rules, chosen_sets,
                              owner=_owner_name(request))
        manager.start(job.id, {"kind": "path", "path": local_path}, confirm=False)

    elif source_kind == "upload":
        if file is None:
            raise HTTPException(400, "file is required for source_kind=upload")
        target = ScanTarget(kind="upload", display=file.filename or "upload.zip")
        job = manager.new_job(target, requested, chosen_rules, chosen_sets,
                              owner=_owner_name(request))
        zip_path = manager.job_dir(job.id) / "upload.zip"
        try:
            await _save_upload(file, zip_path)
        except HTTPException:
            raise
        manager.start(job.id, {"kind": "upload", "zip_path": str(zip_path)},
                      confirm=want_confirm)

    else:
        raise HTTPException(400, f"unknown source_kind: {source_kind}")

    return JSONResponse({"id": job.id, "status": job.status.value}, status_code=201)


@app.post("/api/scans/{job_id}/confirm")
async def confirm_scan(job_id: str) -> dict:
    if manager.get(job_id) is None:
        raise HTTPException(404, "scan not found")
    if not manager.confirm(job_id):
        raise HTTPException(409, "scan is not awaiting confirmation")
    return {"id": job_id, "status": "running"}


@app.post("/api/scans/{job_id}/cancel")
async def cancel_scan(job_id: str) -> dict:
    if manager.get(job_id) is None:
        raise HTTPException(404, "scan not found")
    if not manager.cancel(job_id):
        raise HTTPException(409, "scan is not awaiting confirmation")
    return {"id": job_id, "status": "cancelled"}


@app.get("/api/scans")
async def list_scans(request: Request) -> dict:
    # Only your own scans. A scan's summary names the project someone scanned,
    # which is not everybody's business on a shared deployment.
    jobs = [j for j in manager.list_jobs() if _may_see_scan(request, j)]
    return {
        "jobs": [
            {
                "id": j.id,
                "status": j.status.value,
                "target": j.target.model_dump(),
                "created_at": j.created_at,
                "finished_at": j.finished_at,
                "summary": j.summary,
                # the report list shows each scan's verdict, so send it along
                "decision": (j.policy_evaluation or {}).get("decision", ""),
            }
            for j in jobs
        ]
    }


def _csv_safe(value):
    """Defuse spreadsheet formula injection (CWE-1236).

    Finding text comes from scanned code, so a file name or message could start
    with =, +, - or @ and be executed as a formula when the CSV is opened. A
    leading apostrophe makes the cell literal text.
    """
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


#: Column order for the CSV export — stable, so saved files stay comparable.
_CSV_COLUMNS = [
    "scan_id", "scanned_at", "target", "decision",
    "tool", "severity", "rule_id", "title", "file", "start_line", "end_line",
    "package", "installed_version", "fixed_version", "cwe", "owasp", "message",
]


@app.get("/api/scans/{job_id}/export.csv")
async def export_scan_csv(request: Request, job_id: str) -> Response:
    """Download one scan's findings as CSV (stdlib csv, no extra dependency)."""
    job = manager.get(job_id)
    # 404 rather than 403: "exists but is not yours" is itself information.
    if job is None or not _may_see_scan(request, job):
        raise HTTPException(404, "scan not found")

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    decision = (job.policy_evaluation or {}).get("decision", "")
    for result in job.results.values():
        for f in result.findings:
            extra = f.extra or {}
            writer.writerow({k: _csv_safe(v) for k, v in {
                "scan_id": job.id,
                "scanned_at": job.finished_at or job.created_at,
                "target": job.target.display,
                "decision": decision,
                "tool": f.tool,
                "severity": f.severity.value,
                "rule_id": f.rule_id,
                "title": f.title,
                "file": f.file,
                "start_line": f.start_line if f.start_line is not None else "",
                "end_line": f.end_line if f.end_line is not None else "",
                "package": extra.get("package", ""),
                "installed_version": extra.get("installed_version",
                                               extra.get("version", "")),
                "fixed_version": extra.get("fixed_version", ""),
                "cwe": " ".join(f.cwe),
                "owasp": " ".join(f.owasp),
                "message": f.message,
            }.items()})

    # UTF-8 BOM so Excel opens non-ASCII findings in the right encoding.
    body = "﻿" + buf.getvalue()
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="sast-scan-{job.id}.csv"'},
    )


@app.get("/api/scans/{job_id}")
async def get_scan(request: Request, job_id: str) -> dict:
    job = manager.get(job_id)
    if job is None or not _may_see_scan(request, job):
        raise HTTPException(404, "scan not found")
    return job.model_dump()


def _parse_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


async def _save_upload(file: UploadFile, dest: Path) -> None:
    """Stream the upload to disk with a hard size cap (defence against bombs)."""
    written = 0
    with open(dest, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > config.MAX_UPLOAD_BYTES:
                out.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, "upload exceeds size limit")
            out.write(chunk)


# ---- static single-page UI (mounted last so /api/* wins) ------------------
async def _prepare_accounts() -> None:
    if not config.REQUIRE_AUTH:
        return
    from . import accounts

    password = await run_in_threadpool(accounts.ensure_first_admin)
    if password:
        # Printed once, to the log, because a fixed default would be a
        # backdoor on every deployment that never changed it.
        user = os.environ.get("SAST_ADMIN_USER", "admin")
        print("=" * 68, flush=True)
        print("  First run: created administrator account", flush=True)
        print(f"    username: {user}", flush=True)
        print(f"    password: {password}", flush=True)
        print("  This is shown once. Sign in and change it.", flush=True)
        print("=" * 68, flush=True)


@app.get("/login")
async def login_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
