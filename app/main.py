"""FastAPI application: REST API + static single-page UI for SAST Studio."""
from __future__ import annotations

import os
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from . import events
from .config import config
from .orchestrator import Draining, manager
from .routes import accounts, mcp_http, ops, scans
from .web import STATIC_DIR, _client_ip, _same_site_request, current_user


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    """Prepare the account store and make sure someone can sign in.

    Only runs when auth is enabled, so an existing deployment that has not
    turned it on keeps working exactly as before.
    """
    await _prepare_accounts()
    try:
        from . import events
        events.init()
        events.record("service", "start", detail=f"SAST Studio {app.version}")
    except Exception:  # last line: never block startup on the log
        pass
    from . import upgrades
    upgrades.start_watcher(manager)
    try:
        from . import docker_stats
        docker_stats.start_sampler()
    except Exception:  # last line: monitoring is not worth a failed start
        pass
    yield
    upgrades.stop_watcher()
    try:
        from . import docker_stats
        docker_stats.stop_sampler()
    except Exception:  # last line: never block shutdown
        pass
    try:
        from . import events
        events.record("service", "stop", detail="shutting down")
    except Exception:  # last line: never block shutdown
        pass


app = FastAPI(title="SAST Studio", version="1.0.0", lifespan=_lifespan)


@app.exception_handler(Draining)
async def _draining(_request: Request, exc: Draining) -> JSONResponse:
    """New scans wait while an upgrade switches images; say so plainly."""
    return JSONResponse({"detail": str(exc)}, status_code=503,
                        headers={"Retry-After": "120"})


# Kept beside the gate that reads it, so the gate can be read whole.
# Endpoints that must work before anyone is logged in, plus the static assets
# needed to render the login form itself.
#: Reachable without a session. change-expired is here because the account
#: that needs it cannot sign in -- it still proves the current password.
_PUBLIC_PATHS = {"/api/health", "/api/auth/login", "/api/auth/whoami",
                 "/api/auth/policy", "/api/auth/change-expired"}


#: The app's own front-end. Served straight from the image, so the file on
#: disk changes on every deploy and the URL never does.
_APP_ASSETS = {"/", "/login", "/index.html", "/login.html",
               "/login.js", "/i18n.js", "/style.css"} | {
    f"/js/{name}.js" for name in ("core", "rules", "monitor", "scan", "report", "surface")}


@app.middleware("http")
async def _no_stale_ui(request: Request, call_next):
    """Make the browser check before reusing the UI it already has.

    Nothing set Cache-Control, so browsers fell back to their own heuristic:
    cache for some fraction of the age of the file and do not ask again. That
    is why a deploy kept needing a hard refresh -- the server had the new CSS
    and the browser never asked for it.

    `no-cache` does not mean "do not store". It means "store it, but
    revalidate before use", so the ETag that is already being sent does the
    work and an unchanged file still costs one 304 rather than a download.
    Versioned URLs would let us cache these forever, but the filenames are
    referenced from hand-written HTML, so this is the honest trade for now.
    """
    response = await call_next(request)
    if request.url.path in _APP_ASSETS:
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    return response


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
              or path == "/api/mcp/upload"  # authenticated by its upload ticket
              or path == "/login"
              # The front-end files, each by its own name: a prefix would
              # also let "/js/../index.html" through (round 49).
              or path in {"/i18n.js", "/style.css", "/login.js", "/js/core.js",
                          "/js/rules.js", "/js/monitor.js", "/js/scan.js",
                          "/js/report.js", "/js/surface.js"})
    # A state-changing request authenticated by a cookie is the CSRF case:
    # the browser attaches the cookie whoever asked for the request. A bearer
    # token is not attached automatically, so it is not affected.
    if (request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and not request.headers.get("authorization")
            and not _same_site_request(request)):
        return JSONResponse({"detail": "cross-site request refused"},
                            status_code=403)

    user = current_user(request)
    if user is not None and request.headers.get("authorization") \
            and path.startswith("/api/"):
        events.record("api", "call", actor=user.username,
                      source=_client_ip(request),
                      target=f"{request.method} {path}",
                      detail="api token")
    if public or user is not None:
        # An expired password was reported by whoami and enforced nowhere, so
        # the setting did nothing at all: the account kept working, and its
        # API tokens with it. Expiry has to bite here, for the same reason
        # the gate exists -- one forgotten route is the whole hole.
        if user is not None and not public and _expired_blocked(request, user):
            return _expiry_response(path)
        return await call_next(request)

    if path.startswith("/api/"):
        return JSONResponse({"detail": "sign in to continue"}, status_code=401)
    return RedirectResponse("/login", status_code=302)


#: The only things an account with an expired password may still reach:
#: enough to see who it is, read the rules it has to satisfy, change the
#: password, and sign out. Everything else waits until it is changed.
_EXPIRED_ALLOWED = {
    "/api/auth/whoami",
    "/api/auth/password",
    "/api/auth/policy",
    "/api/auth/logout",
    "/api/auth/login",
}


def _expired_blocked(request: Request, user) -> bool:
    from . import accounts

    if request.url.path in _EXPIRED_ALLOWED:
        return False
    try:
        return accounts.password_expired(user)
    except (sqlite3.Error, OSError, ValueError):  # never lock everyone out over a read
        return False


def _expiry_response(path: str):
    if path.startswith("/api/") or path == "/mcp":
        # 403, not 401: the credentials are right, they are just too old.
        # A distinct code so a client can tell "sign in" from "change it".
        return JSONResponse(
            {"detail": "password expired; change it to continue",
             "reason": "password_expired"}, status_code=403)
    return RedirectResponse("/login?expired=1", status_code=302)


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


# The API, area by area (round 49: one file each, small enough for a
# scanner to read whole). Before the static mount, which takes the rest.
app.include_router(accounts.router)
app.include_router(mcp_http.router)
app.include_router(ops.router)
app.include_router(scans.router)

app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
