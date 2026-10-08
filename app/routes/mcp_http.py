"""The MCP endpoint, its upload, and the client settings it hands out."""
from __future__ import annotations

import os
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from .. import events
from ..config import config
from ..models import ScanTarget
from ..orchestrator import manager
from ..web import _client_ip, _origin_allowed, _public_origin, current_user, require_user


router = APIRouter()


# ------------------------------------------------------------------- MCP
# One endpoint, Streamable HTTP. A token identifies the caller, so a scan an
# assistant starts belongs to the person whose token it used.
@router.post("/mcp")
async def mcp_endpoint(request: Request) -> Response:
    from .. import mcp

    # The spec requires validating Origin: without it a web page could drive
    # this endpoint from a victim's browser (DNS rebinding). A browser always
    # sends Origin on a cross-origin request; a CLI or an assistant sends none,
    # which is why absent is allowed and mismatched is not.
    origin = request.headers.get("origin")
    if origin and not _origin_allowed(origin, request):
        events.record("api", "mcp", level="warn", source=_client_ip(request),
                      target="/mcp", detail=f"origin refused: {origin[:80]}")
        raise HTTPException(403, "origin not allowed")

    user = current_user(request)
    events.record("api", "mcp", actor=(user.username if user else ""),
                  source=_client_ip(request), target="/mcp",
                  detail="authenticated" if user else "unauthenticated")
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
    except ClientDisconnect:
        return Response(status_code=400)         # nobody left to answer
    except ValueError:  # not JSON, or not UTF-8
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None,
             "error": {"code": mcp.PARSE_ERROR, "message": "invalid JSON"}},
            status_code=400)

    # A batch is a list. Notifications inside it produce no reply, which is
    # why the responses are filtered rather than mapped one-to-one.
    # Where this deployment answers, for tools that tell the caller where to
    # send something. The same guarded origin the settings page hands out.
    scheme, host = _public_origin(request)
    base_url = f"{scheme}://{host}"

    if isinstance(message, list):
        replies = [r for r in (await run_in_threadpool(mcp.handle, m, user, base_url)
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

    reply = await run_in_threadpool(mcp.handle, message, user, base_url)
    if reply is None:
        # A notification: accepted, nothing to say back.
        return Response(status_code=202)
    return JSONResponse(reply)


@router.get("/mcp")
async def mcp_stream() -> Response:
    """No server-initiated stream.

    The spec lets a server answer GET with 405 when it never pushes messages
    to the client, which is our case: every answer belongs to a request.
    """
    return Response(status_code=405, headers={"Allow": "POST"})


#: An upload in progress is minutes at most; anything older in _incoming was
#: left by a process that stopped mid-upload and nothing else will remove it.
_INCOMING_MAX_AGE = 3600


def _drop_stale_incoming(incoming: Path) -> None:
    cutoff = time.time() - _INCOMING_MAX_AGE
    for leftover in incoming.glob("*.zip"):
        try:
            if leftover.stat().st_mtime < cutoff:
                leftover.unlink()
        except OSError:
            pass    # another upload's cleanup got there first


@router.put("/api/mcp/upload")
async def mcp_upload(request: Request) -> JSONResponse:
    """Receive the ZIP for a ticket issued by the create_upload_scan tool.

    The ticket rides in the Authorization header, not the URL, so it never
    lands in an access log. It works once: claimed before the body is read,
    so a second upload with it fails even if the first one is still running.
    """
    from .. import accounts, mcp

    origin = request.headers.get("origin")
    if origin and not _origin_allowed(origin, request):
        raise HTTPException(403, "origin not allowed")

    auth = request.headers.get("authorization", "")
    ticket = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    grant = mcp.claim_upload_ticket(ticket)
    if grant is None:
        events.record("api", "mcp-upload", level="warn", source=_client_ip(request),
                      target="/api/mcp/upload", detail="invalid or used ticket")
        return JSONResponse(
            {"detail": "upload ticket is missing, expired or already used; "
                       "call create_upload_scan for a new one"},
            status_code=401, headers={"WWW-Authenticate": "Bearer"})

    if config.REQUIRE_AUTH:
        # The account may have been disabled, or its password may have expired,
        # since the ticket was issued. The ticket carries its rights, not more.
        user = await run_in_threadpool(accounts.get_user, grant.username or "")
        if user is None or user.disabled:
            return JSONResponse({"detail": "the account for this ticket is not active"},
                                status_code=401)
        if await run_in_threadpool(accounts.password_expired, user):
            return JSONResponse({"detail": "password expired; change it to continue",
                                 "reason": "password_expired"}, status_code=403)

    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(413, "upload exceeds size limit")

    # Written aside first, so a refused upload leaves no half-made job behind.
    incoming = config.WORKSPACE_DIR / "_incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    _drop_stale_incoming(incoming)
    tmp = incoming / f"{os.urandom(8).hex()}.zip"
    written = 0
    try:
        with open(tmp, "wb") as out:
            async for chunk in request.stream():
                written += len(chunk)
                if written > config.MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "upload exceeds size limit")
                out.write(chunk)
        if written == 0:
            raise HTTPException(400, "empty upload; send the ZIP archive as the body")
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    target = ScanTarget(kind="upload", display=grant.filename)
    try:
        job = manager.new_job(target, grant.tools, owner=grant.username)
        zip_path = manager.job_dir(job.id) / "upload.zip"
        os.replace(tmp, zip_path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    # confirm=False, as for git scans from MCP: nobody is there to click it.
    manager.start(job.id, {"kind": "upload", "zip_path": str(zip_path)},
                  confirm=False)

    events.record("scan", "start", actor=grant.username or "",
                  source=_client_ip(request), target=target.display,
                  detail=f"mcp upload: {', '.join(grant.tools)}")
    return JSONResponse({
        "scan_id": job.id,
        "status": job.status.value,
        "tools": grant.tools,
        "next": "poll get_scan_result with this scan_id until status is done, "
                "blocked, policy_review or error",
    }, status_code=201)


@router.get("/api/mcp/config")
async def mcp_config(request: Request) -> dict:
    """A ready-to-paste MCP client entry for this deployment.

    The token is left as a placeholder: it is shown once at creation and
    handing it out again from an endpoint would undo that.
    """
    require_user(request)
    scheme, host = _public_origin(request)
    from .. import mcp
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
