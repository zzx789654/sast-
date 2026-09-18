"""FastAPI application: REST API + static single-page UI for SAST Studio."""
from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import json
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from .adapters import ADAPTERS
from .config import config
from .inventory import inventory
from .models import ScanTarget
from .orchestrator import manager
from .policies import customize_policy, get_policy, list_policies
from .source import SourceError, resolve_local_path, validate_git_url

app = FastAPI(title="SAST Studio", version="1.0.0")

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/api/system")
async def system_status() -> dict:
    """Docker container performance for the Monitor tab."""
    from . import docker_stats
    return {"docker": await run_in_threadpool(docker_stats.collect)}


@app.get("/api/tools")
async def list_tools() -> dict:
    """Availability + metadata for every integrated tool."""
    def probe_all() -> list[dict]:
        out = []
        for adapter in ADAPTERS:
            available, version = adapter.probe()
            out.append({
                "name": adapter.name,
                "kind": adapter.kind.value,
                "available": available,
                "version": version,
                "install_hint": adapter.install_hint,
                "languages": adapter.languages,
                "requirement": adapter.requirement,
            })
        return out

    tools = await run_in_threadpool(probe_all)
    return {
        "tools": tools,
        "config": {
            "allow_local_path": config.ALLOW_LOCAL_PATH,
            "allowed_git_schemes": sorted(config.ALLOWED_GIT_SCHEMES),
            "max_upload_bytes": config.MAX_UPLOAD_BYTES,
        },
    }


@app.get("/api/policies")
async def policies() -> dict:
    """Return built-in policy rules and selectable templates."""
    return list_policies()


@app.post("/api/scans/{job_id}/review")
async def review_scan(
    job_id: str,
    decision: str = Form(...),
    reviewer: str = Form(...),
    note: str = Form(...),
) -> dict:
    """Approve or reject a scan paused by the High-finding policy gate."""
    if decision not in {"approve", "reject"}:
        raise HTTPException(400, "decision must be approve or reject")
    if not reviewer.strip() or not note.strip():
        raise HTTPException(400, "reviewer and note are required")
    if not manager.review(job_id, decision, reviewer.strip(), note.strip()):
        raise HTTPException(409, "scan is not awaiting policy review")
    return {"id": job_id, "status": manager.get(job_id).status.value}


@app.post("/api/scans/{job_id}/exceptions")
async def add_scan_exception(
    job_id: str,
    tool: str = Form(...),
    rule_id: str = Form(""),
    file: str = Form(""),
    start_line: Optional[int] = Form(None),
    owner: str = Form(...),
    reason: str = Form(...),
    expires_at: str = Form(...),
) -> dict:
    """Record a time-limited false-positive exception for one finding."""
    job = manager.get(job_id)
    if job is None:
        raise HTTPException(404, "scan not found")
    if not owner.strip() or not reason.strip():
        raise HTTPException(400, "owner and reason are required")
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise HTTPException(400, "expires_at must be an ISO-8601 date/time") from exc
    if expiry <= datetime.now(timezone.utc):
        raise HTTPException(400, "expires_at must be in the future")
    matches = [
        f for result in job.results.values() for f in result.findings
        if f.tool == tool and f.rule_id == rule_id and f.file == file
        and f.start_line == start_line
    ]
    if not matches:
        raise HTTPException(404, "finding not found")
    # Owner/reason/expiry are always recorded so every exception stays
    # auditable; the policy flag only governs whether they are enforced.
    exception = {
        "tool": tool, "rule_id": rule_id, "file": file,
        "start_line": start_line, "owner": owner.strip(),
        "reason": reason.strip(), "expires_at": expiry.isoformat(),
    }
    manager.add_exception(job_id, exception)
    return {"id": job_id, "status": manager.get(job_id).status.value,
            "exception": exception}


@app.post("/api/inspect")
async def inspect_project(
    source_kind: str = Form(...),
    local_path: Optional[str] = Form(None),
) -> dict:
    """Pre-scan look at a project: file/size/language inventory plus, for each
    tool, whether it applies to this project and why not. Available for local
    paths only (uploads/git aren't on disk until a scan starts)."""
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
    source_kind: str = Form(...),
    tools: str = Form(""),
    git_url: Optional[str] = Form(None),
    local_path: Optional[str] = Form(None),
    confirm: Optional[str] = Form(None),
    policy: str = Form("standard"),
    policy_rules: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
) -> JSONResponse:
    requested = [t.strip() for t in tools.split(",") if t.strip()]
    try:
        selected_policy = get_policy(policy)
        if policy_rules:
            selected_policy = customize_policy(policy, json.loads(policy_rules))
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, str(exc)) from exc

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
        job = manager.new_job(target, requested, selected_policy)
        manager.start(job.id, {"kind": "git", "url": git_url}, confirm=want_confirm)

    elif source_kind == "path":
        if not config.ALLOW_LOCAL_PATH:
            raise HTTPException(403, "local path scanning is disabled")
        if not local_path:
            raise HTTPException(400, "local_path is required for source_kind=path")
        target = ScanTarget(kind="path", display=local_path)
        job = manager.new_job(target, requested, selected_policy)
        manager.start(job.id, {"kind": "path", "path": local_path}, confirm=False)

    elif source_kind == "upload":
        if file is None:
            raise HTTPException(400, "file is required for source_kind=upload")
        target = ScanTarget(kind="upload", display=file.filename or "upload.zip")
        job = manager.new_job(target, requested, selected_policy)
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
async def list_scans() -> dict:
    jobs = manager.list_jobs()
    return {
        "jobs": [
            {
                "id": j.id,
                "status": j.status.value,
                "target": j.target.model_dump(),
                "created_at": j.created_at,
                "summary": j.summary,
            }
            for j in jobs
        ]
    }


@app.get("/api/scans/{job_id}")
async def get_scan(job_id: str) -> dict:
    job = manager.get(job_id)
    if job is None:
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
@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
