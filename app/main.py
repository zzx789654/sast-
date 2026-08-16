"""FastAPI application: REST API + static single-page UI for SAST Studio."""
from __future__ import annotations

from pathlib import Path
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
from .source import SourceError, resolve_local_path, validate_git_url

app = FastAPI(title="SAST Studio", version="1.0.0")

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}


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
    file: Optional[UploadFile] = File(None),
) -> JSONResponse:
    requested = [t.strip() for t in tools.split(",") if t.strip()]

    if source_kind == "git":
        if not git_url:
            raise HTTPException(400, "git_url is required for source_kind=git")
        try:
            validate_git_url(git_url)
        except SourceError as exc:
            raise HTTPException(400, str(exc)) from exc
        target = ScanTarget(kind="git", display=git_url)
        job = manager.new_job(target, requested)
        manager.start(job.id, {"kind": "git", "url": git_url})

    elif source_kind == "path":
        if not config.ALLOW_LOCAL_PATH:
            raise HTTPException(403, "local path scanning is disabled")
        if not local_path:
            raise HTTPException(400, "local_path is required for source_kind=path")
        target = ScanTarget(kind="path", display=local_path)
        job = manager.new_job(target, requested)
        manager.start(job.id, {"kind": "path", "path": local_path})

    elif source_kind == "upload":
        if file is None:
            raise HTTPException(400, "file is required for source_kind=upload")
        target = ScanTarget(kind="upload", display=file.filename or "upload.zip")
        job = manager.new_job(target, requested)
        zip_path = manager.job_dir(job.id) / "upload.zip"
        try:
            await _save_upload(file, zip_path)
        except HTTPException:
            raise
        manager.start(job.id, {"kind": "upload", "zip_path": str(zip_path)})

    else:
        raise HTTPException(400, f"unknown source_kind: {source_kind}")

    return JSONResponse({"id": job.id, "status": job.status.value}, status_code=201)


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
