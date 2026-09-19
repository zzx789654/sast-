"""FastAPI application: REST API + static single-page UI for SAST Studio."""
from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import csv
import io
import json
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
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


@app.get("/api/system")
async def system_status() -> dict:
    """Docker container performance for the Monitor tab."""
    from . import docker_stats
    return {"docker": await run_in_threadpool(docker_stats.collect)}


@app.get("/api/admin/status")
async def admin_status() -> dict:
    """State of the operator panel: any job running, and what can be updated."""
    from . import admin
    return admin.status()


@app.post("/api/admin/update-tools")
async def admin_update_tools(tools: Optional[str] = Form(None)) -> JSONResponse:
    """Update the scanners that can be updated in place.

    Returns immediately; the Monitor tab polls /api/admin/status for progress.
    """
    from . import admin
    wanted = [t.strip() for t in (tools or "").split(",") if t.strip()]
    result = admin.start_update(wanted)
    return JSONResponse(result, status_code=202 if result.get("started") else 409)


@app.post("/api/admin/restart")
async def admin_restart() -> JSONResponse:
    """Restart the application process so updated scanners are picked up."""
    from . import admin
    result = admin.restart_app()
    return JSONResponse(result, status_code=202 if result.get("restarting") else 409)


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
    """The fixed rule used to judge every scan (shown in the UI, not chosen)."""
    from .policies import RULE_CATALOG
    return {"rules": RULE_CATALOG}


@app.post("/api/scans/{job_id}/review")
async def review_scan(
    job_id: str,
    decision: str = Form(...),
    reviewer: str = Form(...),
    note: str = Form(...),
) -> dict:
    """Approve or reject a scan paused for manual review."""
    if decision not in {"approve", "reject"}:
        raise HTTPException(400, "decision must be approve or reject")
    if not reviewer.strip() or not note.strip():
        raise HTTPException(400, "reviewer and note are required")
    if not manager.review(job_id, decision, reviewer.strip(), note.strip()):
        raise HTTPException(409, "scan is not awaiting policy review")
    return {"id": job_id, "status": manager.get(job_id).status.value}


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
    file: Optional[UploadFile] = File(None),
) -> JSONResponse:
    requested = [t.strip() for t in tools.split(",") if t.strip()]

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
        job = manager.new_job(target, requested)
        manager.start(job.id, {"kind": "git", "url": git_url}, confirm=want_confirm)

    elif source_kind == "path":
        if not config.ALLOW_LOCAL_PATH:
            raise HTTPException(403, "local path scanning is disabled")
        if not local_path:
            raise HTTPException(400, "local_path is required for source_kind=path")
        target = ScanTarget(kind="path", display=local_path)
        job = manager.new_job(target, requested)
        manager.start(job.id, {"kind": "path", "path": local_path}, confirm=False)

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
async def export_scan_csv(job_id: str) -> Response:
    """Download one scan's findings as CSV (stdlib csv, no extra dependency)."""
    job = manager.get(job_id)
    if job is None:
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
