"""Inspecting a project, scans, their exports, and triage."""
from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from .. import events
from ..adapters import ADAPTERS
from ..attack_surface import NOTE as ATTACK_SURFACE_NOTE
from ..config import config
from ..inventory import inventory
from ..models import JobStatus, ScanTarget
from ..orchestrator import manager
from ..source import SourceError, resolve_local_path, validate_git_url
from ..web import (SEMGREP_RULESETS, _client_ip, _may_see_scan, _owner_name, _parse_bool,
                   require_admin, require_user)


router = APIRouter()


@router.post("/api/inspect")
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


@router.post("/api/scans")
async def create_scan(
    request: Request,
    source_kind: str = Form(...),
    tools: str = Form(""),
    git_url: Optional[str] = Form(None),
    local_path: Optional[str] = Form(None),
    confirm: Optional[str] = Form(None),
    custom_rules: Optional[str] = Form(None),
    rulesets: Optional[str] = Form(None),
    full_inventory: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
) -> JSONResponse:
    requested = [t.strip() for t in tools.split(",") if t.strip()]
    # The deployment-wide setting is the default; a scan may turn it on for
    # itself. It cannot be turned off below the deployment's own choice,
    # because that choice is the operator's.
    want_inventory = (config.OSV_FULL_INVENTORY
                      or _parse_bool(full_inventory, False))
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
        job.full_inventory = want_inventory
        manager.start(job.id, {"kind": "git", "url": git_url}, confirm=want_confirm)

    elif source_kind == "path":
        if not config.ALLOW_LOCAL_PATH:
            raise HTTPException(403, "local path scanning is disabled")
        if not local_path:
            raise HTTPException(400, "local_path is required for source_kind=path")
        target = ScanTarget(kind="path", display=local_path)
        job = manager.new_job(target, requested, chosen_rules, chosen_sets,
                              owner=_owner_name(request))
        job.full_inventory = want_inventory
        manager.start(job.id, {"kind": "path", "path": local_path}, confirm=False)

    elif source_kind == "upload":
        if file is None:
            raise HTTPException(400, "file is required for source_kind=upload")
        target = ScanTarget(kind="upload", display=file.filename or "upload.zip")
        job = manager.new_job(target, requested, chosen_rules, chosen_sets,
                              owner=_owner_name(request))
        job.full_inventory = want_inventory
        zip_path = manager.job_dir(job.id) / "upload.zip"
        try:
            await _save_upload(file, zip_path)
        except HTTPException:
            raise
        manager.start(job.id, {"kind": "upload", "zip_path": str(zip_path)},
                      confirm=want_confirm)

    else:
        raise HTTPException(400, f"unknown source_kind: {source_kind}")

    # The target and the moment, which is what "which scan was that?" needs.
    events.record("scan", "start", actor=_owner_name(request),
                  source=_client_ip(request), target=target.display,
                  detail=f"{source_kind}: {', '.join(requested) or 'all tools'}")
    return JSONResponse({"id": job.id, "status": job.status.value}, status_code=201)


@router.post("/api/scans/{job_id}/confirm")
async def confirm_scan(job_id: str) -> dict:
    if manager.get(job_id) is None:
        raise HTTPException(404, "scan not found")
    if not manager.confirm(job_id):
        raise HTTPException(409, "scan is not awaiting confirmation")
    return {"id": job_id, "status": "running"}


@router.post("/api/scans/{job_id}/cancel")
async def cancel_scan(job_id: str) -> dict:
    if manager.get(job_id) is None:
        raise HTTPException(404, "scan not found")
    if not manager.cancel(job_id):
        raise HTTPException(409, "scan is not awaiting confirmation")
    return {"id": job_id, "status": "cancelled"}


@router.get("/api/scans")
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


@router.get("/api/scans/{job_id}/export.csv")
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


@router.get("/api/triage")
async def list_triage(request: Request) -> dict:
    """Every recorded judgement. Shared, not per-browser.

    These used to live in localStorage, which was right while they were only
    notes. Now that a mark can change a verdict it has to be recorded once,
    for everyone, with the name of whoever made it.
    """
    from .. import accounts

    require_user(request)
    return {"triage": accounts.get_triage()}


@router.post("/api/triage")
async def set_triage(request: Request,
                     finding_key: str = Form(...),
                     verdict: str = Form(""),
                     note: str = Form("")) -> dict:
    """Mark a finding, or clear the mark with an empty verdict."""
    from .. import accounts

    user = require_user(request)
    who = user.username if user is not None else ""
    try:
        return {"ok": True,
                "mark": accounts.set_triage(finding_key, verdict, who, note)}
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/scans/{job_id}/reevaluate")
async def reevaluate_scan(request: Request, job_id: str) -> dict:
    """Judge an existing scan again against the current marks.

    Without this a mark made while reading a report does nothing until the
    next scan, which is exactly when somebody wants to see its effect.
    """
    from .. import accounts
    from ..policies import evaluate_policy

    job = manager.get(job_id)
    if job is None or not _may_see_scan(request, job):
        raise HTTPException(404, "scan not found")

    job.policy_evaluation = evaluate_policy(job, accounts.get_triage())
    decision = job.policy_evaluation["decision"]
    # The status follows the verdict, or the badge and the verdict disagree.
    if job.status in (JobStatus.DONE, JobStatus.BLOCKED, JobStatus.POLICY_REVIEW):
        job.status = {"blocked": JobStatus.BLOCKED,
                      "manual_review": JobStatus.POLICY_REVIEW,
                      "passed": JobStatus.DONE}[decision]
    return job.policy_evaluation


@router.get("/api/scans/{job_id}/packages.csv")
async def export_packages_csv(request: Request, job_id: str) -> Response:
    """The package list with licences, for whoever has to review them.

    A separate file from the findings export: this is an inventory, and the
    person who needs it is usually not the person reading the findings.
    """
    job = manager.get(job_id)
    if job is None or not _may_see_scan(request, job):
        raise HTTPException(404, "scan not found")

    columns = ["scan_id", "scanned_at", "target", "package", "version",
               "ecosystem", "licenses", "category", "needs_attention",
               "declared_in"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for pkg in (job.sbom or {}).get("packages", []):
        writer.writerow({k: _csv_safe(v) for k, v in {
            "scan_id": job.id,
            "scanned_at": job.finished_at or job.created_at,
            "target": job.target.display,
            "package": pkg.get("name", ""),
            "version": pkg.get("version", ""),
            "ecosystem": pkg.get("ecosystem", ""),
            # Several licences is normal ("MIT OR Apache-2.0"); keep them all.
            "licenses": "; ".join(pkg.get("licenses") or []) or "unknown",
            "category": pkg.get("category", ""),
            "needs_attention": "yes" if pkg.get("attention") else "",
            "declared_in": pkg.get("source", ""),
        }.items()})

    body = "\ufeff" + buf.getvalue()
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="sast-packages-{job.id}.csv"'},
    )


@router.get("/api/scans/{job_id}/attack-surface.json")
async def export_attack_surface(request: Request, job_id: str) -> JSONResponse:
    """The attack surface map as a file, for whoever keeps the inventory."""
    job = manager.get(job_id)
    if job is None or not _may_see_scan(request, job):
        raise HTTPException(404, "scan not found")
    body = {
        "scan_id": job.id,
        "scanned_at": job.finished_at or job.created_at,
        "target": job.target.display,
        "note": ATTACK_SURFACE_NOTE,
        **(job.attack_surface or {}),
    }
    return JSONResponse(body, headers={
        "Content-Disposition":
            f'attachment; filename="sast-attack-surface-{job.id}.json"'})


@router.get("/api/scans/{job_id}")
async def get_scan(request: Request, job_id: str) -> dict:
    job = manager.get(job_id)
    if job is None or not _may_see_scan(request, job):
        raise HTTPException(404, "scan not found")
    return job.model_dump()


async def _save_upload(file: UploadFile, dest: Path) -> None:
    """Stream the upload to disk with a hard size cap (defence against bombs)."""
    written = 0
    # Created new and private, and a link at that name is refused rather
    # than written through.
    # O_NOFOLLOW is POSIX; the app runs on Linux, the tests also on Windows.
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as out:
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
