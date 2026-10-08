"""Health, the monitor tab (upgrades, Docker limits, logs, tools) and rules."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .. import events
from ..adapters import ADAPTERS
from ..config import config
from ..web import (SEMGREP_RULESETS, _client_ip, _owner_name, _require_upgrade_admin,
                   require_admin, require_user)


router = APIRouter()


@router.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}


@router.get("/api/system")
async def system_status() -> dict:
    """Docker container performance for the Monitor tab."""
    from .. import docker_stats
    return {"docker": await run_in_threadpool(docker_stats.collect)}


@router.get("/api/admin/upgrades")
async def admin_upgrades(request: Request) -> dict:
    """The upgrade panel: the prepared candidate, the last check, the events.
    Reads files only: checking for new versions is the host's job, every
    morning, and nothing here can ask it to check (round 48)."""
    from .. import upgrades

    _require_upgrade_admin(request)
    return upgrades.status()


@router.post("/api/admin/upgrades/apply")
async def admin_upgrade_apply(request: Request,
                              candidate: Optional[str] = Form(None)) -> JSONResponse:
    """Approve the candidate the host prepared and accepted."""
    from .. import upgrades

    _require_upgrade_admin(request)
    result = upgrades.request_apply((candidate or "").strip(), _owner_name(request) or "")
    events.record("service", "upgrade", level="info" if result["started"] else "warn",
                  actor=_owner_name(request), source=_client_ip(request),
                  detail=f"apply {candidate} requested" if result["started"]
                  else f"apply refused: {result['reason']}")
    return JSONResponse(result, status_code=202 if result["started"] else 409)


@router.get("/api/docker/limits")
async def get_docker_limits(request: Request) -> dict:
    """Current container limits, usage and host capacity.

    Administrators only: it reports the host's total memory and cpu count,
    which is infrastructure detail rather than something every account needs.
    """
    from .. import docker_stats

    require_admin(request)
    return await run_in_threadpool(docker_stats.limits)


@router.post("/api/docker/limits/preview")
async def preview_docker_limits(request: Request,
                                spec: str = Form(...)) -> dict:
    """Turn the wanted limits into a compose fragment. Changes nothing.

    Deliberately a preview and not an apply. The container can reach
    /containers/update through the mounted socket, but using it would give
    this app write access to every container on the host, and compose would
    overwrite the result on the next deploy anyway.
    """
    from .. import docker_stats

    require_admin(request)
    try:
        wanted = json.loads(spec)
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, f"spec: {exc}") from exc

    current = await run_in_threadpool(docker_stats.limits)
    try:
        fragment = docker_stats.compose_fragment(
            wanted, current.get("host_memory"), current.get("host_cpus"))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    events.record("service", "limits", actor=_owner_name(request),
                  source=_client_ip(request),
                  detail="previewed container resource limits")
    return {"fragment": fragment}


@router.get("/api/logs")
async def get_logs(request: Request,
                   categories: str = "", level: str = "", actor: str = "",
                   text: str = "", since: str = "",
                   limit: int = 200, offset: int = 0) -> dict:
    """The activity log, filtered.

    Administrators see everything. Everyone else sees only their own rows:
    the log names who scanned what and which address called the API, which is
    an account's activity, not shared information.
    """
    user = require_user(request)
    if user is None:
        raise HTTPException(400, "authentication is disabled")
    is_admin = bool(user.is_admin)
    wanted = [c.strip() for c in categories.split(",") if c.strip()]
    result = await run_in_threadpool(
        events.query,
        categories=wanted, level=level,
        actor=actor if is_admin else (user.username if user else "\x00"),
        text=text, since=since, limit=limit, offset=offset)
    result["scope"] = "all" if is_admin else "mine"
    if is_admin:
        result["counts"] = await run_in_threadpool(events.counts_by_category)
    return result


@router.post("/api/logs/retention")
async def set_log_retention(request: Request, days: str = Form(...)) -> dict:
    """How many days of log to keep. Older rows are deleted immediately."""
    require_admin(request)
    try:
        kept = await run_in_threadpool(events.set_retention_days, days)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    events.record("service", "retention", level="warn",
                  actor=_owner_name(request), source=_client_ip(request),
                  detail=f"log retention set to {kept} days")
    return {"retention_days": kept}


@router.get("/api/rulesets")
async def list_rulesets() -> dict:
    """Published rulesets the scan form can offer, plus the current default."""
    return {"semgrep": SEMGREP_RULESETS,
            "default": config.SEMGREP_RULESETS}


@router.get("/api/rules")
async def list_custom_rules(engine: Optional[str] = None) -> dict:
    """Every rule the scan form can offer, built-in templates included."""
    from .. import rules as rules_mod
    return {"rules": rules_mod.list_rules(engine),
            "engines": list(rules_mod.ENGINES)}


@router.get("/api/rules/{engine}/{name}")
async def read_custom_rule(engine: str, name: str) -> dict:
    from .. import rules as rules_mod
    try:
        rule = rules_mod.read_rule(engine, name)
    except FileNotFoundError:
        raise HTTPException(404, "rule not found") from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"engine": rule.engine, "name": rule.name,
            "builtin": rule.builtin, "content": rule.content}


@router.post("/api/rules/validate")
async def validate_custom_rule(request: Request, engine: str = Form(...),
                               content: str = Form(...)) -> dict:
    """Ask the scanner whether this rule compiles, without saving it."""
    from .. import rules as rules_mod

    # Validating runs the scanner, so this spends CPU on the host.
    require_user(request)
    return await run_in_threadpool(rules_mod.validate_rule, engine, content)


@router.post("/api/rules/{engine}/{name}")
async def save_custom_rule(request: Request, engine: str, name: str,
                           content: str = Form(...)) -> JSONResponse:
    """Save a rule. It is validated first, so a broken rule is never stored."""
    from .. import rules as rules_mod

    # A saved rule is executed by a scanner on every later scan, so writing
    # one changes what everybody else's scans run.
    require_admin(request)
    try:
        saved = await run_in_threadpool(rules_mod.save_rule, engine, name, content)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return JSONResponse(saved, status_code=201)


@router.delete("/api/rules/{engine}/{name}")
async def delete_custom_rule(request: Request, engine: str, name: str) -> dict:
    from .. import rules as rules_mod

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


@router.get("/api/tools")
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

    # A scanner's version only changes when an upgrade is applied, and that
    # recreates the container -- and this cache with it. Re-probing on every
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


@router.get("/api/policies")
async def policies() -> dict:
    """The fixed rule used to judge every scan (shown in the UI, not chosen)."""
    from ..policies import RULE_CATALOG
    return {"rules": RULE_CATALOG}
