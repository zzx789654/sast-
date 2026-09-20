"""MCP server: let an assistant run a scan and read the findings.

Streamable HTTP transport, one endpoint, JSON responses only. The spec allows
a server to answer a request with either `application/json` or an SSE stream;
plain JSON is chosen because a scan is a request/response, not a conversation,
and an SSE stream here would be a pipe that only ever carries one message.

No session state, so `Mcp-Session-Id` is never issued: every call carries its
own bearer token and the scan id it is asking about. That removes a class of
bug (a session outliving the token that created it) and means a restart cannot
strand a client mid-conversation.

Authentication is the same API token the REST endpoints take, so a scan
started from an assistant is attributable to the person whose token it is.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from .config import config
from .models import ScanTarget
from .orchestrator import manager
from .source import SourceError, validate_git_url

# The version we implement. A client asking for something else still gets this
# back; the spec has the client decide whether it can live with the answer.
PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "sast-studio", "version": "1.0.0"}

# JSON-RPC error codes from the spec.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

TOOLS = [
    {
        "name": "scan_git_repository",
        "title": "Scan a git repository",
        "description": (
            "Run the security scanners over a public git repository and return "
            "the findings. Clones the repository, runs the selected tools, and "
            "reports a verdict with every finding. Only http and https URLs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "git_url": {
                    "type": "string",
                    "description": "http(s) URL of the repository to scan.",
                },
                "tools": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Which scanners to run. Omit for all of them: semgrep, "
                        "bearer, trivy, npm_audit, osv_scanner, gitleaks."
                    ),
                },
            },
            "required": ["git_url"],
        },
    },
    {
        "name": "get_scan_result",
        "title": "Read a scan's result",
        "description": (
            "Fetch the current state of a scan by id. A scan runs in the "
            "background, so poll this until status is done, blocked, "
            "policy_review or error."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Id from scan_git_repository."},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Only return findings at or above this severity.",
                },
            },
            "required": ["scan_id"],
        },
    },
    {
        "name": "list_scanners",
        "title": "List the scanners",
        "description": "Which scanners are installed, and what each one looks at.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


def _result(req_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _text(payload: Any) -> dict:
    """A tool result. Text, because that is what every client can render."""
    body = payload if isinstance(payload, str) else json.dumps(
        payload, indent=2, ensure_ascii=False)
    return {"content": [{"type": "text", "text": body}]}


def handle(message: dict, user) -> Optional[dict]:
    """Handle one JSON-RPC message. None means "nothing to send back"."""
    if message.get("jsonrpc") != "2.0":
        return _error(message.get("id"), INVALID_REQUEST,
                      "jsonrpc must be \"2.0\"")

    method = message.get("method")
    req_id = message.get("id")

    # A notification has no id and takes no reply.
    if req_id is None:
        return None

    if method == "initialize":
        return _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        })

    if method == "tools/list":
        return _result(req_id, {"tools": TOOLS})

    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            return _result(req_id, _call_tool(name, args, user))
        except ValueError as exc:
            # A bad argument is the caller's problem, and saying which one
            # saves a round trip.
            return _result(req_id, {
                "content": [{"type": "text", "text": str(exc)}],
                "isError": True,
            })
        except Exception as exc:  # noqa: BLE001
            return _error(req_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")

    if method == "ping":
        return _result(req_id, {})

    return _error(req_id, METHOD_NOT_FOUND, f"unknown method '{method}'")


def _call_tool(name: str, args: dict, user) -> dict:
    if name == "list_scanners":
        from .adapters import ADAPTERS
        return _text([
            {"name": a.name, "kind": a.kind.value, "looks_at": a.requirement}
            for a in ADAPTERS
        ])

    if name == "scan_git_repository":
        return _start_git_scan(args, user)

    if name == "get_scan_result":
        return _read_scan(args)

    raise ValueError(f"unknown tool '{name}'")


def _start_git_scan(args: dict, user) -> dict:
    from .adapters import ADAPTERS

    git_url = (args.get("git_url") or "").strip()
    if not git_url:
        raise ValueError("git_url is required")
    try:
        # The same validation the web form uses: http/https only, no local
        # paths, no ssh. An assistant is not a more trusted caller.
        validate_git_url(git_url)
    except SourceError as exc:
        raise ValueError(str(exc)) from exc

    known = {a.name for a in ADAPTERS}
    requested = [t for t in (args.get("tools") or []) if t in known]
    if not requested:
        requested = sorted(known)

    target = ScanTarget(kind="git", display=git_url)
    job = manager.new_job(target, requested)
    # confirm=False: an assistant cannot click a confirmation dialog, and the
    # dialog exists to let a person review the inventory first.
    manager.start(job.id, {"kind": "git", "url": git_url}, confirm=False)

    return _text({
        "scan_id": job.id,
        "status": job.status.value,
        "tools": requested,
        "started_by": getattr(user, "username", None),
        "next": "poll get_scan_result with this scan_id until status is done, "
                "blocked, policy_review or error",
    })


def _read_scan(args: dict) -> dict:
    scan_id = (args.get("scan_id") or "").strip()
    if not scan_id:
        raise ValueError("scan_id is required")
    job = manager.get(scan_id)
    if job is None:
        raise ValueError(f"no scan with id '{scan_id}'")

    floor = (args.get("severity") or "info").lower()
    if floor not in _SEVERITY_ORDER:
        raise ValueError(f"severity must be one of {_SEVERITY_ORDER}")
    min_rank = _SEVERITY_ORDER.index(floor)

    findings = []
    for result in job.results.values():
        for f in result.findings:
            if _SEVERITY_ORDER.index(f.severity.value) < min_rank:
                continue
            findings.append({
                "tool": f.tool,
                "severity": f.severity.value,
                "title": f.title,
                "file": f.file,
                "line": f.start_line,
                "cwe": f.cwe,
                "rule_id": f.rule_id,
                # The code that matched, so the caller can judge the finding
                # rather than trusting the description. Scanners report
                # patterns; whether a pattern is a bug here is a judgement.
                "code": (f.extra or {}).get("snippet") or "",
            })

    evaluation = job.policy_evaluation or {}
    return _text({
        "scan_id": job.id,
        "status": job.status.value,
        # Why it failed, if it did. Without this a caller sees "error" and has
        # no way to tell a bad URL from a scanner that fell over.
        "error": job.error or None,
        "target": job.target.display,
        "progress": job.progress,
        "verdict": evaluation.get("decision"),
        "summary": job.summary,
        "tools": {n: {"status": r.status.value, "findings": len(r.findings),
                      "error": r.error or None}
                  for n, r in job.results.items()},
        "findings": findings,
        "note": ("a verdict labels this scan; it does not block anything. "
                 "Scanners report patterns, so check the code before acting."),
    })
