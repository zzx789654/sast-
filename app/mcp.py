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

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass
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

#: Where create_upload_scan sends the archive.
UPLOAD_PATH = "/api/mcp/upload"
#: A ticket is for "upload the thing you are about to zip", not for later.
UPLOAD_TICKET_TTL = 600
#: Unused tickets one account may hold, so a loop cannot grow the table.
UPLOAD_TICKETS_PER_USER = 5
#: Unused tickets in all. Without accounts every caller is anonymous, and a
#: per-account cap would be one shared bucket anyone could empty.
UPLOAD_TICKETS_TOTAL = 50
#: Distinct from API tokens, so neither can be mistaken for the other.
UPLOAD_TICKET_PREFIX = "sastup_"

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
        "name": "create_upload_scan",
        "title": "Scan local files (upload a ZIP)",
        "description": (
            "Scan code that is not in a public repository. Returns a one-time "
            "upload ticket: PUT the ZIP archive's bytes to upload_url with the "
            "header 'Authorization: Bearer <ticket>' (for example curl -T "
            "project.zip). The upload answers with a scan_id; then poll "
            "get_scan_result. The ticket works once and expires in "
            f"{UPLOAD_TICKET_TTL // 60} minutes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Name shown for this scan, e.g. my-project.zip.",
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
                "scan_id": {"type": "string",
                            "description": "Id from scan_git_repository or from the upload."},
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


def handle(message: dict, user, base_url: Optional[str] = None) -> Optional[dict]:
    """Handle one JSON-RPC message. None means "nothing to send back".

    base_url is this deployment's public address, used to tell the caller
    where to upload; without it the upload location is given as a path.
    """
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
            return _result(req_id, _call_tool(name, args, user, base_url))
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


def _call_tool(name: str, args: dict, user, base_url: Optional[str] = None) -> dict:
    if name == "list_scanners":
        from .adapters import ADAPTERS
        return _text([
            {"name": a.name, "kind": a.kind.value, "looks_at": a.requirement}
            for a in ADAPTERS
        ])

    if name == "scan_git_repository":
        return _start_git_scan(args, user)

    if name == "create_upload_scan":
        return _create_upload_ticket(args, user, base_url)

    if name == "get_scan_result":
        return _read_scan(args, user)

    raise ValueError(f"unknown tool '{name}'")


def _requested_tools(args: dict) -> list[str]:
    from .adapters import ADAPTERS

    known = {a.name for a in ADAPTERS}
    requested = [t for t in (args.get("tools") or []) if t in known]
    return requested or sorted(known)


# ------------------------------------------------------------ upload tickets
# A tool call is JSON, so an archive cannot travel in one without being
# base64'd through the assistant's own output. Instead the call hands out a
# ticket and the bytes go over plain HTTP, into the same ZIP path the web
# form uses -- same size cap, same zip-slip and file-count checks. An
# assistant gets what a person with the upload form gets, and no more.
#
# Held in memory: the server is one process, and a ticket that dies with a
# restart costs the caller one more tool call.
@dataclass
class UploadTicket:
    username: Optional[str]
    tools: list[str]
    filename: str
    expires: float


_tickets: dict[str, UploadTicket] = {}   # sha256(ticket) -> ticket
_tickets_lock = threading.Lock()


def _ticket_key(ticket: str) -> str:
    # Stored hashed, like API tokens: a dump of this table is not a way in.
    return hashlib.sha256(ticket.encode()).hexdigest()


def _drop_expired_locked(now: float) -> None:
    for key in [k for k, t in _tickets.items() if t.expires <= now]:
        del _tickets[key]


def issue_upload_ticket(username: Optional[str], tools: list[str],
                        filename: str) -> str:
    now = time.time()
    with _tickets_lock:
        _drop_expired_locked(now)
        wait = f"use one or wait up to {UPLOAD_TICKET_TTL // 60} minutes for them to expire"
        if len(_tickets) >= UPLOAD_TICKETS_TOTAL:
            raise ValueError(f"too many upload tickets are unused; {wait}")
        held = sum(1 for t in _tickets.values() if t.username == username)
        if username is not None and held >= UPLOAD_TICKETS_PER_USER:
            raise ValueError(f"{held} upload tickets are still unused; {wait}")
        ticket = UPLOAD_TICKET_PREFIX + secrets.token_urlsafe(32)
        _tickets[_ticket_key(ticket)] = UploadTicket(
            username=username, tools=tools, filename=filename,
            expires=now + UPLOAD_TICKET_TTL)
    return ticket


def claim_upload_ticket(ticket: str) -> Optional[UploadTicket]:
    """The ticket's grant, removed so it cannot be used twice; None if invalid."""
    if not ticket or not ticket.startswith(UPLOAD_TICKET_PREFIX):
        return None
    with _tickets_lock:
        grant = _tickets.pop(_ticket_key(ticket), None)
    if grant is None or grant.expires <= time.time():
        return None
    return grant


def _create_upload_ticket(args: dict, user, base_url: Optional[str]) -> dict:
    filename = (args.get("filename") or "upload.zip").strip()
    # A label only -- the archive is saved under a fixed name -- but it is
    # shown in the UI and the event log, so keep it short and one line.
    filename = "".join(c for c in filename if c.isprintable())[:120] or "upload.zip"
    tools = _requested_tools(args)
    username = getattr(user, "username", None)
    ticket = issue_upload_ticket(username, tools, filename)
    upload_url = (base_url.rstrip("/") if base_url else "") + UPLOAD_PATH
    return _text({
        "upload_url": upload_url,
        "method": "PUT",
        "header": "Authorization: Bearer <ticket>",
        "ticket": ticket,
        "expires_in_seconds": UPLOAD_TICKET_TTL,
        "tools": tools,
        "max_bytes": config.MAX_UPLOAD_BYTES,
        "example": f'curl -T project.zip -H "Authorization: Bearer {ticket}" {upload_url}',
        "next": "the upload answers with scan_id; poll get_scan_result with it",
    })


def _start_git_scan(args: dict, user) -> dict:
    git_url = (args.get("git_url") or "").strip()
    if not git_url:
        raise ValueError("git_url is required")
    try:
        # The same validation the web form uses: http/https only, no local
        # paths, no ssh. An assistant is not a more trusted caller.
        validate_git_url(git_url)
    except SourceError as exc:
        raise ValueError(str(exc)) from exc

    requested = _requested_tools(args)

    target = ScanTarget(kind="git", display=git_url)
    job = manager.new_job(target, requested,
                          owner=getattr(user, "username", None))
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


def _may_read(job, user) -> bool:
    """Whether this caller may see this scan."""
    if not config.REQUIRE_AUTH:
        return True
    if user is None:
        return False
    if getattr(user, "is_admin", False) or job.owner is None:
        return True
    return job.owner == user.username


def _tool_state(result) -> dict:
    """One tool's state as a caller should read it.

    A tool that has not finished is seeded with status "ok" so the UI can
    lay out its row; reported as-is, a queued scanner read as a clean one.
    """
    from .models import ToolPhase

    finished = result.phase == ToolPhase.FINISHED
    state = {
        "status": result.status.value if finished else result.phase.value,
        "findings": len(result.findings),
        "error": result.error or None,
    }
    if result.skipped:
        state["message"] = result.message
        state["not_analysed"] = result.skipped
    return state


def _read_scan(args: dict, user=None) -> dict:
    scan_id = (args.get("scan_id") or "").strip()
    if not scan_id:
        raise ValueError("scan_id is required")
    job = manager.get(scan_id)
    # A scan's findings quote the scanned source, so a token reads its own
    # owner's scans and not everyone else's. Same message either way: "exists
    # but is not yours" is information in itself.
    if job is None or not _may_read(job, user):
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
        "tools": {n: _tool_state(r) for n, r in job.results.items()},
        "findings": findings,
        "note": ("a verdict labels this scan; it does not block anything. "
                 "Scanners report patterns, so check the code before acting."),
    })
