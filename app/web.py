"""Helpers every part of the web API shares: who is asking, may they, and
where this deployment lives.
"""
from __future__ import annotations

import string
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Request

from .config import config


STATIC_DIR = Path(__file__).parent / "static"


def _require_upgrade_admin(request: Request) -> None:
    """An administrator, and accounts must be on. With accounts off,
    require_admin lets everyone through -- not acceptable for a button that
    swaps the service."""
    if not config.REQUIRE_AUTH:
        raise HTTPException(403, "scanner upgrades need accounts turned on "
                                 "(SAST_REQUIRE_AUTH=true)")
    require_admin(request)


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


def _client_ip(request: Request) -> str:
    """The client address as the proxy saw it.

    "unknown" rather than a guess when there is no proxy header and no peer:
    a wrong address in a log is worse than an absent one, because it reads as
    evidence. Only the first hop is taken -- the rest of x-forwarded-for is
    whatever the client chose to send.
    """
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else "unknown")


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


def _human_wait(seconds: int) -> str:
    """"try again in 847 seconds" is worse than "in 15 minutes"."""
    if seconds < 60:
        return f"{seconds} seconds"
    minutes = round(seconds / 60)
    return "1 minute" if minutes == 1 else f"{minutes} minutes"


def _origin_allowed(origin: str, request: Request) -> bool:
    """Whether this Origin is our own site.

    What this catches is the browser attaching our cookie to a form on
    somebody else's page, and for that the browser's own Origin is honest.
    It is compared with where this deployment says it lives, not with a
    header: nginx sends a fixed Host and, since round 49, no longer passes
    on the one the browser typed. So the site's own addresses are
    SAST_PUBLIC_URL, SAST_ALLOWED_HOSTS and -- without nginx in front --
    the Host itself; with none of them configured, only localhost.
    """
    if any(o.strip() == "*" for o in config.MCP_ALLOWED_ORIGINS):
        return True
    asked = _origin_key(origin)
    if not asked:
        return False
    allowed = {_origin_key(o) for o in config.MCP_ALLOWED_ORIGINS}
    if config.PUBLIC_URL:
        allowed.add(_origin_key(config.PUBLIC_URL))

    hosts = list(config.ALLOWED_HOSTS)
    if not hosts and not config.PUBLIC_URL:
        hosts = ["localhost:8080", "127.0.0.1:8080"]
    host = request.headers.get("host", "").strip()
    if _valid_host(host) and host != _PROXY_HOST:
        hosts.append(host)
    asked_host = urlparse(asked).hostname
    for h in hosts:
        if ":" in h:
            allowed |= {_origin_key(f"{scheme}://{h}") for scheme in ("http", "https")}
        elif h.lower() == asked_host:
            # Listed without a port: any port of that host is ours.
            return True
    allowed.discard("")
    return asked in allowed


#: Ports a browser leaves out of an Origin.
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin_key(url: str) -> str:
    """scheme://host[:port] the way a browser writes an Origin: lower case,
    no default port, no path. "" for anything that is not one."""
    try:
        parsed = urlparse(url.strip())
        port = parsed.port
    except ValueError:
        return ""
    scheme = parsed.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not parsed.hostname:
        return ""
    keep = f":{port}" if port and port != _DEFAULT_PORTS[scheme] else ""
    return f"{scheme}://{parsed.hostname.lower()}{keep}"


_HOST_CHARS = frozenset(string.ascii_letters + string.digits + ".-")


#: The Host nginx always sends (nginx/nginx.conf). Not where a client
#: reached us, so never written into anything the client keeps.
_PROXY_HOST = "sast-studio"


def _valid_host(value: str) -> bool:
    """"name" or "name:port", checked character by character -- no pattern
    matching on a header the client wrote, and nothing that could backtrack."""
    if not value or len(value) > 260:
        return False
    name, sep, port = value.partition(":")
    if sep and not (1 <= len(port) <= 5 and all(c in "0123456789" for c in port)
                    and 1 <= int(port) <= 65535):
        return False
    return (1 <= len(name) <= 253 and all(c in _HOST_CHARS for c in name)
            and any(c.isalnum() for c in name))


def _public_origin(request: Request) -> tuple[str, str]:
    """The scheme and host to put into something the client keeps.

    The bug this closes: these values end up in an MCP client entry and a
    .env, both of which a person pastes into a tool that will then send a
    bearer token to whatever address is written there. Working the host out
    from a header means an attacker who gets a signed-in user to load this
    endpoint with a forged header chooses where that token goes.

    So: the configured SAST_PUBLIC_URL wins outright. nginx no longer passes
    on the host the browser typed (round 49); without nginx, Host is used
    only if it is in the allow-list or, with no list, at least looks like a
    host name. Anything else falls back to a value that is obviously wrong
    rather than quietly pointing elsewhere.
    """
    if config.PUBLIC_URL:
        parsed = urlparse(config.PUBLIC_URL)
        if parsed.scheme and parsed.netloc:
            return parsed.scheme, parsed.netloc

    scheme = "https" if _request_is_https(request) else "http"
    candidate = request.headers.get("host", "").strip()
    allowed = config.ALLOWED_HOSTS
    if not _valid_host(candidate) or candidate == _PROXY_HOST:
        # Behind nginx, or a Host that is not one: the configured name if
        # there is one, else a value that is obviously only local.
        return scheme, allowed[0] if allowed else "localhost:8080"

    if allowed and candidate.lower() not in allowed:
        # A host we do not answer to. Use the first configured name rather
        # than echoing back what the caller asked for.
        return scheme, allowed[0]

    return scheme, candidate


def _parse_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
