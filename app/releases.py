"""Which release of each upgradable scanner may be installed, and why not.

Shared by the web app (to show what an upgrade would do) and by the host
updater (scripts/sast_updater.py), which repeats the check itself rather than
trusting what the web app asked for. Standard library only, and no imports
from the rest of the app, so the host can load this file on its own.

A release is eligible when it is the newest non-draft, non-prerelease one and
has been public for COOLDOWN_DAYS. The wait is there because a compromised
release is usually found and pulled within days; installing on the day it
appears is when that risk is highest.
"""
from __future__ import annotations

import http.client
import json
import re
import ssl
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

COOLDOWN_DAYS = 7

#: Upgradable tools and where their releases are published. Bearer is absent
#: on purpose: it is pinned in the Dockerfile together with its checksum, so
#: a new version is a reviewed change to the repository. npm comes from the
#: OS packages.
SOURCES = {
    "semgrep": ("pypi", "semgrep"),
    "trivy": ("github", "aquasecurity/trivy"),
    "osv_scanner": ("github", "google/osv-scanner"),
    "gitleaks": ("github", "gitleaks/gitleaks"),
}

#: The build argument that pins each tool's version in the Dockerfile.
BUILD_ARGS = {
    "semgrep": "SEMGREP_VERSION",
    "trivy": "TRIVY_VERSION",
    "osv_scanner": "OSV_SCANNER_VERSION",
    "gitleaks": "GITLEAKS_VERSION",
}

VERSION_RE = re.compile(r"^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$")


def version_tuple(text: str) -> tuple:
    return tuple(int(p) for p in text.split("."))


#: The only places release data comes from. urllib would also follow file://
#: and any host; a plain HTTPS connection to a named host cannot.
HOSTS = {"api.github.com", "pypi.org"}


def _fetch_json(url: str, timeout: float = 10.0):
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in HOSTS:
        raise ValueError(f"not a release source: {url}")
    # Certificate and host checks, stated rather than left to the default.
    conn = http.client.HTTPSConnection(parts.hostname, timeout=timeout,
                                       context=ssl.create_default_context())
    try:
        conn.request("GET", parts.path + (f"?{parts.query}" if parts.query else ""),
                     headers={"Accept": "application/json", "User-Agent": "sast-studio"})
        resp = conn.getresponse()
        if resp.status != 200:
            raise OSError(f"{parts.hostname} answered {resp.status}")
        return json.load(resp)
    finally:
        conn.close()


def _parse_time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def published(tool: str, fetch=_fetch_json) -> list[tuple[str, datetime]]:
    """(version, when it last changed) for each stable release, newest first.

    "Last changed", not "first published": an asset can be replaced on an old
    GitHub release, and a wheel can be added to an old PyPI version, without
    the release date moving. A compromised maintainer account could swap the
    files of a release already past its wait. So the clock starts at the
    newest of the release and every file in it.
    """
    kind, name = SOURCES[tool]
    found = []
    if kind == "github":
        for rel in fetch(f"https://api.github.com/repos/{name}/releases?per_page=20"):
            version = (rel.get("tag_name") or "").lstrip("v")
            if rel.get("draft") or rel.get("prerelease") or not VERSION_RE.match(version):
                continue
            times = [_parse_time(rel["published_at"])]
            for asset in rel.get("assets") or []:
                times += [_parse_time(asset[k]) for k in ("created_at", "updated_at")
                          if asset.get(k)]
            found.append((version, max(times)))
    else:
        data = fetch(f"https://pypi.org/pypi/{name}/json")
        for version, files in (data.get("releases") or {}).items():
            # Yanked or file-less releases are not installable.
            files = [f for f in files if not f.get("yanked")]
            if not VERSION_RE.match(version) or not files:
                continue
            found.append((version, max(_parse_time(f["upload_time_iso_8601"])
                                       for f in files)))
    found.sort(key=lambda item: version_tuple(item[0]), reverse=True)
    return found


def assess(tool: str, installed: str, now: datetime | None = None,
           fetch=_fetch_json) -> dict:
    """What an upgrade of `tool` would install, or why it would not.

    Returns {tool, installed, latest, latest_published, eligible, reason}.
    `eligible` is the version to install, or "" when there is nothing to do.
    Only the newest release is considered: an older release that happens to
    be past its wait is not an upgrade anyone asked for.
    """
    now = now or datetime.now(timezone.utc)
    out = {"tool": tool, "installed": installed, "latest": "",
           "latest_published": "", "eligible": "", "reason": ""}
    try:
        releases = published(tool, fetch)
    except Exception as exc:  # any failure here means "we do not know"
        out["reason"] = f"could not check: {type(exc).__name__}"
        return out
    if not releases:
        out["reason"] = "no stable release found"
        return out
    latest, when = releases[0]
    out["latest"] = latest
    out["latest_published"] = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    if VERSION_RE.match(installed or "") and \
            version_tuple(latest) <= version_tuple(installed):
        out["reason"] = "up to date"
        return out
    ready = when + timedelta(days=COOLDOWN_DAYS)
    if now < ready:
        out["reason"] = f"released {when:%Y-%m-%d}; eligible from {ready:%Y-%m-%d}"
        return out
    out["eligible"] = latest
    return out
