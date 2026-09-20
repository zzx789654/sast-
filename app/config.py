"""Runtime configuration, all overridable via environment variables."""
from __future__ import annotations

import os
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default


class Config:
    # Base working directory where each job gets an isolated sub-folder.
    WORKSPACE_DIR = Path(
        os.environ.get("SAST_WORKSPACE", "/tmp/sast-studio-workspaces")
    )

    # Per-tool wall-clock timeout (seconds).
    TOOL_TIMEOUT = _env_int("SAST_TOOL_TIMEOUT", 900)
    # Timeout for `--version` style availability probes.
    PROBE_TIMEOUT = _env_int("SAST_PROBE_TIMEOUT", 20)
    # Timeout for git clone.
    GIT_CLONE_TIMEOUT = _env_int("SAST_GIT_TIMEOUT", 300)

    # How many tools may run concurrently per job.
    MAX_WORKERS = _env_int("SAST_MAX_WORKERS", 4)

    # Upload / extraction safety limits.
    MAX_UPLOAD_BYTES = _env_int("SAST_MAX_UPLOAD_BYTES", 200 * 1024 * 1024)  # 200MB
    MAX_UNCOMPRESSED_BYTES = _env_int(
        "SAST_MAX_UNCOMPRESSED_BYTES", 2 * 1024 * 1024 * 1024  # 2GB
    )
    MAX_UNCOMPRESSED_FILES = _env_int("SAST_MAX_FILES", 200_000)

    # Allow scanning an arbitrary server-local path. Powerful (operator-only).
    ALLOW_LOCAL_PATH = _env_bool("SAST_ALLOW_LOCAL_PATH", True)

    # Git clone url schemes that are permitted.
    ALLOWED_GIT_SCHEMES = {
        s.strip()
        for s in os.environ.get("SAST_GIT_SCHEMES", "http,https").split(",")
        if s.strip()
    }

    # Accounts and sessions. On the same volume as the rules, because both
    # must outlive a restart; scan history deliberately does not.
    ACCOUNTS_DB = Path(
        os.environ.get("SAST_ACCOUNTS_DB", "/tmp/sast-studio-accounts.db")
    )

    # Origins allowed to call /mcp from a browser. The MCP spec requires
    # checking this to stop a web page driving the endpoint via DNS
    # rebinding. Same-host is always allowed; "*" disables the check.
    MCP_ALLOWED_ORIGINS = [
        o.strip() for o in os.environ.get("SAST_MCP_ORIGINS", "").split(",")
        if o.strip()
    ]

    # Whether the UI and API require a login. Off by default so an existing
    # deployment keeps working after an upgrade; the compose file turns it on.
    REQUIRE_AUTH = _env_bool("SAST_REQUIRE_AUTH", False)

    # Where custom scanner rules are kept. On the Docker deployment this sits
    # on the same volume as the workspaces, so rules written in the browser
    # survive a restart and an image rebuild.
    # Defaults beside the workspaces so a local run works without setup; the
    # Docker deployment points it at the persistent volume instead.
    RULES_DIR = Path(
        os.environ.get("SAST_RULES_DIR", "/tmp/sast-studio-rules")
    )

    # Semgrep rulesets, comma separated. --config can be repeated, so several
    # apply together. Needs network; point at a local path for offline use.
    #
    # Not "auto": semgrep refuses to build the auto config while metrics are
    # off, and we always scan with --metrics=off so no code data leaves the box.
    SEMGREP_RULES = os.environ.get("SAST_SEMGREP_RULES", "p/default")
    SEMGREP_RULESETS = [
        r.strip() for r in os.environ.get(
            "SAST_SEMGREP_RULESETS",
            "p/default,p/owasp-top-ten,p/security-audit,p/python,"
            "p/javascript,p/java,p/golang,p/secrets").split(",")
        if r.strip() and r.strip() != "auto"
    ]

    # Keep job workspaces after completion (debugging). Default: clean up.
    KEEP_WORKSPACES = _env_bool("SAST_KEEP_WORKSPACES", False)

    # Retain at most this many finished jobs in memory.
    MAX_JOBS_RETAINED = _env_int("SAST_MAX_JOBS", 100)

    # Docker container monitoring (Monitor tab). OFF by default: reading stats
    # needs the Docker daemon socket mounted into this container, which is a
    # privileged capability — only enable it on a trusted deployment.
    ENABLE_DOCKER_STATS = _env_bool("SAST_ENABLE_DOCKER_STATS", False)
    DOCKER_SOCKET = os.environ.get("SAST_DOCKER_SOCKET", "/var/run/docker.sock")


config = Config()
