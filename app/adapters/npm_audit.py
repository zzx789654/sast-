"""npm audit adapter — SCA against the npm advisory database."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import config
from ..models import Finding, Severity, ToolKind
from .base import BaseAdapter, run_command

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class NpmAuditAdapter(BaseAdapter):
    name = "npm_audit"
    kind = ToolKind.SCA
    binary = "npm"
    install_hint = "Install Node.js (npm ships with it): https://nodejs.org"

    def _probe_version(self) -> tuple[bool, str]:
        res = run_command([self.binary, "--version"], timeout=config.PROBE_TIMEOUT)
        if res.returncode != 0:
            return False, ""
        return True, "npm " + res.stdout.strip()

    def applicable(self, target_dir: Path) -> bool:
        return any(
            (target_dir / f).exists()
            for f in ("package.json", "package-lock.json", "npm-shrinkwrap.json")
        )

    def _execute(self, target_dir: Path) -> list[Finding]:
        # npm audit needs a lockfile; generate one offline-safely if missing.
        if not any((target_dir / f).exists()
                   for f in ("package-lock.json", "npm-shrinkwrap.json")):
            run_command(
                [self.binary, "install", "--package-lock-only",
                 "--ignore-scripts", "--no-audit", "--no-fund"],
                cwd=target_dir, timeout=config.TOOL_TIMEOUT,
            )

        res = run_command(
            [self.binary, "audit", "--json"],
            cwd=target_dir, timeout=config.TOOL_TIMEOUT,
        )
        if res.timed_out:
            raise TimeoutError("npm audit timed out")
        if not res.stdout.strip():
            raise RuntimeError(res.stderr.strip()[:500] or "no output from npm audit")

        data = json.loads(res.stdout)
        if "error" in data:
            raise RuntimeError(str(data["error"])[:500])
        return _parse_v7(data)


def _parse_v7(data: dict) -> list[Finding]:
    """Parse npm >=7 audit JSON (the `vulnerabilities` map)."""
    findings: list[Finding] = []
    vulns = data.get("vulnerabilities", {})
    for pkg_name, info in vulns.items():
        sev = _SEVERITY_MAP.get(str(info.get("severity", "")).lower(), Severity.UNKNOWN)
        for via in info.get("via", []):
            if not isinstance(via, dict):
                continue  # string entries are transitive references
            findings.append(
                Finding(
                    tool="npm_audit",
                    rule_id=str(via.get("source", "")),
                    severity=_SEVERITY_MAP.get(
                        str(via.get("severity", "")).lower(), sev),
                    title=via.get("title", f"Vulnerability in {pkg_name}"),
                    message=(
                        f"{pkg_name} {info.get('range', '')}: "
                        f"{via.get('title', '')}"
                    ).strip(),
                    file="package.json",
                    cwe=_as_list(via.get("cwe")),
                    references=[via["url"]] if via.get("url") else [],
                    extra={
                        "package": pkg_name,
                        "vulnerable_range": info.get("range", ""),
                        "fix_available": bool(info.get("fixAvailable")),
                    },
                )
            )
        if not any(isinstance(v, dict) for v in info.get("via", [])):
            # advisory only referenced transitively; still record the package
            findings.append(
                Finding(
                    tool="npm_audit", severity=sev,
                    title=f"Vulnerable dependency: {pkg_name}",
                    message=f"{pkg_name} {info.get('range', '')} is vulnerable "
                            "via a transitive dependency",
                    file="package.json",
                    extra={"package": pkg_name, "range": info.get("range", "")},
                )
            )
    return findings


def _as_list(value) -> list[str]:
    if value is None:
        return []
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]
