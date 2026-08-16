"""OSV-Scanner adapter — SCA against the OSV.dev database (multi-ecosystem)."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import config
from ..models import Finding, Severity, ToolKind
from .base import BaseAdapter, run_command, severity_from_cvss

# Lockfiles OSV-Scanner understands; presence of any makes it applicable.
_LOCKFILES = (
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile.lock", "poetry.lock",
    "go.mod", "Gemfile.lock", "Cargo.lock",
    "composer.lock", "pom.xml", "gradle.lockfile",
)

_STR_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class OsvScannerAdapter(BaseAdapter):
    name = "osv_scanner"
    kind = ToolKind.SCA
    binary = "osv-scanner"
    install_hint = (
        "go install github.com/google/osv-scanner/cmd/osv-scanner@latest  "
        "(or download a release binary from github.com/google/osv-scanner)"
    )

    def applicable(self, target_dir: Path) -> bool:
        return any(next(target_dir.rglob(f), None) is not None for f in _LOCKFILES)

    def _execute(self, target_dir: Path) -> list[Finding]:
        res = run_command(
            [self.binary, "--format", "json", "-r", str(target_dir)],
            timeout=config.TOOL_TIMEOUT,
        )
        if res.timed_out:
            raise TimeoutError("osv-scanner timed out")
        # exit code 1 == vulnerabilities found (normal); parse stdout regardless.
        if not res.stdout.strip():
            if res.returncode == 0:
                return []
            raise RuntimeError(res.stderr.strip()[:500] or "no output from osv-scanner")
        return _parse(json.loads(res.stdout), target_dir)


def _parse(data: dict, target_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("results", []):
        source = (result.get("source", {}) or {}).get("path", "")
        rel = _rel(source, target_dir)
        for pkg in result.get("packages", []):
            info = pkg.get("package", {}) or {}
            name = info.get("name", "")
            version = info.get("version", "")
            for vuln in pkg.get("vulnerabilities", []):
                findings.append(
                    Finding(
                        tool="osv_scanner",
                        rule_id=vuln.get("id", ""),
                        severity=_severity(vuln),
                        title=vuln.get("summary")
                        or f"{vuln.get('id', 'vuln')} in {name}",
                        message=(vuln.get("summary") or vuln.get("details", ""))[:500],
                        file=rel,
                        cwe=_cwes(vuln),
                        references=[
                            r.get("url", "") for r in vuln.get("references", [])
                            if r.get("url")
                        ][:5],
                        extra={
                            "package": name,
                            "version": version,
                            "ecosystem": info.get("ecosystem", ""),
                            "aliases": vuln.get("aliases", []),
                        },
                    )
                )
    return findings


def _severity(vuln: dict) -> Severity:
    # Prefer a database-specific label, fall back to CVSS score in `severity`.
    label = (vuln.get("database_specific", {}) or {}).get("severity")
    if label and str(label).lower() in _STR_SEVERITY:
        return _STR_SEVERITY[str(label).lower()]
    for sev in vuln.get("severity", []) or []:
        score = sev.get("score", "")
        # CVSS_V3 entries carry a vector; a bare number is rare but handled.
        try:
            return severity_from_cvss(float(score))
        except (TypeError, ValueError):
            continue
    return Severity.MEDIUM


def _cwes(vuln: dict) -> list[str]:
    tags = (vuln.get("database_specific", {}) or {}).get("cwe_ids", [])
    return [str(t) for t in tags] if isinstance(tags, list) else []


def _rel(path: str, target_dir: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(target_dir.resolve()))
    except (ValueError, OSError):
        return path
