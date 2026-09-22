"""OSV-Scanner adapter — SCA against the OSV.dev database (multi-ecosystem)."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import config
from ..models import Finding, Severity, ToolKind
from .base import (BaseAdapter, NotApplicableError, run_command,
                   severity_from_cvss)

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
    languages = ["*"]  # any ecosystem, as long as there is a lockfile
    first_stage = "advisories"     # queries the OSV database
    requirement = "a dependency lockfile (npm, pip, go, cargo, …)"

    def applicability(self, target_dir: Path) -> tuple[bool, str]:
        if any(next(target_dir.rglob(f), None) is not None for f in _LOCKFILES):
            return True, ""
        return False, "no supported lockfile found (package-lock.json, requirements.txt, go.mod, …)"

    #: osv-scanner's "I found nothing to read" exit code. It is not a
    #: failure of the tool: a requirements.txt that is empty, holds only
    #: comments, or starts with a byte-order mark all land here, as does a
    #: lockfile that will not parse. Reported as an error it looks like the
    #: scanner broke; what it means is that there was nothing to scan.
    _NO_SOURCES = 128

    def _execute(self, target_dir: Path) -> list[Finding]:
        # The findings here are vulnerabilities; a package with no advisory
        # never becomes one. The full inventory with licences is a different
        # question, answered in app/sbom.py, so the extra flags belong there
        # rather than making every scan pay for them.
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
            if res.returncode == self._NO_SOURCES:
                raise NotApplicableError(_no_sources_hint(target_dir))
            raise RuntimeError(res.stderr.strip()[:500] or "no output from osv-scanner")
        return _parse(json.loads(res.stdout), target_dir)


def _no_sources_hint(target_dir: Path) -> str:
    """Say which file was there and why it yielded nothing.

    All of these produce the same exit code, and the difference matters:
    "your lockfile is malformed" and "this file is empty" need different
    fixes, and a BOM is invisible in an editor.
    """
    for name in _LOCKFILES:
        found = next(target_dir.rglob(name), None)
        if found is None:
            continue
        try:
            raw = found.read_bytes()
        except OSError:
            continue

        where = found.name
        if raw.startswith(b"\xef\xbb\xbf"):
            return (f"{where} starts with a byte-order mark, which "
                    "osv-scanner cannot read past. Save it as UTF-8 without "
                    "a BOM.")
        text = raw.decode("utf-8", "replace")
        if not text.strip():
            return f"{where} is empty"
        if all(not line.strip() or line.lstrip().startswith("#")
               for line in text.splitlines()):
            return f"{where} contains only comments"
        if where.endswith(".json"):
            try:
                json.loads(text)
            except ValueError:
                return f"{where} is not valid JSON, so it could not be read"
        return (f"{where} was found but osv-scanner read no packages from "
                "it; it may be in an unexpected format")

    return "no dependency file that osv-scanner could read"


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
