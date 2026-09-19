"""Trivy adapter — free (Apache-2.0) all-in-one scanner.

Trivy covers three of our dimensions at once from a filesystem scan:
dependency vulnerabilities (SCA), hardcoded secrets, and — uniquely in this
lineup — Infrastructure-as-Code misconfigurations (Dockerfile/K8s/Terraform).
"""
from __future__ import annotations

import json
from pathlib import Path

from ..config import config
from ..models import Finding, Severity, ToolKind
from .base import BaseAdapter, run_command

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.UNKNOWN,
}


class TrivyAdapter(BaseAdapter):
    name = "trivy"
    kind = ToolKind.SCA
    binary = "trivy"
    install_hint = (
        "brew install trivy  (or see aquasecurity.github.io/trivy — free, Apache-2.0)"
    )
    languages = ["*"]  # deps + secrets + IaC configs, language-agnostic
    first_stage = "vulndb"         # may download the vulnerability DB
    requirement = "any project (deps, secrets, IaC configs)"

    def _execute(self, target_dir: Path) -> list[Finding]:
        args = [
            self.binary, "fs",
            "--format", "json",
            "--quiet",
            "--scanners", "vuln,secret,misconfig",
        ]
        # Custom Rego checks live in one directory; trivy needs the directory
        # and the namespace they declare.
        custom = getattr(self, "custom_rules", [])
        if custom:
            args += ["--config-check", str(custom[0].parent),
                     "--check-namespaces", "custom"]
        args.append(str(target_dir))
        res = run_command(args, timeout=config.TOOL_TIMEOUT)
        if res.timed_out:
            raise TimeoutError("trivy timed out")
        if not res.stdout.strip():
            if res.returncode == 0:
                return []
            raise RuntimeError(res.stderr.strip()[:500] or "no output from trivy")
        return _parse(json.loads(res.stdout), target_dir)


def _parse(data: dict, target_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        target = _rel(result.get("Target", ""), target_dir)

        for vuln in result.get("Vulnerabilities") or []:
            findings.append(Finding(
                tool="trivy",
                rule_id=vuln.get("VulnerabilityID", ""),
                severity=_sev(vuln.get("Severity")),
                title=vuln.get("Title") or vuln.get("VulnerabilityID", "vulnerability"),
                message=(vuln.get("Description") or "")[:500],
                file=target,
                cwe=[str(c) for c in vuln.get("CweIDs", []) or []],
                references=[vuln["PrimaryURL"]] if vuln.get("PrimaryURL") else [],
                extra={
                    "category": "vulnerability",
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                },
            ))

        for mis in result.get("Misconfigurations") or []:
            cause = mis.get("CauseMetadata", {}) or {}
            findings.append(Finding(
                tool="trivy",
                rule_id=mis.get("ID", ""),
                severity=_sev(mis.get("Severity")),
                title=mis.get("Title") or mis.get("ID", "misconfiguration"),
                message=(mis.get("Message") or mis.get("Description") or "")[:500],
                file=target,
                start_line=cause.get("StartLine"),
                end_line=cause.get("EndLine"),
                references=[mis["PrimaryURL"]] if mis.get("PrimaryURL") else [],
                extra={"category": "misconfiguration",
                       "resolution": mis.get("Resolution", "")},
            ))

        for secret in result.get("Secrets") or []:
            findings.append(Finding(
                tool="trivy",
                rule_id=secret.get("RuleID", ""),
                severity=_sev(secret.get("Severity")) or Severity.HIGH,
                title=secret.get("Title") or "Hardcoded secret",
                message=f"Potential secret ({secret.get('Category', '')}) detected",
                file=target,
                start_line=secret.get("StartLine"),
                end_line=secret.get("EndLine"),
                extra={"category": "secret",
                       "match_preview": _mask(secret.get("Match", ""))},
            ))
    return findings


def _sev(value) -> Severity:
    return _SEVERITY_MAP.get(str(value).upper(), Severity.UNKNOWN)


def _mask(value: str) -> str:
    value = (value or "").strip().replace("\n", " ")
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(len(value) - 8, 12)}{value[-4:]}"


def _rel(path: str, target_dir: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(target_dir.resolve()))
    except (ValueError, OSError):
        return path
