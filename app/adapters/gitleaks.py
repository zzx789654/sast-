"""Gitleaks adapter — hardcoded secret detection.

Detected secret values are ALWAYS masked before leaving this module, so the
web UI can show "a secret was found here" without re-leaking it.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..config import config
from ..models import Finding, Severity, ToolKind
from .base import BaseAdapter, run_command


class GitleaksAdapter(BaseAdapter):
    name = "gitleaks"
    kind = ToolKind.SECRET
    binary = "gitleaks"
    install_hint = (
        "brew install gitleaks  (or download from github.com/gitleaks/gitleaks/releases)"
    )
    languages = ["*"]  # secret scanning is language-agnostic
    requirement = "any files (secret scan)"

    def _probe_version(self) -> tuple[bool, str]:
        res = run_command([self.binary, "version"], timeout=config.PROBE_TIMEOUT)
        if res.returncode != 0 and not res.stdout:
            return False, ""
        return True, "gitleaks " + (res.stdout or res.stderr).strip().splitlines()[0]

    def _execute(self, target_dir: Path) -> list[Finding]:
        with tempfile.TemporaryDirectory(prefix="gitleaks-") as tmp:
            report = Path(tmp) / "report.json"
            # `detect --no-git` scans the filesystem tree (works on uploaded
            # sources that are not git repos). Exit code 1 => leaks found.
            res = run_command(
                [
                    self.binary, "detect",
                    "--source", str(target_dir),
                    "--no-git",
                    "--report-format", "json",
                    "--report-path", str(report),
                    "--no-banner",
                    "--exit-code", "0",
                ],
                timeout=config.TOOL_TIMEOUT,
            )
            if res.timed_out:
                raise TimeoutError("gitleaks timed out")
            if not report.exists():
                # older/newer CLIs differ; treat a clean run with no report as no leaks
                if res.returncode in (0, 1):
                    return []
                raise RuntimeError(res.stderr.strip()[:500] or "gitleaks failed")
            raw = report.read_text(encoding="utf-8").strip()
            if not raw:
                return []
            return _parse(json.loads(raw), target_dir)


def _parse(data, target_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for item in data or []:
        rule = item.get("RuleID", "secret")
        findings.append(
            Finding(
                tool="gitleaks",
                rule_id=rule,
                severity=Severity.HIGH,
                title=item.get("Description", "Hardcoded secret"),
                message=f"Potential secret ({rule}) detected",
                file=_rel(item.get("File", ""), target_dir),
                start_line=item.get("StartLine"),
                end_line=item.get("EndLine"),
                extra={
                    "match_preview": _mask(item.get("Match", "")),
                    "secret_preview": _mask(item.get("Secret", "")),
                    "entropy": item.get("Entropy"),
                },
            )
        )
    return findings


def _mask(value: str) -> str:
    """Show only enough of a match to locate it; never the full secret."""
    value = (value or "").strip().replace("\n", " ")
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(len(value) - 8, 12)}{value[-4:]}"


def _rel(path: str, target_dir: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(target_dir.resolve()))
    except (ValueError, OSError):
        return path
