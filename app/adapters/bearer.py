"""Bearer adapter — free (Elastic License) semantic SAST.

Bearer does dataflow-based static analysis for security & privacy risks across
many languages (Ruby, JS/TS, Java, PHP, Python, Go). It's the closest
zero-cost stand-in for CodeQL's semantic analysis. Its JSON report is an object
keyed by severity, each holding a list of findings.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..config import config
from ..inventory import has_language
from ..models import Finding, Severity, ToolKind
from .base import BaseAdapter, run_command

_SEVERITY_KEYS = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "warning": Severity.LOW,
}


class BearerAdapter(BaseAdapter):
    name = "bearer"
    kind = ToolKind.SAST
    binary = "bearer"
    install_hint = (
        "curl -sSfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh "
        "| sh  (free, Elastic License — see github.com/Bearer/bearer)"
    )
    languages = ["ruby", "javascript", "typescript", "java", "php", "python", "go"]
    first_stage = "dataflow"       # semantic/data-flow analysis
    requirement = "Ruby/JS/TS/Java/PHP/Python/Go source"

    def applicability(self, target_dir: Path) -> tuple[bool, str]:
        if has_language(target_dir, set(self.languages)):
            return True, ""
        return False, (
            "no supported source files found "
            f"(Bearer analyses {', '.join(self.languages)})"
        )

    def _probe_version(self) -> tuple[bool, str]:
        res = run_command([self.binary, "version"], timeout=config.PROBE_TIMEOUT)
        if res.returncode != 0 and not res.stdout:
            return False, ""
        return True, "bearer " + (res.stdout or res.stderr).strip().splitlines()[0]

    def _execute(self, target_dir: Path) -> list[Finding]:
        res = run_command(
            [
                self.binary, "scan", str(target_dir),
                "--format", "json",
                "--quiet",
                "--exit-code", "0",
                "--force",
            ],
            timeout=config.TOOL_TIMEOUT,
        )
        if res.timed_out:
            raise TimeoutError("bearer timed out")
        if not res.stdout.strip():
            # No findings at all prints nothing on some versions.
            if res.returncode == 0:
                return []
            raise RuntimeError(res.stderr.strip()[:500] or "no output from bearer")
        try:
            data = json.loads(res.stdout)
        except json.JSONDecodeError:
            # locate the JSON object if the CLI prefixes progress text
            start = res.stdout.find("{")
            if start < 0:
                return []
            data = json.loads(res.stdout[start:])
        return _parse(data, target_dir)


def _parse(data: dict, target_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for key, severity in _SEVERITY_KEYS.items():
        for item in data.get(key, []) or []:
            findings.append(Finding(
                tool="bearer",
                rule_id=item.get("id", ""),
                severity=severity,
                title=item.get("title") or item.get("id", "finding"),
                message=(item.get("description") or "").strip()[:500],
                file=_rel(item.get("filename") or item.get("full_filename", ""), target_dir),
                start_line=item.get("line_number"),
                cwe=[f"CWE-{c}" for c in item.get("cwe_ids", []) or []],
                references=[item["documentation_url"]] if item.get("documentation_url") else [],
                extra={"category_groups": item.get("category_groups", [])},
            ))
    return findings


def _rel(path: str, target_dir: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(target_dir.resolve()))
    except (ValueError, OSError):
        return path
