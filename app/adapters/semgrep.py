"""Semgrep adapter — pattern-based SAST engine (Python-based)."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import config
from ..models import Finding, Severity, ToolKind
from .base import BaseAdapter, run_command

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepAdapter(BaseAdapter):
    name = "semgrep"
    kind = ToolKind.SAST
    binary = "semgrep"
    install_hint = "pip install semgrep  (or: brew install semgrep)"
    languages = ["*"]  # rule-dependent; supports 30+ languages
    requirement = "source code (30+ languages, rule-based)"

    def _probe_version(self) -> tuple[bool, str]:
        res = run_command([self.binary, "--version"], timeout=config.PROBE_TIMEOUT)
        if res.returncode != 0 and not res.stdout:
            return False, ""
        return True, (res.stdout or res.stderr).strip().splitlines()[0]

    def _execute(self, target_dir: Path) -> list[Finding]:
        args = [
            self.binary,
            "scan",
            "--config",
            config.SEMGREP_RULES,
            "--json",
            "--quiet",
            "--disable-version-check",
            "--metrics=off",
            str(target_dir),
        ]
        res = run_command(args, timeout=config.TOOL_TIMEOUT)
        if res.timed_out:
            raise TimeoutError("semgrep scan exceeded time limit")
        if not res.stdout.strip():
            # Non-zero with no JSON usually means config/ruleset failure.
            raise RuntimeError(res.stderr.strip()[:500] or "no output from semgrep")

        data = json.loads(res.stdout)
        findings: list[Finding] = []
        for item in data.get("results", []):
            extra = item.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            sev = _SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), Severity.LOW)
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=item.get("check_id", ""),
                    severity=sev,
                    title=(item.get("check_id", "") or "semgrep finding").split(".")[-1],
                    message=extra.get("message", "").strip(),
                    file=_relpath(item.get("path", ""), target_dir),
                    start_line=(item.get("start") or {}).get("line"),
                    end_line=(item.get("end") or {}).get("line"),
                    cwe=_as_list(meta.get("cwe")),
                    owasp=_as_list(meta.get("owasp")),
                    references=_as_list(meta.get("references")),
                    extra={"category": meta.get("category", "")},
                )
            )
        return findings


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _relpath(path: str, target_dir: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(target_dir.resolve()))
    except (ValueError, OSError):
        return path
