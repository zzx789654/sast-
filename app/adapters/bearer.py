"""Bearer adapter — free (Elastic License) semantic SAST.

Bearer does dataflow-based static analysis for security & privacy risks across
many languages (Ruby, JS/TS, Java, PHP, Python, Go). It's the closest
zero-cost stand-in for CodeQL's semantic analysis. Its JSON report is an object
keyed by severity, each holding a list of findings.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..config import config
from ..inventory import has_language
from ..models import Finding, Severity, ToolKind
from .base import BaseAdapter, Partial, run_command

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

    def _execute(self, target_dir: Path) -> Partial:
        findings, failed = self._run_once(target_dir)
        if failed:
            # Measured: a file that misses Bearer's per-file deadline on a
            # busy host (six scanners on two CPUs) is analysed fine once the
            # load has moved on. One retry, not a loop.
            self.report_stage("retrying skipped files")
            retry_findings, retry_failed = self._run_once(target_dir)
            if len(retry_failed) < len(failed):
                findings, failed = retry_findings, retry_failed
        return Partial(findings, failed)

    def _run_once(self, target_dir: Path) -> tuple[list[Finding], list[str]]:
        res = run_command(
            [
                self.binary, "scan", str(target_dir),
                "--format", "json",
                "--quiet",
                "--exit-code", "0",
                "--force",
                # A file Bearer gives up on is reported only at debug level;
                # at the default level the run exits 0 as if it were clean.
                "--log-level", "debug",
            ],
            timeout=config.TOOL_TIMEOUT,
        )
        if res.timed_out:
            raise TimeoutError("bearer timed out")
        failed = _failed_files(res.stderr)
        if not res.stdout.strip():
            # No findings at all prints nothing on some versions.
            if res.returncode == 0:
                return [], failed
            raise RuntimeError(_last_error(res.stderr) or "no output from bearer")
        try:
            data = json.loads(res.stdout)
        except json.JSONDecodeError:
            # locate the JSON object if the CLI prefixes progress text
            start = res.stdout.find("{")
            if start < 0:
                return [], failed
            data = json.loads(res.stdout[start:])
        return _parse(data, target_dir), failed


# "DBG failed to scan file renderer/app.js: javascript scan failed: context
# deadline exceeded process=worker-0" -- the progress bar shares the line.
_FAILED_FILE = re.compile(r"failed to scan file (.+?): (.+?)(?: process=\S+)?\s*$")


def _failed_files(stderr: str) -> list[str]:
    seen: dict[str, str] = {}
    for line in stderr.splitlines():
        m = _FAILED_FILE.search(line)
        if m:
            seen.setdefault(m.group(1), m.group(2).strip())
    return [f"{path}: {reason}" for path, reason in seen.items()]


def _last_error(stderr: str) -> str:
    """The last non-debug line: with debug on, the reason is not the first line."""
    lines = [l for l in stderr.strip().splitlines() if l.strip() and " DBG " not in l]
    return (lines[-1] if lines else "")[:500]


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
                extra={"category_groups": item.get("category_groups", []),
                       # Bearer returns the offending lines; showing them is
                       # what lets a reader judge the finding instead of
                       # trusting the description. Without it a false positive
                       # and a real bug read exactly the same.
                       "snippet": _snippet(item.get("code_extract"))},
            ))
    return findings


# Same limits as the other adapters: enough context to judge, not so much
# that one finding fills the screen.
MAX_SNIPPET_LINES = 12
MAX_SNIPPET_CHARS = 1200


def _snippet(code) -> str:
    """Trim Bearer's source excerpt to a displayable size."""
    if not code or not isinstance(code, str):
        return ""
    kept = code.strip("\n").splitlines()[:MAX_SNIPPET_LINES]
    return "\n".join(kept)[:MAX_SNIPPET_CHARS]


def _rel(path: str, target_dir: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(target_dir.resolve()))
    except (ValueError, OSError):
        return path
