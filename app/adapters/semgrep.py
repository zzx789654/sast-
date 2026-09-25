"""Semgrep adapter — pattern-based SAST engine (Python-based)."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import config
from ..models import Finding, Severity, ToolKind
from .base import BaseAdapter, Partial, run_command

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
    first_stage = "rules"          # fetching and compiling rulesets
    requirement = "source code (30+ languages, rule-based)"

    def _probe_version(self) -> tuple[bool, str]:
        res = run_command([self.binary, "--version"], timeout=config.PROBE_TIMEOUT)
        if res.returncode != 0 and not res.stdout:
            return False, ""
        return True, (res.stdout or res.stderr).strip().splitlines()[0]

    def _execute(self, target_dir: Path) -> Partial:
        args = [self.binary, "scan"]
        # One --config per ruleset: semgrep unions them, so picking OWASP on
        # top of the default set adds rules rather than swapping them.
        rulesets = getattr(self, "rulesets", None) or config.SEMGREP_RULESETS
        for ruleset in rulesets:
            args += ["--config", ruleset]
        # --config can be repeated, so custom rules add to the registry set
        # rather than replacing it: adding one rule of your own should not
        # cost you the coverage of the default ruleset.
        for rule in getattr(self, "custom_rules", []):
            args += ["--config", str(rule)]
        args += [
            # A custom rule can contain a regex that backtracks catastrophically.
            # Validation only proves a rule compiles, not that it terminates
            # quickly, so let semgrep abandon a rule that runs away instead of
            # letting it consume the whole scan's time budget.
            "--timeout", "30",
            "--timeout-threshold", "3",
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
        skipped = _coverage_gaps(data, target_dir)
        for item in data.get("results", []):
            extra = item.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            sev = _SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), Severity.LOW)
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=_clean_check_id(item.get("check_id", "")),
                    severity=sev,
                    title=(item.get("check_id", "") or "semgrep finding").split(".")[-1],
                    message=extra.get("message", "").strip(),
                    file=_relpath(item.get("path", ""), target_dir),
                    start_line=(item.get("start") or {}).get("line"),
                    end_line=(item.get("end") or {}).get("line"),
                    cwe=_as_list(meta.get("cwe")),
                    owasp=_as_list(meta.get("owasp")),
                    references=_as_list(meta.get("references")),
                    extra={"category": meta.get("category", ""),
                           # Semgrep returns the offending source line(s); keep
                           # them so the UI can show the code, not just a path.
                           "snippet": _snippet(extra.get("lines"))},
                )
            )
        return Partial(findings, skipped)


#: Skip reasons that mean "this file was meant to be scanned and was not".
#: The rest (gitignore, .semgrepignore, binary, minified) are choices.
_COVERAGE_SKIPS = {"exceeded_size_limit", "too_big",
                   "analysis_failed_parser_or_internal_error"}


def _coverage_gaps(data: dict, target_dir: Path) -> list[str]:
    """Files semgrep says it did not fully analyse.

    A rule that times out on a file (and, past --timeout-threshold, every
    remaining rule on it) is reported only in `errors`, with exit code 0.
    Measured: forcing a 1s timeout on a 100 KB file gave rc 0, zero results
    and one Timeout error -- the same output as a clean file.
    """
    gaps: dict[str, set] = {}
    for err in data.get("errors") or []:
        path = err.get("path") or ((err.get("spans") or [{}])[0] or {}).get("file")
        if not path:
            continue            # a rule/config problem, not a file left unread
        kind = err.get("type")
        if isinstance(kind, list):
            kind = kind[0] if kind else ""
        gaps.setdefault(_relpath(path, target_dir), set()).add(str(kind or "error"))
    for item in (data.get("paths") or {}).get("skipped") or []:
        if isinstance(item, dict) and item.get("reason") in _COVERAGE_SKIPS:
            gaps.setdefault(_relpath(item.get("path", ""), target_dir), set()).add(item["reason"])
    return [f"{path}: {', '.join(sorted(kinds))}" for path, kinds in gaps.items()]


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


#: Snippets come from scanned (untrusted) files, so bound how much is kept.
MAX_SNIPPET_LINES = 12
MAX_SNIPPET_CHARS = 1200


def _clean_check_id(check_id: str) -> str:
    """Drop the path prefix semgrep adds to a rule loaded from a file.

    A rule from a local file is reported as the path to it with dots for
    separators, so a custom rule showed up as
    "data.workspaces.<job>.rules.semgrep.no-pickle-loads". The id the user
    wrote is the last segment; the rest is where we happened to put the file.
    """
    if "rules.semgrep." in check_id:
        return check_id.split("rules.semgrep.", 1)[1]
    if "rules.trivy." in check_id:
        return check_id.split("rules.trivy.", 1)[1]
    return check_id


def _snippet(lines) -> str:
    """Trim the scanner-supplied source excerpt to a displayable size."""
    if not lines or not isinstance(lines, str):
        return ""
    text = lines.strip("\n")
    if text.strip() == "requires login":   # semgrep's placeholder for pro rules
        return ""
    kept = text.splitlines()[:MAX_SNIPPET_LINES]
    out = "\n".join(kept)
    return out[:MAX_SNIPPET_CHARS]


def _relpath(path: str, target_dir: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(target_dir.resolve()))
    except (ValueError, OSError):
        return path
