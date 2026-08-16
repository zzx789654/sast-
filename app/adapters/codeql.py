"""CodeQL adapter — semantic SAST via a compiled query database.

CodeQL is the heavyweight of the five: it builds a database from the source
then runs a query suite, emitting SARIF. For interpreted languages the DB can
be built with no build command; compiled languages need one and are reported
as needing manual setup rather than guessed at.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..config import config
from ..models import Finding, Severity, ToolKind
from .base import BaseAdapter, run_command, severity_from_cvss

# Languages CodeQL can autobuild (no build command required).
_NO_BUILD_LANGS = {
    "javascript": ["*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs"],
    "python": ["*.py"],
    "ruby": ["*.rb"],
    "go": ["*.go"],
}


class CodeqlAdapter(BaseAdapter):
    name = "codeql"
    kind = ToolKind.SAST
    binary = "codeql"
    install_hint = (
        "Download the CodeQL CLI bundle from "
        "https://github.com/github/codeql-action/releases and put `codeql` on PATH"
    )

    def _probe_version(self) -> tuple[bool, str]:
        res = run_command([self.binary, "version", "--format=terse"],
                          timeout=config.PROBE_TIMEOUT)
        if res.returncode != 0 and not res.stdout:
            return False, ""
        return True, (res.stdout or res.stderr).strip().splitlines()[0]

    def _detect_language(self, target_dir: Path) -> str | None:
        for lang, patterns in _NO_BUILD_LANGS.items():
            for pattern in patterns:
                if next(target_dir.rglob(pattern), None) is not None:
                    return lang
        return None

    def applicable(self, target_dir: Path) -> bool:
        return self._detect_language(target_dir) is not None

    def _execute(self, target_dir: Path) -> list[Finding]:
        lang = self._detect_language(target_dir)
        if lang is None:
            raise RuntimeError(
                "no CodeQL-autobuildable language detected "
                "(compiled languages need a manual build command)"
            )
        with tempfile.TemporaryDirectory(prefix="codeql-") as tmp:
            db_dir = Path(tmp) / "db"
            sarif = Path(tmp) / "out.sarif"
            create = run_command(
                [
                    self.binary, "database", "create", str(db_dir),
                    f"--language={lang}",
                    f"--source-root={target_dir}",
                    "--overwrite",
                ],
                timeout=config.TOOL_TIMEOUT,
            )
            if create.timed_out:
                raise TimeoutError("codeql database create timed out")
            if create.returncode != 0:
                raise RuntimeError(create.stderr.strip()[:500] or "database create failed")

            analyze = run_command(
                [
                    self.binary, "database", "analyze", str(db_dir),
                    f"codeql/{lang}-queries:codeql-suites/{lang}-security-and-quality.qls",
                    "--format=sarif-latest",
                    f"--output={sarif}",
                ],
                timeout=config.TOOL_TIMEOUT,
            )
            if analyze.timed_out:
                raise TimeoutError("codeql database analyze timed out")
            if analyze.returncode != 0 or not sarif.exists():
                raise RuntimeError(analyze.stderr.strip()[:500] or "analyze failed")
            return parse_sarif(sarif.read_text(encoding="utf-8"), self.name, target_dir)


def parse_sarif(text: str, tool: str, target_dir: Path) -> list[Finding]:
    """Parse a SARIF 2.1.0 document into normalized findings."""
    data = json.loads(text)
    findings: list[Finding] = []
    for run in data.get("runs", []):
        rules = {
            r.get("id"): r
            for r in (run.get("tool", {}).get("driver", {}).get("rules", []) or [])
        }
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "")
            rule = rules.get(rule_id, {})
            props = rule.get("properties", {}) or {}
            severity = _sarif_severity(res.get("level"), props)
            loc = _first_location(res)
            findings.append(
                Finding(
                    tool=tool,
                    rule_id=rule_id,
                    severity=severity,
                    title=(rule.get("name") or rule_id or "finding"),
                    message=_message(res),
                    file=_rel(loc.get("file", ""), target_dir),
                    start_line=loc.get("start_line"),
                    end_line=loc.get("end_line"),
                    cwe=_cwe_tags(props.get("tags", [])),
                    references=_refs(rule),
                    extra={"tags": props.get("tags", [])},
                )
            )
    return findings


def _sarif_severity(level, props) -> Severity:
    score = props.get("security-severity")
    if score is not None:
        try:
            return severity_from_cvss(float(score))
        except (TypeError, ValueError):
            pass
    return {"error": Severity.HIGH, "warning": Severity.MEDIUM,
            "note": Severity.LOW}.get(str(level).lower(), Severity.MEDIUM)


def _message(res) -> str:
    return (res.get("message", {}) or {}).get("text", "").strip()


def _first_location(res) -> dict:
    locs = res.get("locations", []) or []
    if not locs:
        return {}
    phys = (locs[0].get("physicalLocation", {}) or {})
    region = phys.get("region", {}) or {}
    return {
        "file": (phys.get("artifactLocation", {}) or {}).get("uri", ""),
        "start_line": region.get("startLine"),
        "end_line": region.get("endLine"),
    }


def _cwe_tags(tags) -> list[str]:
    out = []
    for t in tags or []:
        s = str(t)
        if "cwe" in s.lower():
            # tags look like "external/cwe/cwe-089"
            part = s.split("/")[-1].upper().replace("CWE-", "CWE-")
            out.append(part.upper())
    return out


def _refs(rule) -> list[str]:
    url = rule.get("helpUri")
    return [url] if url else []


def _rel(path: str, target_dir: Path) -> str:
    try:
        return str(Path(path))
    except Exception:  # noqa: BLE001
        return path
