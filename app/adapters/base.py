"""Base adapter contract and subprocess helpers.

Every tool adapter subclasses `BaseAdapter` and implements three things:
availability probing, applicability, and `_execute` (run + normalize). The
`scan()` template method wraps those with timing, timeout handling and error
capture so no individual adapter has to repeat that plumbing.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import config
from ..models import Finding, Severity, ToolKind, ToolResult, ToolStatus


class NotApplicableError(Exception):
    """The tool ran but had nothing to work on.

    Distinct from an error: "your requirements.txt is empty" is a fact about
    the project, not a failure of the scanner, and showing it in red next to
    a stack-trace-shaped message sends people looking for a broken tool.
    """


@dataclass
class Partial:
    """What `_execute` returns when the tool itself reported gaps.

    Returned rather than stored on the adapter, so the result travels with the
    call that produced it and not with whatever instance happened to run it.
    """
    findings: list[Finding]
    skipped: list[str]           # "path: reason", in the tool's own words


#: Enough to see which files and why; a pathological run can report thousands.
MAX_SKIPPED = 50


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_command(
    args: list[str],
    cwd: str | Path | None = None,
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run an external command safely.

    Always list-args + shell=False (no shell interpolation of user input),
    always bounded by a timeout. This is the single choke point through which
    every tool is invoked.
    """
    try:
        proc = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        return CommandResult(proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return CommandResult(-1, out, err, timed_out=True)
    except FileNotFoundError:
        return CommandResult(-1, "", "executable not found")


# Rough CVSS-score -> severity mapping shared by SARIF / OSV parsers.
def severity_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


class BaseAdapter:
    name: str = "base"
    kind: ToolKind = ToolKind.SAST
    binary: str = ""
    install_hint: str = ""
    # Languages the tool meaningfully analyses. ["*"] means language-agnostic
    # (works on any project). Used for the pre-scan applicability warning.
    languages: list[str] = ["*"]
    # One-line, human-readable statement of what the tool needs to find work.
    requirement: str = "any project"

    # ---- availability -------------------------------------------------
    def probe(self) -> tuple[bool, str]:
        """Return (available, version_string)."""
        if not self.binary or shutil.which(self.binary) is None:
            return False, ""
        return self._probe_version()

    def _probe_version(self) -> tuple[bool, str]:
        res = run_command(
            [self.binary, "--version"], timeout=config.PROBE_TIMEOUT
        )
        if res.returncode != 0 and not res.stdout:
            return False, ""
        version = (res.stdout or res.stderr).strip().splitlines()
        return True, version[0] if version else ""

    # ---- applicability ------------------------------------------------
    def applicability(self, target_dir: Path) -> tuple[bool, str]:
        """Return (applicable, reason). Reason explains a False result so the
        UI can tell the user *why* a tool would find nothing."""
        return True, ""

    # ---- execution (implemented per tool) -----------------------------
    def _execute(self, target_dir: Path) -> "list[Finding] | Partial":
        raise NotImplementedError

    # ---- progress reporting --------------------------------------------
    # "running" for eight minutes tells the user nothing, and the work really
    # is different per tool: trivy downloads a vulnerability database, semgrep
    # compiles rules, gitleaks does neither. Each adapter names its own stages.
    first_stage = "scanning"

    def report_stage(self, stage: str) -> None:
        """Tell the orchestrator which part of this tool's work is running."""
        callback = getattr(self, "_on_stage", None)
        if callback:
            try:
                callback(stage)
            except Exception:  # noqa: BLE001 - progress must never break a scan
                pass

    # ---- template method ----------------------------------------------
    def scan(self, target_dir: Path,
             custom_rules: "list[Path] | None" = None,
             rulesets: "list[str] | None" = None) -> ToolResult:
        # Passed down rather than read from config, and safe to keep on self
        # only because get_adapters() hands every scan its own instances.
        self.custom_rules = list(custom_rules or [])
        self.rulesets = list(rulesets or [])
        result = ToolResult(tool=self.name, kind=self.kind, status=ToolStatus.OK)
        result.install_hint = self.install_hint

        self.report_stage("probing")
        available, version = self.probe()
        result.available = available
        result.version = version
        if not available:
            result.status = ToolStatus.UNAVAILABLE
            result.error = f"{self.name} is not installed"
            return result.compute_summary()

        self.report_stage("checking")
        applicable, reason = self.applicability(target_dir)
        if not applicable:
            result.status = ToolStatus.NOT_APPLICABLE
            result.message = reason
            return result.compute_summary()

        start = time.monotonic()
        self.report_stage(self.first_stage)
        try:
            out = self._execute(target_dir)
            if isinstance(out, Partial):
                result.findings = out.findings
                if out.skipped:
                    # The findings stand; what is missing is the rest.
                    result.status = ToolStatus.INCOMPLETE
                    result.skipped = out.skipped[:MAX_SKIPPED]
                    result.message = (
                        f"{len(out.skipped)} item(s) were not fully analysed, "
                        "so findings in them may be missing")
            else:
                result.findings = out
        except NotApplicableError as exc:
            # Nothing to scan is not a failure; it is the same outcome as
            # applicability() returning False, just discovered later.
            result.status = ToolStatus.NOT_APPLICABLE
            result.message = str(exc)
        except TimeoutError as exc:
            result.status = ToolStatus.TIMEOUT
            result.error = str(exc) or "tool timed out"
        except Exception as exc:  # noqa: BLE001 - surface any tool failure
            result.status = ToolStatus.ERROR
            result.error = f"{type(exc).__name__}: {exc}"
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result.compute_summary()
