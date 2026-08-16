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
    def applicable(self, target_dir: Path) -> bool:
        """Whether this tool has anything to scan in target_dir."""
        return True

    # ---- execution (implemented per tool) -----------------------------
    def _execute(self, target_dir: Path) -> list[Finding]:
        raise NotImplementedError

    # ---- template method ----------------------------------------------
    def scan(self, target_dir: Path) -> ToolResult:
        result = ToolResult(tool=self.name, kind=self.kind, status=ToolStatus.OK)
        result.install_hint = self.install_hint

        available, version = self.probe()
        result.available = available
        result.version = version
        if not available:
            result.status = ToolStatus.UNAVAILABLE
            result.error = f"{self.name} is not installed"
            return result.compute_summary()

        if not self.applicable(target_dir):
            result.status = ToolStatus.NOT_APPLICABLE
            return result.compute_summary()

        start = time.monotonic()
        try:
            result.findings = self._execute(target_dir)
        except TimeoutError as exc:
            result.status = ToolStatus.TIMEOUT
            result.error = str(exc) or "tool timed out"
        except Exception as exc:  # noqa: BLE001 - surface any tool failure
            result.status = ToolStatus.ERROR
            result.error = f"{type(exc).__name__}: {exc}"
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result.compute_summary()
