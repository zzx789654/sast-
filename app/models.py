"""Shared data models for SAST Studio.

A single normalized `Finding` shape is the contract every tool adapter must
produce, so the orchestrator and UI never need to understand any individual
tool's native output format.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    """Unified severity scale. Order matters for sorting (see `rank`)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.UNKNOWN: 5,
}

# Counting buckets that show up in every summary.
COUNTED_SEVERITIES = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
]


class ToolKind(str, enum.Enum):
    SAST = "sast"          # source code analysis
    SCA = "sca"            # dependency / supply-chain analysis
    SECRET = "secret"      # hardcoded secret detection


class ToolStatus(str, enum.Enum):
    OK = "ok"
    UNAVAILABLE = "unavailable"          # binary not installed
    NOT_APPLICABLE = "not_applicable"    # nothing for this tool to scan
    ERROR = "error"
    TIMEOUT = "timeout"


class Finding(BaseModel):
    tool: str
    rule_id: str = ""
    severity: Severity = Severity.UNKNOWN
    title: str = ""
    message: str = ""
    file: str = ""                       # path relative to scan root
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    # Extra tool-specific context, safe for display (secrets are pre-redacted).
    extra: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    tool: str
    kind: ToolKind
    status: ToolStatus
    available: bool = False
    version: str = ""
    duration_ms: int = 0
    findings: list[Finding] = Field(default_factory=list)
    error: str = ""
    install_hint: str = ""
    summary: dict[str, int] = Field(default_factory=dict)

    def compute_summary(self) -> "ToolResult":
        counts = {s.value: 0 for s in COUNTED_SEVERITIES}
        for f in self.findings:
            counts[f.severity.value] += 1
        counts["total"] = len(self.findings)
        self.summary = counts
        return self


class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"


class ScanTarget(BaseModel):
    kind: str          # "upload" | "path" | "git"
    display: str       # human readable label (repo url, filename, path)


class Job(BaseModel):
    id: str
    status: JobStatus = JobStatus.QUEUED
    target: ScanTarget
    requested_tools: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: _now())
    started_at: str = ""
    finished_at: str = ""
    results: dict[str, ToolResult] = Field(default_factory=dict)
    summary: dict[str, int] = Field(default_factory=dict)
    error: str = ""
    logs: list[str] = Field(default_factory=list)

    def compute_summary(self) -> "Job":
        counts = {s.value: 0 for s in COUNTED_SEVERITIES}
        total = 0
        for res in self.results.values():
            for f in res.findings:
                counts[f.severity.value] += 1
                total += 1
        counts["total"] = total
        counts["tools_run"] = sum(
            1 for r in self.results.values() if r.status == ToolStatus.OK
        )
        self.summary = counts
        return self


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
