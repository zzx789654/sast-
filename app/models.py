"""Shared data models for SAST Studio.

A single normalized `Finding` shape is the contract every tool adapter must
produce, so the orchestrator and UI never need to understand any individual
tool's native output format.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional

from typing import Optional

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


class ToolPhase(str, enum.Enum):
    """Live execution phase, independent of the final outcome (ToolStatus)."""

    PENDING = "pending"      # queued, not started yet
    RUNNING = "running"      # currently executing
    FINISHED = "finished"    # done — see `status` for the outcome


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
    phase: ToolPhase = ToolPhase.PENDING
    # Which part of this tool's own work is in progress. "running" for
    # eight minutes says nothing; the parts genuinely differ per tool.
    stage: str = ""
    available: bool = False
    version: str = ""
    started_at: str = ""
    duration_ms: int = 0
    findings: list[Finding] = Field(default_factory=list)
    error: str = ""
    message: str = ""            # non-error note, e.g. why it was not applicable
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
    AWAITING = "awaiting_confirmation"   # source prepared; waiting for user to run
    DONE = "done"
    POLICY_REVIEW = "policy_review"
    BLOCKED = "blocked"
    ERROR = "error"
    CANCELLED = "cancelled"


class ScanTarget(BaseModel):
    kind: str          # "upload" | "path" | "git"
    display: str       # human readable label (repo url, filename, path)


class Job(BaseModel):
    id: str
    status: JobStatus = JobStatus.QUEUED
    target: ScanTarget
    requested_tools: list[str] = Field(default_factory=list)
    # Who started this scan. A scan carries the scanned project's source in
    # its findings, so it is only for the person who asked for it (and for an
    # administrator, who can already read everything).
    owner: Optional[str] = None
    # Custom rules the user ticked, as {engine: [name, ...]}.
    custom_rules: dict[str, list[str]] = Field(default_factory=dict)
    # Published rulesets per tool, as {tool: [ruleset, ...]}; empty uses the
    # configured default.
    rulesets: dict[str, list[str]] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: _now())
    started_at: str = ""
    finished_at: str = ""
    results: dict[str, ToolResult] = Field(default_factory=dict)
    summary: dict[str, int] = Field(default_factory=dict)
    progress: dict[str, int] = Field(default_factory=dict)
    inventory: dict = Field(default_factory=dict)   # file count / size / languages
    # Third-party packages and their licences. Separate from findings: a
    # dependency is not a problem, it is a fact about the project.
    sbom: dict = Field(default_factory=dict)
    applicability: list[dict] = Field(default_factory=list)  # per-tool, set at pause
    stage: str = ""            # human-readable current step (e.g. "cloning repo")
    error: str = ""
    logs: list[str] = Field(default_factory=list)
    policy_evaluation: dict = Field(default_factory=dict)

    def compute_progress(self) -> "Job":
        total = len(self.results)
        finished = sum(1 for r in self.results.values()
                       if r.phase == ToolPhase.FINISHED)
        running = sum(1 for r in self.results.values()
                      if r.phase == ToolPhase.RUNNING)
        self.progress = {
            "total": total,
            "finished": finished,
            "running": running,
            "pending": total - finished - running,
            "percent": int(finished * 100 / total) if total else 0,
        }
        return self

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
