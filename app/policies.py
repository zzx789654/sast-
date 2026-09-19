"""The single, fixed rule for judging a scan.

There used to be selectable policy templates with per-rule checkboxes. They
made the scan form long and asked the user to decide something that has one
sensible answer, so the rule is now fixed and the form is gone.

A verdict labels the scan. It does not stop a build or a deployment: by the
time it is computed the scan has already finished, and nothing downstream
consumes it. The wording says so rather than implying an enforcement that
does not exist.
"""
from __future__ import annotations

from typing import Any

from .models import Finding, Job, Severity

# Severity is judged on the combined findings of every tool that ran, never on
# one tool in particular. A single High from any of them fails the scan.
#
#   critical / high  -> blocked        (must not go live)
#   medium           -> manual_review  (a person decides)
#   low / info / none-> passed
#
# Secrets are treated as blocking whatever severity the tool gave them: a
# leaked credential is already public, and grading it does not change that.
BLOCKING = (Severity.CRITICAL, Severity.HIGH)
REVIEW = (Severity.MEDIUM,)

# Which tools can produce each kind of finding. Shown in the UI so it is clear
# the rule spans all tools rather than belonging to one of them.
SEVERITY_SOURCES = ["semgrep", "bearer", "trivy", "npm_audit", "osv_scanner"]
SECRET_SOURCES = ["gitleaks", "trivy"]

# The rules, in the order they are evaluated, for the UI to render.
RULE_CATALOG = [
    {"id": "block_high_and_above",
     "trigger": "severity:critical_high",
     "effect": "blocked",
     "sources": SEVERITY_SOURCES,
     "counter": "blocking"},
    {"id": "secret_block",
     "trigger": "kind:secret",
     "effect": "blocked",
     "sources": SECRET_SOURCES,
     "counter": "secrets"},
    {"id": "medium_manual_review",
     "trigger": "severity:medium",
     "effect": "manual_review",
     "sources": SEVERITY_SOURCES,
     "counter": "medium"},
    {"id": "low_passes",
     "trigger": "severity:low_or_none",
     "effect": "passed",
     "sources": SEVERITY_SOURCES,
     "counter": "low"},
]


def evaluate_policy(job: Job) -> dict[str, Any]:
    """Judge the combined findings of every tool that ran."""
    findings = [f for result in job.results.values() for f in result.findings]

    blocking_sev = [f for f in findings if f.severity in BLOCKING]
    secrets = [f for f in findings if _is_secret(f)]
    medium = [f for f in findings if f.severity in REVIEW]
    low = [f for f in findings
           if f.severity in (Severity.LOW, Severity.INFO, Severity.UNKNOWN)]

    # A secret counts as blocking even when its tool graded it lower.
    blocking = list(blocking_sev)
    blocking.extend(f for f in secrets if f not in blocking)

    if blocking:
        decision = "blocked"
    elif medium:
        decision = "manual_review"
    else:
        # Low, info or nothing at all. Zero findings passes: a clean project is
        # not less safe than one with a single low-severity note.
        decision = "passed"

    return {
        "decision": decision,
        "blocking_findings": [_finding_ref(f) for f in blocking],
        "manual_review_findings": [_finding_ref(f) for f in medium]
                                  if decision == "manual_review" else [],
        "counts": {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "blocking": len(blocking),
            "medium": len(medium),
            "low": len(low),
            "secrets": len(secrets),
            "total": len(findings),
        },
        "rules": RULE_CATALOG,
    }


def _is_secret(finding: Finding) -> bool:
    return finding.tool == "gitleaks" or finding.extra.get("category") == "secret"


def _finding_ref(finding: Finding) -> dict[str, Any]:
    return {
        "tool": finding.tool,
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "title": finding.title,
        "file": finding.file,
        "line": finding.start_line,
    }
