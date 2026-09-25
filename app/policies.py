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

from .models import Finding, Job, Severity, ToolStatus

# Severity is judged on the combined findings of every tool that ran, never on
# one tool in particular. A single High from any of them fails the scan.
#
#   critical / high  -> blocked        (must not go live)
#   medium           -> manual_review  (a person decides)
#   low / info / none-> passed
#   ...unless a tool did not finish looking -> manual_review
#
# Secrets are treated as blocking whatever severity the tool gave them: a
# leaked credential is already public, and grading it does not change that.
BLOCKING = (Severity.CRITICAL, Severity.HIGH)
REVIEW = (Severity.MEDIUM,)

# "No findings" means clean only if every tool looked at everything. A tool
# that failed, ran out of time or left files unread cannot vouch for what it
# did not see, so a verdict that would pass goes to a person instead. Not
# installed and nothing-to-scan are not gaps: both are facts about the setup
# or the project, and the tool said so plainly. (User decision, talk.md #021.)
COVERAGE_GAPS = (ToolStatus.ERROR, ToolStatus.TIMEOUT, ToolStatus.INCOMPLETE)

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
    {"id": "incomplete_coverage_review",
     "trigger": "tools:incomplete",
     "effect": "manual_review",
     "sources": ["semgrep", "bearer", "trivy", "npm_audit", "osv_scanner",
                 "gitleaks"],
     "counter": "coverage_gaps"},
    {"id": "low_passes",
     "trigger": "severity:low_or_none",
     "effect": "passed",
     "sources": SEVERITY_SOURCES,
     "counter": "low"},
]


#: A mark that means "this will not be fixed", so the finding no longer
#: counts towards the verdict. "real" is not here: agreeing that a finding is
#: real cannot be a way to dismiss it.
DISMISSED = {"false_positive", "accepted"}


def finding_key(finding: Finding) -> str:
    """The identity of a finding across scans of the same project.

    Matches the key the UI builds, so a mark made while reading one scan
    still applies when the same code is scanned again.
    """
    return "|".join([finding.tool, finding.rule_id, finding.file,
                     str(finding.start_line if finding.start_line is not None
                         else "")])


def evaluate_policy(job: Job, triage: "dict | None" = None) -> dict[str, Any]:
    """Judge the combined findings of every tool that ran.

    `triage` maps a finding key to a recorded judgement. A finding somebody
    has marked a false positive, or knowingly accepted, stops counting --
    with one exception below, and with the count of what was set aside
    reported alongside the verdict so it is never silently smaller.
    """
    triage = triage or {}
    all_findings = [f for result in job.results.values() for f in result.findings]

    dismissed = []
    findings = []
    for f in all_findings:
        mark = triage.get(finding_key(f)) or {}
        if mark.get("verdict") in DISMISSED and not _is_secret(f):
            dismissed.append((f, mark))
        else:
            # A secret is never dismissible. A credential that reached the
            # repository is already exposed, and deciding it is a false
            # positive does not un-expose it -- if it is genuinely not a
            # secret, the fix is a scanner rule, not a verdict override.
            findings.append(f)

    blocking_sev = [f for f in findings if f.severity in BLOCKING]
    secrets = [f for f in findings if _is_secret(f)]
    medium = [f for f in findings if f.severity in REVIEW]
    low = [f for f in findings
           if f.severity in (Severity.LOW, Severity.INFO, Severity.UNKNOWN)]

    # A secret counts as blocking even when its tool graded it lower.
    blocking = list(blocking_sev)
    blocking.extend(f for f in secrets if f not in blocking)

    gaps = [r for r in job.results.values() if r.status in COVERAGE_GAPS]

    if blocking:
        decision = "blocked"
    elif medium or gaps:
        decision = "manual_review"
    else:
        # Low, info or nothing at all, from tools that all finished. Zero
        # findings passes: a clean project is not less safe than one with a
        # single low-severity note.
        decision = "passed"

    return {
        "decision": decision,
        "blocking_findings": [_finding_ref(f) for f in blocking],
        "manual_review_findings": [_finding_ref(f) for f in medium]
                                  if decision == "manual_review" else [],
        # Listed whatever the decision: a blocked scan with a tool that did
        # not finish may have more to find than it shows.
        "coverage_gaps": [
            {"tool": r.tool, "status": r.status.value,
             "reason": (r.error or r.message)[:200],
             "not_analysed": r.skipped[:5]}
            for r in gaps
        ],
        "counts": {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "blocking": len(blocking),
            "medium": len(medium),
            "low": len(low),
            "secrets": len(secrets),
            "coverage_gaps": len(gaps),
            "total": len(findings),
            # Both numbers, always: a verdict reached by setting findings
            # aside should never look like a verdict reached by having none.
            "dismissed": len(dismissed),
            "total_before_triage": len(all_findings),
        },
        "dismissed_findings": [
            dict(_finding_ref(f), verdict=mark.get("verdict", ""),
                 marked_by=mark.get("marked_by", ""),
                 marked_at=mark.get("marked_at", ""),
                 note=mark.get("note", ""))
            for f, mark in dismissed
        ],
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
