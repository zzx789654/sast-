"""Built-in scan policy templates and result evaluation."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from .models import Finding, Job, Severity


class PolicyDefinition(BaseModel):
    id: str
    name: str
    description: str
    block_critical: bool
    high_requires_review: bool
    block_secrets: bool
    exception_requires_owner_reason_expiry: bool
    report_retention_days: int = Field(ge=1)
    require_pull_request_scan: bool
    require_release_scan: bool

    @property
    def required_events(self) -> list[str]:
        events: list[str] = []
        if self.require_pull_request_scan:
            events.append("pull_request")
        if self.require_release_scan:
            events.append("release")
        return events

    def as_dict(self) -> dict[str, Any]:
        data = self.model_dump()
        data["required_events"] = self.required_events
        return data


RULE_CATALOG = [
    {"id": "critical_block", "title": "Critical findings / Critical 一律阻擋",
     "description": "A Critical finding changes the scan decision to blocked."},
    {"id": "high_manual_review", "title": "High findings / High 需要人工審查",
     "description": "A High finding changes a clean decision to manual review."},
    {"id": "secret_block", "title": "Secrets / Secret 一律阻擋",
     "description": "A secret finding changes the scan decision to blocked."},
    {"id": "false_positive_exception", "title": "False-positive exception / 誤報例外",
     "description": "Exceptions must record an owner, reason, and expiry date."},
    {"id": "report_retention", "title": "Report retention / 報告保存期限",
     "description": "Requested report retention period in days."},
    {"id": "pipeline_events", "title": "PR and release scans / PR 與 Release 前掃描",
     "description": "Declares whether scans are required before pull requests and releases."},
]


POLICY_TEMPLATES = {
    "standard": PolicyDefinition(
        id="standard", name="Standard / 標準",
        description="阻擋 Critical 與 Secret；High 需要人工審查；適合一般團隊日常掃描。",
        block_critical=True, high_requires_review=True, block_secrets=True,
        exception_requires_owner_reason_expiry=True, report_retention_days=30,
        require_pull_request_scan=False, require_release_scan=False,
    ),
    "strict": PolicyDefinition(
        id="strict", name="Strict / 嚴格",
        description="所有 PR 與 Release 前都必須掃描，並阻擋 Critical、Secret，High 需審查。",
        block_critical=True, high_requires_review=True, block_secrets=True,
        exception_requires_owner_reason_expiry=True, report_retention_days=90,
        require_pull_request_scan=True, require_release_scan=True,
    ),
    "report_only": PolicyDefinition(
        id="report_only", name="Report-only / 僅報告",
        description="只產生報告，不阻擋掃描；適合導入初期建立基準線。",
        block_critical=False, high_requires_review=False, block_secrets=False,
        exception_requires_owner_reason_expiry=True, report_retention_days=7,
        require_pull_request_scan=False, require_release_scan=False,
    ),
}

_OVERRIDE_KEYS = {
    "block_critical", "high_requires_review", "block_secrets",
    "exception_requires_owner_reason_expiry", "report_retention_days",
    "require_pull_request_scan", "require_release_scan",
}


def get_policy(policy_id: str) -> PolicyDefinition:
    try:
        return POLICY_TEMPLATES[policy_id]
    except KeyError as exc:
        choices = ", ".join(sorted(POLICY_TEMPLATES))
        raise ValueError(f"unknown policy '{policy_id}'; choose one of: {choices}") from exc


def customize_policy(policy_id: str, overrides: dict[str, Any]) -> PolicyDefinition:
    """Create a validated, per-scan policy from a built-in template."""
    base = get_policy(policy_id)
    unknown = set(overrides) - _OVERRIDE_KEYS
    if unknown:
        raise ValueError(f"unknown policy rule(s): {', '.join(sorted(unknown))}")
    data = base.model_dump()
    for key, value in overrides.items():
        if key == "report_retention_days":
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 3650:
                raise ValueError("report_retention_days must be an integer from 1 to 3650")
        elif not isinstance(value, bool):
            raise ValueError(f"{key} must be a boolean")
        data[key] = value
    data["id"] = f"{base.id}_custom"
    data["name"] = f"{base.name} / Custom"
    data["description"] = f"Customized from {base.name}; each policy rule is independently configured."
    return PolicyDefinition(**data)


def list_policies() -> dict[str, Any]:
    return {
        "rules": RULE_CATALOG,
        "templates": [
            {**policy.as_dict(), "rules": _rule_values(policy)}
            for policy in POLICY_TEMPLATES.values()
        ],
        "default": "standard",
    }


def _rule_values(policy: PolicyDefinition) -> dict[str, Any]:
    return {
        "critical_block": policy.block_critical,
        "high_manual_review": policy.high_requires_review,
        "secret_block": policy.block_secrets,
        "false_positive_exception": policy.exception_requires_owner_reason_expiry,
        "report_retention_days": policy.report_retention_days,
        "require_pull_request_scan": policy.require_pull_request_scan,
        "require_release_scan": policy.require_release_scan,
    }


def evaluate_policy(job: Job) -> dict[str, Any]:
    """Evaluate normalized findings and return an auditable policy decision."""
    policy = PolicyDefinition(**job.policy) if job.policy else get_policy(job.policy_id)
    findings = [finding for result in job.results.values() for finding in result.findings]
    active_exceptions = [e for e in job.exceptions if _exception_active(e)]
    exceptioned = [f for f in findings if _is_excepted(f, active_exceptions)]
    findings = [f for f in findings if f not in exceptioned]
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    high = [f for f in findings if f.severity == Severity.HIGH]
    secrets = [f for f in findings if _is_secret(f)]

    blocking: list[Finding] = []
    if policy.block_critical:
        blocking.extend(critical)
    if policy.block_secrets:
        blocking.extend(f for f in secrets if f not in blocking)

    if blocking:
        decision = "blocked"
    elif policy.high_requires_review and high:
        decision = "manual_review"
    else:
        decision = "passed"

    return {
        "policy_id": policy.id,
        "decision": decision,
        "blocking_findings": [_finding_ref(f) for f in blocking],
        "manual_review_findings": [_finding_ref(f) for f in high] if decision == "manual_review" else [],
        "counts": {"critical": len(critical), "high": len(high),
                    "secrets": len(secrets), "total": len(findings),
                    "excepted": len(exceptioned)},
        "exceptions": active_exceptions,
        "exception_requirements": {
            "owner": policy.exception_requires_owner_reason_expiry,
            "reason": policy.exception_requires_owner_reason_expiry,
            "expiry": policy.exception_requires_owner_reason_expiry,
        },
        "report_retention_days": policy.report_retention_days,
        "required_events": policy.required_events,
    }


def _is_secret(finding: Finding) -> bool:
    return finding.tool == "gitleaks" or finding.extra.get("category") == "secret"


def _is_excepted(finding: Finding, exceptions: list[dict]) -> bool:
    return any(
        item.get("tool") == finding.tool
        and item.get("rule_id") == finding.rule_id
        and item.get("file") == finding.file
        and item.get("start_line") == finding.start_line
        for item in exceptions
    )


def _exception_active(item: dict) -> bool:
    try:
        expiry = datetime.fromisoformat(str(item["expires_at"]).replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry > datetime.now(timezone.utc)
    except (KeyError, TypeError, ValueError):
        return False


def _finding_ref(finding: Finding) -> dict[str, Any]:
    return {"tool": finding.tool, "rule_id": finding.rule_id,
            "file": finding.file, "start_line": finding.start_line,
            "severity": finding.severity.value}
