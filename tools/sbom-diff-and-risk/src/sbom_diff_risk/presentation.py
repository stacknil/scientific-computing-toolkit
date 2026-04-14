from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .policy_models import PolicyConfig, PolicyEvaluation, PolicyViolation


@dataclass(slots=True, frozen=True)
class RuleCatalogEntry:
    rule_id: str
    kind: str
    description: str
    finding_buckets: tuple[str, ...] = ()


_RULE_CATALOG = (
    RuleCatalogEntry(
        rule_id="new_package",
        kind="risk_finding",
        description="Component is present only in the after input.",
        finding_buckets=("new_package",),
    ),
    RuleCatalogEntry(
        rule_id="major_upgrade",
        kind="risk_finding",
        description="Version change is a parseable SemVer major upgrade.",
        finding_buckets=("major_upgrade",),
    ),
    RuleCatalogEntry(
        rule_id="version_change_unclassified",
        kind="risk_finding",
        description="Version changed but could not be classified as a reliable major SemVer upgrade.",
        finding_buckets=("version_change_unclassified",),
    ),
    RuleCatalogEntry(
        rule_id="unknown_license",
        kind="risk_finding",
        description="License metadata is missing, empty, UNKNOWN, or NOASSERTION.",
        finding_buckets=("unknown_license",),
    ),
    RuleCatalogEntry(
        rule_id="suspicious_source",
        kind="risk_finding",
        description="Source provenance is missing or points to a suspicious scheme, path, or host.",
        finding_buckets=("suspicious_source",),
    ),
    RuleCatalogEntry(
        rule_id="stale_package",
        kind="risk_finding",
        description="Staleness check result. Offline mode maps this rule to not_evaluated instead of guessing.",
        finding_buckets=("stale_package", "not_evaluated"),
    ),
    RuleCatalogEntry(
        rule_id="max_added_packages",
        kind="policy_check",
        description="Added package count exceeded the configured deterministic threshold.",
    ),
    RuleCatalogEntry(
        rule_id="allow_sources",
        kind="policy_check",
        description="Component source host was not present in the configured allow_sources list.",
    ),
)


def build_policy_report_sections(policy_evaluation: PolicyEvaluation | None) -> dict[str, Any]:
    evaluation_dict = policy_evaluation_to_dict(policy_evaluation)
    return {
        "policy_evaluation": evaluation_dict,
        "blocking_findings": [
            policy_violation_to_dict(item) for item in effective_policy_evaluation(policy_evaluation).blocking_violations
        ],
        "warning_findings": [
            policy_violation_to_dict(item) for item in effective_policy_evaluation(policy_evaluation).warning_violations
        ],
        "suppressed_findings": [
            policy_violation_to_dict(item) for item in effective_policy_evaluation(policy_evaluation).suppressed_violations
        ],
        "rule_catalog": rule_catalog_to_dict(),
    }


def effective_policy_evaluation(policy_evaluation: PolicyEvaluation | None) -> PolicyEvaluation:
    if policy_evaluation is not None:
        return policy_evaluation
    return PolicyEvaluation(applied=False, policy_path=None, effective_policy=None, exit_code=0)


def policy_evaluation_to_dict(policy_evaluation: PolicyEvaluation | None) -> dict[str, Any]:
    resolved = effective_policy_evaluation(policy_evaluation)
    return {
        "applied": resolved.applied,
        "policy_path": resolved.policy_path,
        "effective_policy": policy_config_to_dict(resolved.effective_policy),
        "blocking_violations": [policy_violation_to_dict(item) for item in resolved.blocking_violations],
        "warning_violations": [policy_violation_to_dict(item) for item in resolved.warning_violations],
        "suppressed_violations": [policy_violation_to_dict(item) for item in resolved.suppressed_violations],
        "totals": {
            "blocking": len(resolved.blocking_violations),
            "warning": len(resolved.warning_violations),
            "suppressed": len(resolved.suppressed_violations),
            "ignored_checks": resolved.ignored_checks,
        },
        "exit_code": resolved.exit_code,
    }


def policy_config_to_dict(policy: PolicyConfig | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    return {
        "version": policy.version,
        "block_on": list(policy.block_on),
        "warn_on": list(policy.warn_on),
        "max_added_packages": policy.max_added_packages,
        "allow_sources": list(policy.allow_sources),
        "ignore_rules": list(policy.ignore_rules),
    }


def policy_violation_to_dict(violation: PolicyViolation) -> dict[str, Any]:
    return {
        "rule_id": violation.rule_id,
        "level": violation.level.value if violation.level is not None else None,
        "message": violation.message,
        "component_key": violation.component_key,
        "component_name": violation.component_name,
        "finding_bucket": violation.finding_bucket,
        "suppression_reason": violation.suppression_reason,
    }


def rule_catalog_to_dict() -> dict[str, dict[str, Any]]:
    return {
        entry.rule_id: {
            "rule_id": entry.rule_id,
            "kind": entry.kind,
            "description": entry.description,
            "finding_buckets": list(entry.finding_buckets),
        }
        for entry in _RULE_CATALOG
    }


def summarize_violations_by_rule(violations: list[PolicyViolation]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for violation in violations:
        counts[violation.rule_id] = counts.get(violation.rule_id, 0) + 1
    return sorted(counts.items())
