from __future__ import annotations

from urllib.parse import urlparse

from .diffing import component_key
from .models import Component, ComponentChange, RiskBucket, RiskFinding
from .policy_models import PolicyConfig, PolicyEvaluation, PolicyLevel, PolicyViolation


def evaluate_policy(
    policy: PolicyConfig | None,
    *,
    policy_path: str | None,
    added: list[Component],
    changed: list[ComponentChange],
    findings: list[RiskFinding],
) -> PolicyEvaluation:
    if policy is None:
        return PolicyEvaluation(applied=False, policy_path=None, effective_policy=None, exit_code=0)

    blocking_violations: list[PolicyViolation] = []
    warning_violations: list[PolicyViolation] = []
    suppressed_violations: list[PolicyViolation] = []
    ignored_checks = 0

    for finding in findings:
        rule_id = finding_rule_id(finding)
        severity = _severity_for_rule(policy, rule_id)
        if rule_id in policy.ignore_rules:
            ignored_checks += 1
            suppressed_violations.append(
                PolicyViolation(
                    rule_id=rule_id,
                    level=severity,
                    message=finding.rationale,
                    component_key=finding.component_key,
                    component_name=finding.component.name,
                    finding_bucket=finding.bucket.value,
                    suppression_reason="ignored_by_policy",
                )
            )
            continue

        if severity is None:
            continue

        violation = PolicyViolation(
            rule_id=rule_id,
            level=severity,
            message=finding.rationale,
            component_key=finding.component_key,
            component_name=finding.component.name,
            finding_bucket=finding.bucket.value,
        )
        _append_violation(violation, blocking_violations, warning_violations)

    if policy.max_added_packages is not None and len(added) > policy.max_added_packages:
        rule_id = "max_added_packages"
        severity = _severity_for_rule(policy, rule_id, default=PolicyLevel.BLOCK)
        violation = PolicyViolation(
            rule_id=rule_id,
            level=severity,
            message=f"Added package count {len(added)} exceeds max_added_packages={policy.max_added_packages}.",
            suppression_reason="ignored_by_policy" if rule_id in policy.ignore_rules else None,
        )
        if rule_id in policy.ignore_rules:
            ignored_checks += 1
            suppressed_violations.append(violation)
        elif severity is not None:
            _append_violation(violation, blocking_violations, warning_violations)

    if policy.allow_sources:
        for component in _components_for_source_policy(added, changed):
            host = _source_host(component.source_url)
            if host in policy.allow_sources:
                continue

            rule_id = "allow_sources"
            severity = _severity_for_rule(policy, rule_id, default=PolicyLevel.BLOCK)
            violation = PolicyViolation(
                rule_id=rule_id,
                level=severity,
                message=f"Source host {host or 'missing'} is not present in allow_sources.",
                component_key=component_key(component),
                component_name=component.name,
                suppression_reason="ignored_by_policy" if rule_id in policy.ignore_rules else None,
            )
            if rule_id in policy.ignore_rules:
                ignored_checks += 1
                suppressed_violations.append(violation)
                continue
            if severity is not None:
                _append_violation(violation, blocking_violations, warning_violations)

    blocking_violations.sort(key=_violation_sort_key)
    warning_violations.sort(key=_violation_sort_key)
    suppressed_violations.sort(key=_violation_sort_key)

    exit_code = 1 if blocking_violations else 0
    return PolicyEvaluation(
        applied=True,
        policy_path=policy_path,
        effective_policy=policy,
        blocking_violations=blocking_violations,
        warning_violations=warning_violations,
        suppressed_violations=suppressed_violations,
        ignored_checks=ignored_checks,
        exit_code=exit_code,
    )


def finding_rule_id(finding: RiskFinding) -> str:
    if finding.bucket in {RiskBucket.STALE_PACKAGE, RiskBucket.NOT_EVALUATED}:
        return "stale_package"
    return finding.bucket.value


def _severity_for_rule(
    policy: PolicyConfig,
    rule_id: str,
    *,
    default: PolicyLevel | None = None,
) -> PolicyLevel | None:
    if rule_id in policy.block_on:
        return PolicyLevel.BLOCK
    if rule_id in policy.warn_on:
        return PolicyLevel.WARN
    return default


def _append_violation(
    violation: PolicyViolation,
    blocking_violations: list[PolicyViolation],
    warning_violations: list[PolicyViolation],
) -> None:
    if violation.level is PolicyLevel.BLOCK:
        blocking_violations.append(violation)
    elif violation.level is PolicyLevel.WARN:
        warning_violations.append(violation)


def _components_for_source_policy(added: list[Component], changed: list[ComponentChange]) -> list[Component]:
    components = list(added)
    components.extend(change.after for change in changed)
    return components


def _source_host(source_url: str | None) -> str | None:
    if not source_url:
        return None
    host = (urlparse(source_url).hostname or "").strip().lower()
    return host or None


def _violation_sort_key(violation: PolicyViolation) -> tuple[str, str, str]:
    return (
        violation.rule_id,
        violation.component_key or "",
        violation.component_name or "",
    )
