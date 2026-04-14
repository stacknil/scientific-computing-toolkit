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
    ignored_checks = 0

    for finding in findings:
        rule_id = finding_rule_id(finding)
        if rule_id in policy.ignore_rules:
            ignored_checks += 1
            continue

        level = _severity_for_rule(policy, rule_id)
        if level is None:
            continue

        violation = PolicyViolation(
            rule_id=rule_id,
            level=level,
            message=finding.rationale,
            component_key=finding.component_key,
            component_name=finding.component.name,
            finding_bucket=finding.bucket.value,
        )
        _append_violation(violation, blocking_violations, warning_violations)

    if policy.max_added_packages is not None and len(added) > policy.max_added_packages:
        rule_id = "max_added_packages"
        if rule_id in policy.ignore_rules:
            ignored_checks += 1
        else:
            level = _severity_for_rule(policy, rule_id, default=PolicyLevel.BLOCK)
            if level is not None:
                violation = PolicyViolation(
                    rule_id=rule_id,
                    level=level,
                    message=(
                        f"Added package count {len(added)} exceeds max_added_packages="
                        f"{policy.max_added_packages}."
                    ),
                )
                _append_violation(violation, blocking_violations, warning_violations)

    if policy.allow_sources:
        for component in _components_for_source_policy(added, changed):
            host = _source_host(component.source_url)
            if host in policy.allow_sources:
                continue

            rule_id = "allow_sources"
            if rule_id in policy.ignore_rules:
                ignored_checks += 1
                continue

            level = _severity_for_rule(policy, rule_id, default=PolicyLevel.BLOCK)
            if level is None:
                continue

            violation = PolicyViolation(
                rule_id=rule_id,
                level=level,
                message=f"Source host {host} is not present in allow_sources.",
                component_key=component_key(component),
                component_name=component.name,
            )
            _append_violation(violation, blocking_violations, warning_violations)

    exit_code = 1 if blocking_violations else 0
    return PolicyEvaluation(
        applied=True,
        policy_path=policy_path,
        effective_policy=policy,
        blocking_violations=blocking_violations,
        warning_violations=warning_violations,
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
    else:
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
