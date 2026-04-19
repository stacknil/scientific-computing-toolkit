from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .diffing import component_key
from .models import Component, ComponentChange, ProvenanceStatus, RiskBucket, RiskFinding, ScorecardStatus
from .policy_models import PolicyConfig, PolicyEvaluation, PolicyLevel, PolicyViolation


@dataclass(slots=True, frozen=True)
class ProvenanceAssessment:
    attestation_available: bool
    provenance_unavailable: bool
    verified: bool
    publisher_kinds: tuple[str, ...]
    unavailable_message: str | None = None
    unverified_message: str | None = None


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
        ignored_checks += _record_violation(
            policy,
            severity=severity,
            violation=PolicyViolation(
                rule_id=rule_id,
                level=severity,
                message=finding.rationale,
                component_key=finding.component_key,
                component_name=finding.component.name,
                finding_bucket=finding.bucket.value,
            ),
            blocking_violations=blocking_violations,
            warning_violations=warning_violations,
            suppressed_violations=suppressed_violations,
        )

    provenance_components = _components_for_policy(added, changed)
    added_pypi_keys = {
        component_key(item)
        for item in added
        if item.ecosystem.strip().lower() == "pypi"
    }
    suspicious_source_keys = {
        finding.component_key
        for finding in findings
        if finding_rule_id(finding) == "suspicious_source"
    }
    for component in provenance_components:
        if component.ecosystem.strip().lower() != "pypi":
            continue
        package_is_unattested_allowed = _package_is_unattested_allowed(policy, component)
        assessment = _assess_provenance(component, policy)

        # Keep allow_unattested_packages narrow and explicit: it waives only
        # missing-attestation checks, not complete provenance unavailability.
        if assessment.provenance_unavailable:
            severity = _severity_for_rule(policy, "provenance_unavailable")
            ignored_checks += _record_violation(
                policy,
                severity=severity,
                violation=PolicyViolation(
                    rule_id="provenance_unavailable",
                    level=severity,
                    message=assessment.unavailable_message or "PyPI provenance evidence is unavailable.",
                    component_key=component_key(component),
                    component_name=component.name,
                ),
                blocking_violations=blocking_violations,
                warning_violations=warning_violations,
                suppressed_violations=suppressed_violations,
            )
        elif not assessment.attestation_available and not package_is_unattested_allowed:
            severity = _severity_for_rule(policy, "missing_attestation")
            ignored_checks += _record_violation(
                policy,
                severity=severity,
                violation=PolicyViolation(
                    rule_id="missing_attestation",
                    level=severity,
                    message="PyPI release metadata was fetched, but no attestations were published for this package release.",
                    component_key=component_key(component),
                    component_name=component.name,
                ),
                blocking_violations=blocking_violations,
                warning_violations=warning_violations,
                suppressed_violations=suppressed_violations,
            )

        if assessment.attestation_available and not assessment.verified:
            severity = _severity_for_rule(policy, "unverified_provenance")
            ignored_checks += _record_violation(
                policy,
                severity=severity,
                violation=PolicyViolation(
                    rule_id="unverified_provenance",
                    level=severity,
                    message=assessment.unverified_message or "PyPI provenance could not be verified.",
                    component_key=component_key(component),
                    component_name=component.name,
                ),
                blocking_violations=blocking_violations,
                warning_violations=warning_violations,
                suppressed_violations=suppressed_violations,
            )

        requirement_contexts: list[str] = []
        if policy.require_attestations_for_new_packages and component_key(component) in added_pypi_keys:
            requirement_contexts.append("new package")
        if (
            policy.require_provenance_for_suspicious_sources
            and component_key(component) in suspicious_source_keys
        ):
            requirement_contexts.append("suspicious source")

        if requirement_contexts:
            requirement_message = _provenance_requirement_message(
                assessment,
                requirement_contexts,
                package_is_unattested_allowed=package_is_unattested_allowed,
            )
            if requirement_message is not None:
                severity = _severity_for_rule(policy, "provenance_required", default=PolicyLevel.BLOCK)
                ignored_checks += _record_violation(
                    policy,
                    severity=severity,
                    violation=PolicyViolation(
                        rule_id="provenance_required",
                        level=severity,
                        message=requirement_message,
                        component_key=component_key(component),
                        component_name=component.name,
                    ),
                    blocking_violations=blocking_violations,
                    warning_violations=warning_violations,
                    suppressed_violations=suppressed_violations,
                )

    if policy.max_added_packages is not None and len(added) > policy.max_added_packages:
        rule_id = "max_added_packages"
        severity = _severity_for_rule(policy, rule_id, default=PolicyLevel.BLOCK)
        ignored_checks += _record_violation(
            policy,
            severity=severity,
            violation=PolicyViolation(
                rule_id=rule_id,
                level=severity,
                message=f"Added package count {len(added)} exceeds max_added_packages={policy.max_added_packages}.",
            ),
            blocking_violations=blocking_violations,
            warning_violations=warning_violations,
            suppressed_violations=suppressed_violations,
        )

    if policy.allow_sources:
        for component in provenance_components:
            host = _source_host(component.source_url)
            if host in policy.allow_sources:
                continue

            rule_id = "allow_sources"
            severity = _severity_for_rule(policy, rule_id, default=PolicyLevel.BLOCK)
            ignored_checks += _record_violation(
                policy,
                severity=severity,
                violation=PolicyViolation(
                    rule_id=rule_id,
                    level=severity,
                    message=f"Source host {host or 'missing'} is not present in allow_sources.",
                    component_key=component_key(component),
                    component_name=component.name,
                ),
                blocking_violations=blocking_violations,
                warning_violations=warning_violations,
                    suppressed_violations=suppressed_violations,
                )

    if policy.minimum_scorecard_score is not None:
        rule_id = "scorecard_below_threshold"
        severity = _severity_for_rule(policy, rule_id)
        for component in provenance_components:
            scorecard_score = _scorecard_score(component)
            if scorecard_score is None or scorecard_score >= policy.minimum_scorecard_score:
                continue
            repository_name = (
                component.scorecard.repository.canonical_name
                if component.scorecard is not None and component.scorecard.repository is not None
                else "unmapped-repository"
            )
            ignored_checks += _record_violation(
                policy,
                severity=severity,
                violation=PolicyViolation(
                    rule_id=rule_id,
                    level=severity,
                    message=(
                        f"Scorecard score {scorecard_score:.1f} is below minimum_scorecard_score="
                        f"{policy.minimum_scorecard_score:.1f} for repository {repository_name}."
                    ),
                    component_key=component_key(component),
                    component_name=component.name,
                ),
                blocking_violations=blocking_violations,
                warning_violations=warning_violations,
                suppressed_violations=suppressed_violations,
            )

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


def _record_violation(
    policy: PolicyConfig,
    *,
    severity: PolicyLevel | None,
    violation: PolicyViolation,
    blocking_violations: list[PolicyViolation],
    warning_violations: list[PolicyViolation],
    suppressed_violations: list[PolicyViolation],
) -> int:
    if violation.rule_id in policy.ignore_rules:
        suppressed_violations.append(
            PolicyViolation(
                rule_id=violation.rule_id,
                level=severity,
                message=violation.message,
                component_key=violation.component_key,
                component_name=violation.component_name,
                finding_bucket=violation.finding_bucket,
                suppression_reason="ignored_by_policy",
            )
        )
        return 1
    if severity is None:
        return 0

    _append_violation(
        PolicyViolation(
            rule_id=violation.rule_id,
            level=severity,
            message=violation.message,
            component_key=violation.component_key,
            component_name=violation.component_name,
            finding_bucket=violation.finding_bucket,
        ),
        blocking_violations,
        warning_violations,
    )
    return 0


def _append_violation(
    violation: PolicyViolation,
    blocking_violations: list[PolicyViolation],
    warning_violations: list[PolicyViolation],
) -> None:
    if violation.level is PolicyLevel.BLOCK:
        blocking_violations.append(violation)
    elif violation.level is PolicyLevel.WARN:
        warning_violations.append(violation)


def _components_for_policy(added: list[Component], changed: list[ComponentChange]) -> list[Component]:
    components = list(added)
    components.extend(change.after for change in changed)
    return components


def _package_is_unattested_allowed(policy: PolicyConfig, component: Component) -> bool:
    return component.name.strip().lower() in set(policy.allow_unattested_packages)


def _assess_provenance(component: Component, policy: PolicyConfig) -> ProvenanceAssessment:
    provenance = component.provenance
    if provenance is None:
        return ProvenanceAssessment(
            attestation_available=False,
            provenance_unavailable=True,
            verified=False,
            publisher_kinds=(),
            unavailable_message="PyPI provenance evidence is unavailable because enrichment was not enabled for this run.",
        )

    status_set = set(provenance.statuses)
    if ProvenanceStatus.ENRICHMENT_ERROR in status_set:
        return ProvenanceAssessment(
            attestation_available=False,
            provenance_unavailable=True,
            verified=False,
            publisher_kinds=(),
            unavailable_message=provenance.error or "PyPI provenance evidence could not be fetched due to an enrichment error.",
        )
    if ProvenanceStatus.UNSUPPORTED_FOR_PACKAGE in status_set:
        return ProvenanceAssessment(
            attestation_available=False,
            provenance_unavailable=True,
            verified=False,
            publisher_kinds=(),
            unavailable_message="PyPI provenance evidence is unavailable for this package or version.",
        )

    attestation_available = _status_present(provenance.statuses, ProvenanceStatus.ATTESTATION_AVAILABLE) or any(
        _status_present(item.statuses, ProvenanceStatus.ATTESTATION_AVAILABLE)
        for item in provenance.files
    )
    publisher_kinds = tuple(
        sorted(
            {
                publisher.strip().lower()
                for item in provenance.files
                for publisher in item.publisher_kinds
                if publisher.strip()
            }
        )
    )
    verified = _publishers_are_verified(publisher_kinds, policy.allow_provenance_publishers) if attestation_available else False
    unverified_message = None
    if attestation_available and not verified:
        if policy.allow_provenance_publishers:
            allowlist = ", ".join(policy.allow_provenance_publishers)
            actual = ", ".join(publisher_kinds) if publisher_kinds else "missing"
            unverified_message = (
                f"PyPI attestations were present, but publisher kinds {actual} did not match "
                f"allow_provenance_publishers={allowlist}."
            )
        else:
            unverified_message = "PyPI attestations were present, but no publisher identity was available to verify provenance."

    return ProvenanceAssessment(
        attestation_available=attestation_available,
        provenance_unavailable=False,
        verified=verified,
        publisher_kinds=publisher_kinds,
        unverified_message=unverified_message,
    )


def _status_present(statuses: tuple[ProvenanceStatus, ...], candidate: ProvenanceStatus) -> bool:
    return candidate in statuses


def _publishers_are_verified(publisher_kinds: tuple[str, ...], allowlist: tuple[str, ...]) -> bool:
    if not publisher_kinds:
        return False
    if not allowlist:
        return True
    return any(publisher in set(allowlist) for publisher in publisher_kinds)


def _scorecard_score(component: Component) -> float | None:
    if component.scorecard is None:
        return None
    if ScorecardStatus.SCORECARD_AVAILABLE not in component.scorecard.statuses:
        return None
    return component.scorecard.score


def _provenance_requirement_message(
    assessment: ProvenanceAssessment,
    requirement_contexts: list[str],
    *,
    package_is_unattested_allowed: bool,
) -> str | None:
    context_label = " and ".join(requirement_contexts)
    if assessment.provenance_unavailable:
        return f"Provenance is required for {context_label}, but evidence is unavailable: {assessment.unavailable_message}"
    if not assessment.attestation_available:
        if package_is_unattested_allowed:
            return None
        return f"Provenance is required for {context_label}, but no attestations were published for this PyPI package."
    if not assessment.verified:
        return (
            f"Provenance is required for {context_label}, but the available attestations could not be verified: "
            f"{assessment.unverified_message}"
        )
    return None


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
