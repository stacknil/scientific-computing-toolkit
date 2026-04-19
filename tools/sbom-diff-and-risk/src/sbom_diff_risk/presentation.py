from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from .diffing import component_key
from .enrichment import enrichment_metadata_to_dict
from .models import CompareReport, Component, ProvenanceStatus, ScorecardStatus
from .policy_models import (
    PolicyConfig,
    PolicyEvaluation,
    PolicyViolation,
    V2_PROVENANCE_POLICY_RULE_IDS,
    V3_SCORECARD_POLICY_RULE_IDS,
)


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
    RuleCatalogEntry(
        rule_id="missing_attestation",
        kind="provenance_signal",
        description="PyPI release metadata was fetched, but no attestations were published for the package release.",
    ),
    RuleCatalogEntry(
        rule_id="unverified_provenance",
        kind="provenance_signal",
        description="PyPI attestations were present, but provenance could not be verified against publisher metadata.",
    ),
    RuleCatalogEntry(
        rule_id="provenance_unavailable",
        kind="provenance_signal",
        description="PyPI provenance evidence was unavailable because enrichment was disabled, unsupported, or errored.",
    ),
    RuleCatalogEntry(
        rule_id="provenance_required",
        kind="policy_check",
        description="A configured provenance requirement was not satisfied for the component.",
    ),
    RuleCatalogEntry(
        rule_id="scorecard_below_threshold",
        kind="policy_check",
        description="A mapped repository's OpenSSF Scorecard score was below the configured minimum threshold.",
    ),
)


def build_policy_report_sections(policy_evaluation: PolicyEvaluation | None) -> dict[str, Any]:
    evaluation_dict = policy_evaluation_to_dict(policy_evaluation)
    provenance_policy = provenance_policy_summary(policy_evaluation)
    return {
        "policy_evaluation": evaluation_dict,
        "provenance_policy": provenance_policy,
        "provenance_policy_impact": provenance_policy,
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
    payload = {
        "version": policy.version,
        "block_on": list(policy.block_on),
        "warn_on": list(policy.warn_on),
        "max_added_packages": policy.max_added_packages,
        "allow_sources": list(policy.allow_sources),
        "ignore_rules": list(policy.ignore_rules),
    }
    if policy.version >= 2:
        payload.update(
            {
                "require_attestations_for_new_packages": policy.require_attestations_for_new_packages,
                "require_provenance_for_suspicious_sources": policy.require_provenance_for_suspicious_sources,
                "allow_unattested_packages": list(policy.allow_unattested_packages),
                "allow_provenance_publishers": list(policy.allow_provenance_publishers),
            }
        )
    if policy.version >= 3:
        payload.update(
            {
                "minimum_scorecard_score": policy.minimum_scorecard_score,
            }
        )
    return payload


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


def build_trust_signal_report_sections(report: CompareReport) -> dict[str, Any]:
    components = _current_state_components(report)
    pypi_components = [component for component in components if component.ecosystem.strip().lower() == "pypi"]
    provenance_components = [component for component in components if component.provenance is not None]
    scorecard_components = [component for component in components if component.scorecard is not None]
    publisher_counts = Counter(
        publisher
        for component in provenance_components
        for file_evidence in component.provenance.files
        for publisher in file_evidence.publisher_kinds
    )
    packages_with_attestation_gaps = [
        {
            "component_key": component_key(component),
            "name": component.name,
            "version": component.version,
            "statuses": [status.value for status in component.provenance.statuses],
        }
        for component in provenance_components
        if _component_has_attestation_gap(component)
    ]
    provenance_summary = {
        "components_in_scope": len(components),
        "pypi_components_in_scope": len(pypi_components),
        "pypi_components_without_provenance": sum(1 for component in pypi_components if component.provenance is None),
        "components_with_provenance": sum(1 for component in provenance_components if _component_has_status(component, ProvenanceStatus.PROVENANCE_AVAILABLE)),
        "components_with_attestations": sum(1 for component in provenance_components if _component_has_status(component, ProvenanceStatus.ATTESTATION_AVAILABLE)),
        "components_with_attestation_gaps": len(packages_with_attestation_gaps),
        "components_with_enrichment_errors": sum(1 for component in provenance_components if _component_has_status(component, ProvenanceStatus.ENRICHMENT_ERROR)),
        "unsupported_components": sum(1 for component in provenance_components if _component_has_status(component, ProvenanceStatus.UNSUPPORTED_FOR_PACKAGE)),
    }
    attestation_summary = {
        "files_evaluated": sum(len(component.provenance.files) for component in provenance_components),
        "files_with_attestations": sum(
            1
            for component in provenance_components
            for file_evidence in component.provenance.files
            if file_evidence.attestation_count > 0
        ),
        "files_without_attestations": sum(
            1
            for component in provenance_components
            for file_evidence in component.provenance.files
            if file_evidence.attestation_count == 0
        ),
        "packages_with_attestation_gaps": packages_with_attestation_gaps,
        "publisher_kind_counts": {publisher: publisher_counts[publisher] for publisher in sorted(publisher_counts)},
    }
    scorecard_results = [
        {
            "component_key": component_key(component),
            "name": component.name,
            "version": component.version,
            "repository": component.scorecard.repository.canonical_name if component.scorecard and component.scorecard.repository else None,
            "repository_source": component.scorecard.repository.source if component.scorecard and component.scorecard.repository else None,
            "status": _primary_scorecard_status(component),
            "score": component.scorecard.score if component.scorecard else None,
            "note": component.scorecard.note if component.scorecard else None,
            "error": component.scorecard.error if component.scorecard else None,
        }
        for component in scorecard_components
    ]
    scorecard_summary = {
        "enabled": report.metadata.enrichment.scorecard_enabled or bool(scorecard_components),
        "components_in_scope": len(components),
        "candidate_components": report.metadata.enrichment.scorecard_candidate_components,
        "supported_components": report.metadata.enrichment.scorecard_supported_components,
        "components_with_mapped_repositories": sum(
            1 for component in scorecard_components if component.scorecard and component.scorecard.repository is not None
        ),
        "components_with_scorecards": sum(
            1 for component in scorecard_components if _component_has_scorecard_status(component, ScorecardStatus.SCORECARD_AVAILABLE)
        ),
        "scorecard_unavailable": sum(
            1 for component in scorecard_components if _component_has_scorecard_status(component, ScorecardStatus.SCORECARD_UNAVAILABLE)
        ),
        "repository_unmapped": sum(
            1 for component in scorecard_components if _component_has_scorecard_status(component, ScorecardStatus.REPOSITORY_UNMAPPED)
        ),
        "components_with_enrichment_errors": sum(
            1 for component in scorecard_components if _component_has_scorecard_status(component, ScorecardStatus.ENRICHMENT_ERROR)
        ),
        "results": scorecard_results,
    }
    trust_signal_notes = _build_trust_signal_notes(
        report,
        provenance_components=provenance_components,
        packages_with_attestation_gaps=packages_with_attestation_gaps,
        publisher_counts=publisher_counts,
        scorecard_components=scorecard_components,
    )
    return {
        "provenance_summary": provenance_summary,
        "attestation_summary": attestation_summary,
        "scorecard_summary": scorecard_summary,
        "enrichment_metadata": enrichment_metadata_to_dict(report.metadata.enrichment),
        "trust_signal_notes": trust_signal_notes,
    }


def provenance_policy_violations(policy_evaluation: PolicyEvaluation | None) -> dict[str, list[PolicyViolation]]:
    resolved = effective_policy_evaluation(policy_evaluation)
    provenance_rule_ids = set(V2_PROVENANCE_POLICY_RULE_IDS)
    return {
        "blocking": [violation for violation in resolved.blocking_violations if violation.rule_id in provenance_rule_ids],
        "warning": [violation for violation in resolved.warning_violations if violation.rule_id in provenance_rule_ids],
        "suppressed": [violation for violation in resolved.suppressed_violations if violation.rule_id in provenance_rule_ids],
    }


def provenance_policy_summary(policy_evaluation: PolicyEvaluation | None) -> dict[str, Any] | None:
    resolved = effective_policy_evaluation(policy_evaluation)
    policy = resolved.effective_policy
    impacts = provenance_policy_violations(policy_evaluation)
    if policy is None or not _policy_has_provenance_configuration(policy):
        if not impacts["blocking"] and not impacts["warning"] and not impacts["suppressed"]:
            return None
        return {
            "configured": False,
            "requirements": {
                "require_attestations_for_new_packages": False,
                "require_provenance_for_suspicious_sources": False,
                "allow_unattested_packages": [],
                "allow_provenance_publishers": [],
            },
            "counts": {
                "blocking": len(impacts["blocking"]),
                "warning": len(impacts["warning"]),
                "suppressed": len(impacts["suppressed"]),
            },
            "blocking": [policy_violation_to_dict(item) for item in impacts["blocking"]],
            "warning": [policy_violation_to_dict(item) for item in impacts["warning"]],
            "suppressed": [policy_violation_to_dict(item) for item in impacts["suppressed"]],
        }
    return {
        "configured": True,
        "requirements": {
            "require_attestations_for_new_packages": policy.require_attestations_for_new_packages,
            "require_provenance_for_suspicious_sources": policy.require_provenance_for_suspicious_sources,
            "allow_unattested_packages": list(policy.allow_unattested_packages),
            "allow_provenance_publishers": list(policy.allow_provenance_publishers),
        },
        "counts": {
            "blocking": len(impacts["blocking"]),
            "warning": len(impacts["warning"]),
            "suppressed": len(impacts["suppressed"]),
        },
        "blocking": [policy_violation_to_dict(item) for item in impacts["blocking"]],
        "warning": [policy_violation_to_dict(item) for item in impacts["warning"]],
        "suppressed": [policy_violation_to_dict(item) for item in impacts["suppressed"]],
    }


def scorecard_policy_violations(policy_evaluation: PolicyEvaluation | None) -> dict[str, list[PolicyViolation]]:
    resolved = effective_policy_evaluation(policy_evaluation)
    scorecard_rule_ids = set(V3_SCORECARD_POLICY_RULE_IDS)
    return {
        "blocking": [violation for violation in resolved.blocking_violations if violation.rule_id in scorecard_rule_ids],
        "warning": [violation for violation in resolved.warning_violations if violation.rule_id in scorecard_rule_ids],
        "suppressed": [violation for violation in resolved.suppressed_violations if violation.rule_id in scorecard_rule_ids],
    }


def _policy_has_provenance_configuration(policy: PolicyConfig) -> bool:
    return any(
        (
            rule in V2_PROVENANCE_POLICY_RULE_IDS
            for rule in (*policy.block_on, *policy.warn_on, *policy.ignore_rules)
        )
    ) or policy.require_attestations_for_new_packages or policy.require_provenance_for_suspicious_sources or bool(
        policy.allow_unattested_packages
    ) or bool(policy.allow_provenance_publishers)


def _current_state_components(report: CompareReport) -> list[Component]:
    components = list(report.components.added)
    components.extend(change.after for change in report.components.changed)
    return components


def _component_has_status(component: Component, status: ProvenanceStatus) -> bool:
    if component.provenance is None:
        return False
    if status in component.provenance.statuses:
        return True
    return any(status in file_evidence.statuses for file_evidence in component.provenance.files)


def _component_has_attestation_gap(component: Component) -> bool:
    if component.provenance is None:
        return False
    return _component_has_status(component, ProvenanceStatus.ATTESTATION_UNAVAILABLE) and not _component_has_status(
        component,
        ProvenanceStatus.ATTESTATION_AVAILABLE,
    )


def _component_has_scorecard_status(component: Component, status: ScorecardStatus) -> bool:
    if component.scorecard is None:
        return False
    return status in component.scorecard.statuses


def _primary_scorecard_status(component: Component) -> str | None:
    if component.scorecard is None or not component.scorecard.statuses:
        return None
    return component.scorecard.statuses[0].value


def _build_trust_signal_notes(
    report: CompareReport,
    *,
    provenance_components: list[Component],
    packages_with_attestation_gaps: list[dict[str, Any]],
    publisher_counts: Counter[str],
    scorecard_components: list[Component],
) -> list[str]:
    notes: list[str] = []
    pypi_component_count = sum(1 for component in _current_state_components(report) if component.ecosystem.strip().lower() == "pypi")
    unsupported_component_count = sum(
        1 for component in provenance_components if _component_has_status(component, ProvenanceStatus.UNSUPPORTED_FOR_PACKAGE)
    )
    if not report.metadata.enrichment.pypi_enabled and not provenance_components:
        if pypi_component_count:
            notes.append("PyPI components are present, but provenance enrichment was not enabled for this run.")
        else:
            notes.append("No opt-in provenance enrichment data is present in this report.")
    if packages_with_attestation_gaps:
        notes.append(
            "Missing attestations indicate an attestation gap for the release; they are not treated as proof of compromise."
        )
    if any(_component_has_status(component, ProvenanceStatus.ENRICHMENT_ERROR) for component in provenance_components):
        notes.append("PyPI enrichment errors are recorded as evidence gaps and only affect policy when configured explicitly.")
    if unsupported_component_count:
        notes.append(
            "Some package versions could not provide provenance evidence from the enrichment source and remain evidence gaps."
        )
    if publisher_counts:
        notes.append(f"Observed attestation publisher kinds: {', '.join(sorted(publisher_counts))}.")
    provenance_impacts = provenance_policy_violations(report.metadata.policy_evaluation)
    impact_count = len(provenance_impacts["blocking"]) + len(provenance_impacts["warning"])
    if impact_count:
        notes.append(f"Policy produced {impact_count} provenance-related blocking or warning decision(s).")
    if report.metadata.enrichment.scorecard_enabled or scorecard_components:
        notes.append("OpenSSF Scorecard results are auxiliary trust signals and are not proof of safety.")
    if any(_component_has_scorecard_status(component, ScorecardStatus.REPOSITORY_UNMAPPED) for component in scorecard_components):
        notes.append("Scorecard lookups are skipped when no high-confidence repository mapping is available.")
    scorecard_impacts = scorecard_policy_violations(report.metadata.policy_evaluation)
    scorecard_impact_count = len(scorecard_impacts["blocking"]) + len(scorecard_impacts["warning"])
    if scorecard_impact_count:
        notes.append(f"Policy produced {scorecard_impact_count} Scorecard-related blocking or warning decision(s).")
    return notes
