from __future__ import annotations

from .models import CompareReport, Component, EvidenceConfidence

_SBOM_FORMATS = {"cyclonedx-json", "spdx-json"}


def evidence_confidence_for_report(report: CompareReport) -> EvidenceConfidence:
    if report.metadata.evidence_confidence is not None:
        return report.metadata.evidence_confidence

    if _has_enrichment_evidence(report):
        if _has_live_enrichment(report):
            return EvidenceConfidence.ENRICHMENT_LIVE
        return EvidenceConfidence.ENRICHMENT_MOCKED

    if _has_policy_match(report):
        return EvidenceConfidence.POLICY_MATCHED

    if _has_sbom_input(report):
        return EvidenceConfidence.SBOM_PRESENT

    return EvidenceConfidence.LOCAL_MANIFEST_ONLY


def evidence_confidence_value(report: CompareReport) -> str:
    return evidence_confidence_for_report(report).value


def _has_enrichment_evidence(report: CompareReport) -> bool:
    metadata = report.metadata.enrichment
    if metadata.pypi_enabled or metadata.scorecard_enabled:
        return True

    return any(component.provenance is not None or component.scorecard is not None for component in _all_components(report))


def _has_live_enrichment(report: CompareReport) -> bool:
    metadata = report.metadata.enrichment
    return (
        metadata.network_access_performed
        or metadata.pypi_network_access_performed
        or metadata.scorecard_network_access_performed
    )


def _has_policy_match(report: CompareReport) -> bool:
    evaluation = report.metadata.policy_evaluation
    if evaluation is None or not evaluation.applied:
        return False

    return bool(evaluation.blocking_violations or evaluation.warning_violations or evaluation.suppressed_violations)


def _has_sbom_input(report: CompareReport) -> bool:
    return report.metadata.before_format in _SBOM_FORMATS or report.metadata.after_format in _SBOM_FORMATS


def _all_components(report: CompareReport) -> tuple[Component, ...]:
    components: list[Component] = [*report.components.added, *report.components.removed]
    for change in report.components.changed:
        components.append(change.before)
        components.append(change.after)
    return tuple(components)
