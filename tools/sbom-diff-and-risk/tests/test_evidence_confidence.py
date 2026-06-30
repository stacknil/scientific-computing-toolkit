from __future__ import annotations

from sbom_diff_risk.evidence_confidence import evidence_confidence_for_report
from sbom_diff_risk.models import (
    CompareReport,
    Component,
    EvidenceConfidence,
    ReportComponents,
    ReportEnrichmentMetadata,
    ReportMetadata,
    ReportSummary,
)
from sbom_diff_risk.policy_models import PolicyEvaluation, PolicyLevel, PolicyViolation


def test_evidence_confidence_values_are_release_facing_labels() -> None:
    assert {item.value for item in EvidenceConfidence} == {
        "local_manifest_only",
        "sbom_present",
        "policy_matched",
        "enrichment_recorded",
        "provenance_recorded",
    }


def test_evidence_confidence_defaults_to_local_manifest_only() -> None:
    report = _minimal_report(before_format="requirements-txt", after_format="requirements-txt")

    assert evidence_confidence_for_report(report) is EvidenceConfidence.LOCAL_MANIFEST_ONLY


def test_evidence_confidence_marks_sbom_present() -> None:
    report = _minimal_report(before_format="cyclonedx-json", after_format="cyclonedx-json")

    assert evidence_confidence_for_report(report) is EvidenceConfidence.SBOM_PRESENT


def test_evidence_confidence_marks_policy_matched() -> None:
    report = _minimal_report(
        before_format="requirements-txt",
        after_format="requirements-txt",
        policy_evaluation=PolicyEvaluation(
            applied=True,
            warning_violations=[
                PolicyViolation(
                    rule_id="new_package",
                    level=PolicyLevel.WARN,
                    message="New package matched local policy.",
                )
            ],
        ),
    )
    assert evidence_confidence_for_report(report) is EvidenceConfidence.POLICY_MATCHED


def test_evidence_confidence_marks_provenance_recorded_when_pypi_enrichment_is_used() -> None:
    report = _minimal_report(
        before_format="requirements-txt",
        after_format="requirements-txt",
        enrichment=ReportEnrichmentMetadata(
            mode="opt_in_pypi",
            pypi_enabled=True,
            pypi_network_access_performed=False,
            network_access_performed=False,
        ),
    )

    assert evidence_confidence_for_report(report) is EvidenceConfidence.PROVENANCE_RECORDED


def test_evidence_confidence_marks_enrichment_recorded_when_scorecard_enrichment_is_used() -> None:
    report = _minimal_report(
        before_format="requirements-txt",
        after_format="requirements-txt",
        enrichment=ReportEnrichmentMetadata(
            mode="opt_in_scorecard",
            scorecard_enabled=True,
            scorecard_network_access_performed=True,
            network_access_performed=True,
        ),
    )

    assert evidence_confidence_for_report(report) is EvidenceConfidence.ENRICHMENT_RECORDED


def test_evidence_confidence_allows_explicit_recorded_override_for_constructed_snapshots() -> None:
    report = _minimal_report(
        before_format="requirements-txt",
        after_format="requirements-txt",
        evidence_confidence=EvidenceConfidence.PROVENANCE_RECORDED,
        enrichment=ReportEnrichmentMetadata(
            mode="opt_in_pypi",
            pypi_enabled=True,
            pypi_network_access_performed=True,
            network_access_performed=True,
        ),
    )

    assert evidence_confidence_for_report(report) is EvidenceConfidence.PROVENANCE_RECORDED


def _minimal_report(
    *,
    before_format: str,
    after_format: str,
    policy_evaluation: PolicyEvaluation | None = None,
    evidence_confidence: EvidenceConfidence | None = None,
    enrichment: ReportEnrichmentMetadata | None = None,
) -> CompareReport:
    return CompareReport(
        summary=ReportSummary(added=0, removed=0, changed=0, risk_counts={}),
        components=ReportComponents(
            added=[Component(name="requests", version="2.32.0", ecosystem="pypi")],
            removed=[],
            changed=[],
        ),
        risks=[],
        metadata=ReportMetadata(
            before_format=before_format,
            after_format=after_format,
            policy_evaluation=policy_evaluation,
            evidence_confidence=evidence_confidence,
            enrichment=enrichment or ReportEnrichmentMetadata(),
        ),
    )
