from __future__ import annotations

import json

from .enrichment import enrichment_metadata_to_dict, provenance_evidence_to_dict
from .models import CompareReport, Component, ComponentChange, ReportEnrichmentMetadata, RiskFinding
from .presentation import build_policy_report_sections, build_trust_signal_report_sections
from .policy_models import PolicyEvaluation
from .scorecard_enrichment import scorecard_evidence_to_dict


def render_report_json(report: CompareReport) -> str:
    policy_sections = build_policy_report_sections(report.metadata.policy_evaluation)
    trust_signal_sections = build_trust_signal_report_sections(report)
    payload = {
        "summary": _summary_to_dict(report),
        "components": {
            "added": [_component_to_dict(component) for component in report.components.added],
            "removed": [_component_to_dict(component) for component in report.components.removed],
            "changed": [_change_to_dict(change) for change in report.components.changed],
        },
        "risks": [_risk_to_dict(finding) for finding in report.risks],
        "policy_evaluation": policy_sections["policy_evaluation"],
        "blocking_findings": policy_sections["blocking_findings"],
        "warning_findings": policy_sections["warning_findings"],
        "suppressed_findings": policy_sections["suppressed_findings"],
        "rule_catalog": policy_sections["rule_catalog"],
        "provenance_summary": trust_signal_sections["provenance_summary"],
        "attestation_summary": trust_signal_sections["attestation_summary"],
        "scorecard_summary": trust_signal_sections["scorecard_summary"],
        "enrichment_metadata": trust_signal_sections["enrichment_metadata"],
        "trust_signal_notes": trust_signal_sections["trust_signal_notes"],
        "metadata": {
            "before_format": report.metadata.before_format,
            "after_format": report.metadata.after_format,
            "generated_at": report.metadata.generated_at,
            "strict": report.metadata.strict,
            "stub": report.metadata.stub,
            "policy_evaluation": policy_sections["policy_evaluation"],
            "enrichment": enrichment_metadata_to_dict(report.metadata.enrichment),
        },
        "notes": list(report.notes),
    }
    if policy_sections["provenance_policy"] is not None:
        payload["provenance_policy"] = policy_sections["provenance_policy"]
        payload["provenance_policy_impact"] = policy_sections["provenance_policy_impact"]
    return json.dumps(payload, indent=2) + "\n"


def _summary_to_dict(report: CompareReport) -> dict[str, object]:
    summary: dict[str, object] = {
        "added": report.summary.added,
        "removed": report.summary.removed,
        "changed": report.summary.changed,
        "risk_counts": dict(report.summary.risk_counts),
    }

    policy_summary = _policy_summary_to_dict(report.metadata.policy_evaluation)
    if policy_summary is not None:
        summary["policy"] = policy_summary

    enrichment_summary = _enrichment_summary_to_dict(report.metadata.enrichment)
    if enrichment_summary is not None:
        summary["enrichment"] = enrichment_summary

    return summary


def _policy_summary_to_dict(evaluation: PolicyEvaluation | None) -> dict[str, object] | None:
    if evaluation is None or not evaluation.applied:
        return None

    blocking = len(evaluation.blocking_violations)
    warning = len(evaluation.warning_violations)
    suppressed = len(evaluation.suppressed_violations)
    status = "fail" if blocking else "warn" if warning else "pass"

    return {
        "status": status,
        "blocking": blocking,
        "warning": warning,
        "suppressed": suppressed,
    }


def _enrichment_summary_to_dict(metadata: ReportEnrichmentMetadata) -> dict[str, object] | None:
    if not (metadata.pypi_enabled or metadata.scorecard_enabled):
        return None

    summary: dict[str, object] = {
        "status": "used",
        "mode": metadata.mode,
    }
    if metadata.pypi_enabled:
        summary["pypi"] = {
            "candidate_components": metadata.candidate_components,
            "supported_components": metadata.supported_components,
            "status_counts": _sorted_counts(metadata.status_counts),
        }
    if metadata.scorecard_enabled:
        summary["scorecard"] = {
            "candidate_components": metadata.scorecard_candidate_components,
            "supported_components": metadata.scorecard_supported_components,
            "status_counts": _sorted_counts(metadata.scorecard_status_counts),
        }
    return summary


def _sorted_counts(counts: dict[str, int]) -> dict[str, int]:
    return {key: counts[key] for key in sorted(counts)}


def _component_to_dict(component: Component) -> dict[str, object]:
    evidence = dict(component.evidence)
    provenance = provenance_evidence_to_dict(component.provenance)
    if provenance is not None:
        evidence["provenance"] = provenance
    scorecard = scorecard_evidence_to_dict(component.scorecard)
    if scorecard is not None:
        evidence["scorecard"] = scorecard
    return {
        "name": component.name,
        "version": component.version,
        "ecosystem": component.ecosystem,
        "purl": component.purl,
        "license_id": component.license_id,
        "supplier": component.supplier,
        "source_url": component.source_url,
        "bom_ref": component.bom_ref,
        "raw_type": component.raw_type,
        "evidence": evidence,
    }


def _change_to_dict(change: ComponentChange) -> dict[str, object]:
    return {
        "key": change.key,
        "classification": change.classification,
        "before": _component_to_dict(change.before),
        "after": _component_to_dict(change.after),
    }


def _risk_to_dict(finding: RiskFinding) -> dict[str, object]:
    return {
        "bucket": finding.bucket.value,
        "component_key": finding.component_key,
        "component": _component_to_dict(finding.component),
        "rationale": finding.rationale,
    }
