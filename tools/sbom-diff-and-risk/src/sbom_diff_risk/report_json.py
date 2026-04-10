from __future__ import annotations

import json

from .models import CompareReport, Component, ComponentChange, RiskFinding


def render_report_json(report: CompareReport) -> str:
    payload = {
        "summary": {
            "added": report.summary.added,
            "removed": report.summary.removed,
            "changed": report.summary.changed,
            "risk_counts": dict(report.summary.risk_counts),
        },
        "components": {
            "added": [_component_to_dict(component) for component in report.components.added],
            "removed": [_component_to_dict(component) for component in report.components.removed],
            "changed": [_change_to_dict(change) for change in report.components.changed],
        },
        "risks": [_risk_to_dict(finding) for finding in report.risks],
        "metadata": {
            "before_format": report.metadata.before_format,
            "after_format": report.metadata.after_format,
            "generated_at": report.metadata.generated_at,
            "strict": report.metadata.strict,
            "stub": report.metadata.stub,
        },
        "notes": list(report.notes),
    }
    return json.dumps(payload, indent=2) + "\n"


def _component_to_dict(component: Component) -> dict[str, object]:
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
        "evidence": component.evidence,
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
