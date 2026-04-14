from __future__ import annotations

import json

from .models import CompareReport, Component, ComponentChange, RiskFinding
from .policy_models import PolicyConfig, PolicyEvaluation, PolicyViolation


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
            "policy_evaluation": _policy_evaluation_to_dict(report.metadata.policy_evaluation),
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


def _policy_evaluation_to_dict(policy_evaluation: PolicyEvaluation | None) -> dict[str, object]:
    if policy_evaluation is None:
        return {
            "applied": False,
            "policy_path": None,
            "effective_policy": None,
            "blocking_violations": [],
            "warning_violations": [],
            "totals": {
                "blocking": 0,
                "warning": 0,
                "ignored_checks": 0,
            },
            "exit_code": 0,
        }

    return {
        "applied": policy_evaluation.applied,
        "policy_path": policy_evaluation.policy_path,
        "effective_policy": _policy_config_to_dict(policy_evaluation.effective_policy),
        "blocking_violations": [_policy_violation_to_dict(item) for item in policy_evaluation.blocking_violations],
        "warning_violations": [_policy_violation_to_dict(item) for item in policy_evaluation.warning_violations],
        "totals": {
            "blocking": len(policy_evaluation.blocking_violations),
            "warning": len(policy_evaluation.warning_violations),
            "ignored_checks": policy_evaluation.ignored_checks,
        },
        "exit_code": policy_evaluation.exit_code,
    }


def _policy_config_to_dict(policy: PolicyConfig | None) -> dict[str, object] | None:
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


def _policy_violation_to_dict(violation: PolicyViolation) -> dict[str, object]:
    return {
        "rule_id": violation.rule_id,
        "level": violation.level.value,
        "message": violation.message,
        "component_key": violation.component_key,
        "component_name": violation.component_name,
        "finding_bucket": violation.finding_bucket,
    }
