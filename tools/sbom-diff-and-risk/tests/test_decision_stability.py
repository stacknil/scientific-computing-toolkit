"""Production adapters for the separately authored, bounded decision oracle."""

import json
import random
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from sbom_diff_risk.component_identity import canonicalize_component_identity
from sbom_diff_risk.errors import PolicyError
from sbom_diff_risk.models import (
    CompareReport,
    Component,
    ComponentChange,
    ProvenanceEvidence,
    ProvenanceFileEvidence,
    ProvenanceStatus,
    ReportComponents,
    ReportMetadata,
    ReportSummary,
    RepositoryMapping,
    RiskBucket,
    RiskFinding,
    ScorecardEvidence,
    ScorecardStatus,
)
from sbom_diff_risk.policy_evaluator import _assess_provenance, evaluate_policy
from sbom_diff_risk.policy_models import PolicyConfig
from sbom_diff_risk.policy_parser import build_policy
from sbom_diff_risk.report_json import (
    render_policy_json,
    render_report_json,
    render_summary_json,
)
from sbom_diff_risk.report_md import render_report_markdown
from sbom_diff_risk.report_sarif import render_report_sarif
from sbom_diff_risk.risk import summarize_risks

from test_decision_stability_oracle import CASES, KEY, NAME, require, validate_case


def synthetic_component(case):
    component = Component(
        NAME,
        "1.0.0",
        "pypi",
        purl=f"pkg:pypi/{NAME}@1.0.0",
        license_id="MIT",
        source_url=case.source_url,
        evidence={"source_format": "cyclonedx-json"},
    )
    if case.provenance != "none":
        states = {
            "error": (ProvenanceStatus.ENRICHMENT_ERROR,),
            "unsupported": (ProvenanceStatus.UNSUPPORTED_FOR_PACKAGE,),
            "missing": (
                ProvenanceStatus.PROVENANCE_AVAILABLE,
                ProvenanceStatus.ATTESTATION_UNAVAILABLE,
            ),
            "attested": (
                ProvenanceStatus.PROVENANCE_AVAILABLE,
                ProvenanceStatus.ATTESTATION_AVAILABLE,
            ),
            "error-and-attested": (
                ProvenanceStatus.ENRICHMENT_ERROR,
                ProvenanceStatus.ATTESTATION_AVAILABLE,
            ),
        }
        statuses = states[case.provenance]
        has_attestation = ProvenanceStatus.ATTESTATION_AVAILABLE in statuses
        component.provenance = ProvenanceEvidence(
            provider="synthetic-pypi",
            requested=True,
            supported=case.provenance != "unsupported",
            lookup_performed=case.provenance != "unsupported",
            package_name=NAME,
            package_version="1.0.0",
            statuses=statuses,
            files=(
                ProvenanceFileEvidence(
                    filename="qualification-alpha-1.0.0.whl",
                    statuses=statuses,
                    attestation_count=int(has_attestation),
                    publisher_kinds=case.publishers,
                ),
            ),
            error="Synthetic offline transport error"
            if "error" in case.provenance
            else None,
        )
    if case.score is not None:
        component.scorecard = ScorecardEvidence(
            provider="synthetic-scorecard",
            requested=True,
            repository=RepositoryMapping(
                "github.com",
                "example",
                "qualification",
                "github.com/example/qualification",
                "https://github.com/example/qualification",
                "synthetic-explicit-vcs",
            )
            if case.score_available
            else None,
            statuses=(ScorecardStatus.SCORECARD_AVAILABLE,)
            if case.score_available
            else (ScorecardStatus.REPOSITORY_UNMAPPED,),
            score=case.score,
        )
    return component


def observe_case(case, directory, seed=103):
    directory.mkdir(parents=True, exist_ok=True)
    policy_path = None
    if case.policy is not None:
        entries = list(case.policy.items())
        random.Random(seed).shuffle(entries)
        policy_path = directory / "policy.yml"
        policy_path.write_text(
            yaml.safe_dump(dict(entries), sort_keys=False), encoding="utf-8"
        )
    try:
        policy, _ = build_policy(
            policy_path=policy_path, fail_on=case.fail_on, warn_on=case.warn_on
        )
    except PolicyError as exc:
        return {
            "decision": "INVALID_INPUT",
            "exit_code": 2,
            "error_type": type(exc).__name__,
        }, None
    component = synthetic_component(case)
    added = [component] if case.scope == "added" else []
    changed = (
        [
            ComponentChange(
                KEY,
                replace(component, license_id="BSD-3-Clause"),
                component,
                "metadata_changed",
            )
        ]
        if case.scope == "changed"
        else []
    )
    findings = [
        RiskFinding(
            RiskBucket(bucket), KEY, component, "Synthetic local heuristic observation."
        )
        for bucket in case.findings
    ]
    random.Random(seed).shuffle(findings)
    evaluation = evaluate_policy(
        policy,
        policy_path="policy.yml" if policy_path else None,
        added=added,
        changed=changed,
        findings=findings,
    )
    rows = []
    for group, violations in (
        ("blocking", evaluation.blocking_violations),
        ("warning", evaluation.warning_violations),
        ("suppressed", evaluation.suppressed_violations),
    ):
        keys = [
            (item.rule_id, item.component_key or "", item.component_name or "")
            for item in violations
        ]
        require("deterministic-order", keys, sorted(keys))
        for item in violations:
            rows.append(
                {
                    "group": group,
                    "rule": item.rule_id,
                    "policy_rule": item.policy_rule,
                    "level": item.level.value if item.level else None,
                    "reason": item.decision_reason,
                    "source": item.severity_source,
                    "observed": item.observed_value,
                    "threshold": item.matched_threshold,
                    "key": item.component_key,
                    "name": item.component_name,
                    "bucket": item.finding_bucket,
                    "confidence": item.confidence_level,
                    "suppression": item.suppression_reason,
                }
            )
    assessment = _assess_provenance(component, policy or PolicyConfig(version=1))
    decision = (
        "NOT_APPLIED"
        if not evaluation.applied
        else "FAIL"
        if evaluation.blocking_violations
        else "WARN"
        if evaluation.warning_violations
        else "PASS"
    )
    observation = {
        "decision": decision,
        "exit_code": evaluation.exit_code,
        "rows": rows,
        "identity": canonicalize_component_identity(component).component_key,
        "assessment": (
            assessment.attestation_available,
            assessment.provenance_unavailable,
            assessment.verified,
            assessment.publisher_kinds,
        ),
        "ignored_checks": evaluation.ignored_checks,
        "effective_version": policy.version if policy else None,
    }
    report = CompareReport(
        ReportSummary(len(added), 0, len(changed), summarize_risks(findings)),
        ReportComponents(added, [], changed),
        findings,
        ReportMetadata(
            "cyclonedx-json", "cyclonedx-json", stub=False, policy_evaluation=evaluation
        ),
        [
            "This tool uses heuristic risk classification.",
            "Synthetic recorded evidence; no cryptographic verification or package safety verdict.",
        ],
    )
    return observation, report


def render_bundle(report):
    return {
        "report": json.loads(render_report_json(report)),
        "summary": json.loads(render_summary_json(report)),
        "policy": json.loads(render_policy_json(report)),
        "markdown": render_report_markdown(report),
        "sarif": json.loads(
            render_report_sarif(
                report, before_path=Path("before.json"), after_path=Path("after.json")
            )
        ),
    }


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_hand_authored_policy_microcase(case, tmp_path):
    actual, report = observe_case(case, tmp_path)
    validate_case(case, actual)
    if report is not None:
        require("renderer-determinism", render_bundle(report), render_bundle(report))


def test_expected_oracle_does_not_import_product_code():
    import ast
    import test_decision_stability_oracle as oracle

    tree = ast.parse(Path(oracle.__file__).read_text(encoding="utf-8"))
    imports = [
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    ]
    imports.extend(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    assert all(
        not name.startswith(("sbom_diff_risk", "test_decision_stability."))
        for name in imports
    )
