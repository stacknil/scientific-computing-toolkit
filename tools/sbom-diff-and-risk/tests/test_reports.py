from __future__ import annotations

import json
from pathlib import Path

from sbom_diff_risk.diffing import diff_components
from sbom_diff_risk.models import (
    CompareReport,
    Component,
    ProvenanceEvidence,
    ProvenanceFileEvidence,
    ProvenanceStatus,
    ReportComponents,
    ReportMetadata,
    ReportSummary,
)
from sbom_diff_risk.policy_evaluator import evaluate_policy
from sbom_diff_risk.policy_models import PolicyConfig
from sbom_diff_risk.policy_parser import build_policy
from sbom_diff_risk.normalize import normalize_input
from sbom_diff_risk.report_json import render_report_json, render_summary_json
from sbom_diff_risk.report_md import render_report_markdown
from sbom_diff_risk.risk import evaluate_risks, summarize_risks


def test_report_json_matches_cyclonedx_golden_pass() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json")

    rendered = render_report_json(report)
    expected = _read_example("sample-report.json")

    assert rendered == expected


def test_summary_json_matches_cyclonedx_golden_pass() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json")

    rendered = render_summary_json(report)
    expected = _read_example("sample-summary.json")

    assert rendered == expected
    assert json.loads(rendered) == json.loads(_read_example("sample-report.json"))["summary"]


def test_report_markdown_matches_cyclonedx_golden_pass() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json")

    rendered = render_report_markdown(report)
    expected = _read_example("sample-report.md")

    assert rendered == expected


def test_report_json_matches_cyclonedx_policy_warn_golden() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json", policy_name="policy-minimal.yml")

    rendered = render_report_json(report)
    expected = _read_example("sample-policy-warn-report.json")

    assert rendered == expected


def test_report_markdown_matches_cyclonedx_policy_warn_golden() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json", policy_name="policy-minimal.yml")

    rendered = render_report_markdown(report)
    expected = _read_example("sample-policy-warn-report.md")

    assert rendered == expected


def test_report_json_matches_cyclonedx_policy_fail_golden() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json", policy_name="policy-strict.yml")

    rendered = render_report_json(report)
    expected = _read_example("sample-policy-fail-report.json")

    assert rendered == expected


def test_report_markdown_matches_cyclonedx_policy_fail_golden() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json", policy_name="policy-strict.yml")

    rendered = render_report_markdown(report)
    expected = _read_example("sample-policy-fail-report.md")

    assert rendered == expected


def test_report_json_matches_requirements_golden() -> None:
    report = _build_report("requirements_before.txt", "requirements_after.txt")

    rendered = render_report_json(report)
    expected = _read_example("sample-requirements-report.json")

    assert rendered == expected


def test_report_markdown_matches_requirements_golden() -> None:
    report = _build_report("requirements_before.txt", "requirements_after.txt")

    rendered = render_report_markdown(report)
    expected = _read_example("sample-requirements-report.md")

    assert rendered == expected


def test_report_json_keeps_legacy_sections() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json")

    payload = json.loads(render_report_json(report))

    assert set(payload) >= {
        "summary",
        "components",
        "risks",
        "policy_evaluation",
        "blocking_findings",
        "warning_findings",
        "suppressed_findings",
        "rule_catalog",
        "provenance_summary",
        "attestation_summary",
        "scorecard_summary",
        "enrichment_metadata",
        "trust_signal_notes",
        "metadata",
        "notes",
    }
    assert payload["metadata"]["policy_evaluation"] == payload["policy_evaluation"]
    assert payload["metadata"]["enrichment"] == payload["enrichment_metadata"]
    assert "provenance_policy" not in payload
    assert "provenance_policy_impact" not in payload


def test_report_json_offline_enrichment_metadata_is_stable_by_default() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json")

    first = render_report_json(report)
    second = render_report_json(report)
    payload = json.loads(first)

    assert first == second
    assert payload["summary"] == {
        "added": 1,
        "removed": 0,
        "changed": 1,
        "risk_counts": {
            "new_package": 1,
            "major_upgrade": 0,
            "version_change_unclassified": 1,
            "unknown_license": 0,
            "stale_package": 0,
            "suspicious_source": 0,
            "not_evaluated": 2,
        },
    }
    assert payload["metadata"]["enrichment"] == {
        "mode": "offline_default",
        "pypi_enabled": False,
        "pypi_timeout_seconds": None,
        "pypi_network_access_performed": False,
        "network_access_performed": False,
        "candidate_components": 0,
        "supported_components": 0,
        "status_counts": {},
        "scorecard_enabled": False,
        "scorecard_timeout_seconds": None,
        "scorecard_network_access_performed": False,
        "scorecard_candidate_components": 0,
        "scorecard_supported_components": 0,
        "scorecard_status_counts": {},
    }
    assert payload["provenance_summary"]["pypi_components_without_provenance"] == 2
    assert payload["provenance_summary"]["components_with_provenance"] == 0
    assert payload["attestation_summary"]["files_evaluated"] == 0
    assert payload["scorecard_summary"]["enabled"] is False
    assert payload["scorecard_summary"]["components_with_scorecards"] == 0
    assert payload["scorecard_summary"]["repository_unmapped"] == 0
    assert payload["trust_signal_notes"] == ["PyPI components are present, but provenance enrichment was not enabled for this run."]
    added_components = payload["components"]["added"]
    assert all("provenance" not in component["evidence"] for component in added_components)
    assert all("scorecard" not in component["evidence"] for component in added_components)


def test_report_json_summary_includes_policy_status_when_policy_is_used() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json", policy_name="policy-minimal.yml")

    payload = json.loads(render_report_json(report))

    assert payload["summary"]["policy"] == {
        "status": "warn",
        "blocking": 0,
        "warning": 1,
        "suppressed": 0,
    }
    assert "enrichment" not in payload["summary"]


def test_reports_render_suppressions_when_policy_ignores_findings() -> None:
    policy = PolicyConfig(
        version=1,
        warn_on=("new_package",),
        ignore_rules=("new_package",),
    )
    report = _build_report("cdx_before.json", "cdx_after.json", policy=policy)

    payload = json.loads(render_report_json(report))
    markdown = render_report_markdown(report)

    assert payload["suppressed_findings"]
    assert payload["suppressed_findings"][0]["suppression_reason"] == "ignored_by_policy"
    assert "## Suppressions" in markdown


def test_reports_include_provenance_policy_details_for_v2_policy() -> None:
    component = Component(
        name="urllib3",
        version="2.2.1",
        ecosystem="pypi",
        provenance=ProvenanceEvidence(
            provider="pypi",
            requested=True,
            package_name="urllib3",
            package_version="2.2.1",
            release_url="https://pypi.org/project/urllib3/2.2.1/",
            statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
            files=(
                ProvenanceFileEvidence(
                    filename="urllib3-2.2.1.tar.gz",
                    statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
                    attestation_count=0,
                ),
            ),
        ),
    )
    policy = PolicyConfig(
        version=2,
        warn_on=("missing_attestation",),
        require_attestations_for_new_packages=True,
        allow_unattested_packages=("pip",),
    )
    policy_evaluation = evaluate_policy(policy, policy_path="policy-provenance-minimal.yml", added=[component], changed=[], findings=[])
    report = CompareReport(
        summary=ReportSummary(added=1, removed=0, changed=0, risk_counts={}),
        components=ReportComponents(added=[component], removed=[], changed=[]),
        risks=[],
        metadata=ReportMetadata(
            before_format="requirements-txt",
            after_format="requirements-txt",
            generated_at=None,
            strict=False,
            stub=False,
            policy_evaluation=policy_evaluation,
        ),
        notes=["PyPI provenance enrichment was requested explicitly."],
    )

    payload = json.loads(render_report_json(report))
    markdown = render_report_markdown(report)

    assert payload["policy_evaluation"]["effective_policy"]["require_attestations_for_new_packages"] is True
    assert payload["policy_evaluation"]["effective_policy"]["allow_unattested_packages"] == ["pip"]
    assert payload["provenance_policy"]["configured"] is True
    assert payload["provenance_policy"]["requirements"]["allow_unattested_packages"] == ["pip"]
    assert payload["provenance_policy"]["counts"]["blocking"] == 1
    assert any(item["rule_id"] == "provenance_required" for item in payload["blocking_findings"])
    assert "- Configured provenance policy: yes" in markdown
    assert "- Allow unattested packages: pip" in markdown
    assert "provenance_required" in markdown
    assert "missing_attestation" in markdown


def _build_report(
    before_name: str,
    after_name: str,
    *,
    policy_name: str | None = None,
    policy: PolicyConfig | None = None,
    fail_on: str | None = None,
    warn_on: str | None = None,
) -> CompareReport:
    examples = Path(__file__).resolve().parents[1] / "examples"
    before_path = examples / before_name
    after_path = examples / after_name

    before_format, before_components, before_notes = normalize_input(before_path)
    after_format, after_components, after_notes = normalize_input(after_path)

    added, removed, changed = diff_components(before_components, after_components)
    risks = evaluate_risks(added, changed, allowlist=["pypi.org", "files.pythonhosted.org", "github.com"])

    if policy is None:
        built_policy, policy_path = build_policy(
            policy_path=examples / policy_name if policy_name else None,
            fail_on=fail_on,
            warn_on=warn_on,
        )
    else:
        built_policy = policy
        policy_path = None

    policy_evaluation = evaluate_policy(
        built_policy,
        policy_path=policy_path,
        added=added,
        changed=changed,
        findings=risks,
    )

    notes = [
        "This tool uses heuristic risk classification.",
        "No network enrichment was performed.",
        *before_notes,
        *after_notes,
    ]

    return CompareReport(
        summary=ReportSummary(
            added=len(added),
            removed=len(removed),
            changed=len(changed),
            risk_counts=summarize_risks(risks),
        ),
        components=ReportComponents(
            added=added,
            removed=removed,
            changed=changed,
        ),
        risks=risks,
        metadata=ReportMetadata(
            before_format=before_format,
            after_format=after_format,
            generated_at=None,
            strict=False,
            stub=False,
            policy_evaluation=policy_evaluation,
        ),
        notes=notes,
    )


def _read_example(name: str) -> str:
    examples = Path(__file__).resolve().parents[1] / "examples"
    return (examples / name).read_text(encoding="utf-8")
