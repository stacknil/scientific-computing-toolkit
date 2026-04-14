from __future__ import annotations

import json
from pathlib import Path

from sbom_diff_risk.diffing import diff_components
from sbom_diff_risk.models import CompareReport, ReportComponents, ReportMetadata, ReportSummary
from sbom_diff_risk.policy_evaluator import evaluate_policy
from sbom_diff_risk.policy_models import PolicyConfig
from sbom_diff_risk.policy_parser import build_policy
from sbom_diff_risk.normalize import normalize_input
from sbom_diff_risk.report_json import render_report_json
from sbom_diff_risk.report_md import render_report_markdown
from sbom_diff_risk.risk import evaluate_risks, summarize_risks


def test_report_json_matches_cyclonedx_golden_pass() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json")

    rendered = render_report_json(report)
    expected = _read_example("sample-report.json")

    assert rendered == expected


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
        "metadata",
        "notes",
    }
    assert payload["metadata"]["policy_evaluation"] == payload["policy_evaluation"]


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
            policy_path=(Path("examples") / policy_name) if policy_name else None,
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
