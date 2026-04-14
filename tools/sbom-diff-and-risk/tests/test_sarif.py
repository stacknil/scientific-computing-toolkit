from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from sbom_diff_risk.cli import run_compare
from sbom_diff_risk.diffing import diff_components
from sbom_diff_risk.models import CompareReport, ReportComponents, ReportMetadata, ReportSummary, RiskBucket
from sbom_diff_risk.normalize import normalize_input
from sbom_diff_risk.policy_evaluator import evaluate_policy
from sbom_diff_risk.policy_parser import build_policy
from sbom_diff_risk.report_sarif import (
    render_report_sarif_output,
    render_report_sarif,
    sarif_rule_id_for_policy_violation,
    sarif_rule_id_for_risk_bucket,
)
from sbom_diff_risk.risk import evaluate_risks, summarize_risks


def test_render_report_sarif_matches_golden() -> None:
    project_root = Path(__file__).resolve().parents[1]
    report, before_path, after_path = _build_report(
        "sarif_before.json",
        "sarif_after.json",
        policy_name="policy-strict.yml",
    )

    rendered = render_report_sarif(report, before_path=before_path, after_path=after_path, base_dir=project_root)
    expected = (project_root / "examples" / "sample-sarif.sarif").read_text(encoding="utf-8")

    assert _normalize_sarif_golden(rendered) == _normalize_sarif_golden(expected)


def test_sarif_rule_ids_are_stable() -> None:
    assert sarif_rule_id_for_risk_bucket(RiskBucket.UNKNOWN_LICENSE) == "sdr.unknown_license"
    assert sarif_rule_id_for_risk_bucket(RiskBucket.SUSPICIOUS_SOURCE) == "sdr.suspicious_source"
    assert sarif_rule_id_for_risk_bucket(RiskBucket.MAJOR_UPGRADE) == "sdr.major_upgrade"
    assert sarif_rule_id_for_policy_violation("max_added_packages") == "sdr.policy_violation.max_added_packages"
    assert sarif_rule_id_for_policy_violation("allow_sources") == "sdr.policy_violation.allow_sources"
    assert sarif_rule_id_for_policy_violation("stale_package") is None


def test_sarif_structure_and_mapping_are_github_compatible() -> None:
    project_root = Path(__file__).resolve().parents[1]
    report, before_path, after_path = _build_report(
        "sarif_before.json",
        "sarif_after.json",
        policy_name="policy-strict.yml",
    )

    payload = json.loads(render_report_sarif(report, before_path=before_path, after_path=after_path, base_dir=project_root))

    assert payload["version"] == "2.1.0"
    assert payload["$schema"].endswith("sarif-2.1.0.json")
    assert len(payload["runs"]) == 1

    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "sbom-diff-risk"
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].startswith("file:///")

    rules = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert rules == {
        "sdr.major_upgrade",
        "sdr.policy_violation.allow_sources",
        "sdr.policy_violation.max_added_packages",
        "sdr.suspicious_source",
        "sdr.unknown_license",
    }

    results = run["results"]
    assert [result["ruleId"] for result in results] == [
        "sdr.suspicious_source",
        "sdr.unknown_license",
        "sdr.policy_violation.allow_sources",
        "sdr.policy_violation.max_added_packages",
        "sdr.major_upgrade",
    ]
    assert any(result["level"] == "error" for result in results)
    assert all(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "examples/sarif_after.json" for result in results)
    assert results[0]["message"]["text"].startswith("Blocked by policy:")
    assert results[2]["message"]["text"].startswith("mystery-lib")


def test_sarif_truncation_is_deterministic_and_recorded_in_metadata() -> None:
    project_root = Path(__file__).resolve().parents[1]
    report, before_path, after_path = _build_report(
        "sarif_before.json",
        "sarif_after.json",
        policy_name="policy-strict.yml",
    )

    first = render_report_sarif_output(
        report,
        before_path=before_path,
        after_path=after_path,
        base_dir=project_root,
        result_limit=2,
    )
    second = render_report_sarif_output(
        report,
        before_path=before_path,
        after_path=after_path,
        base_dir=project_root,
        result_limit=2,
    )

    assert first.content == second.content
    assert first.metadata.truncated is True
    assert first.metadata.total_candidate_results == 5
    assert first.metadata.emitted_results == 2
    assert first.metadata.omitted_results == 3
    assert first.metadata.warning_message is not None

    payload = json.loads(first.content)
    run = payload["runs"][0]
    assert run["properties"]["sbom_diff_risk"]["truncated"] is True
    assert run["properties"]["sbom_diff_risk"]["emitted_results"] == 2
    assert [result["ruleId"] for result in run["results"]] == [
        "sdr.suspicious_source",
        "sdr.unknown_license",
    ]


def test_run_compare_emits_stderr_warning_when_sarif_is_truncated(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    before = project_root / "examples" / "sarif_before.json"
    after = project_root / "examples" / "sarif_after.json"

    monkeypatch.setattr("sbom_diff_risk.report_sarif.DEFAULT_SARIF_RESULT_LIMIT", 2)

    exit_code = run_compare(
        argparse.Namespace(
            before=before,
            after=after,
            format="auto",
            before_format=None,
            after_format=None,
            out_json=None,
            out_md=None,
            out_sarif=tmp_path / "report.sarif",
            policy=project_root / "examples" / "policy-strict.yml",
            fail_on=None,
            warn_on=None,
            strict=False,
            enrich_pypi=False,
            source_allowlist="pypi.org,files.pythonhosted.org,github.com",
        )
    )

    stderr = capsys.readouterr().err
    assert exit_code == 1
    assert "SARIF results were truncated deterministically" in stderr
    assert "limit 2" in stderr
    assert (tmp_path / "report.sarif").is_file()


def _build_report(before_name: str, after_name: str, *, policy_name: str | None = None) -> tuple[CompareReport, Path, Path]:
    project_root = Path(__file__).resolve().parents[1]
    examples = project_root / "examples"
    before_path = examples / before_name
    after_path = examples / after_name

    before_format, before_components, before_notes = normalize_input(before_path)
    after_format, after_components, after_notes = normalize_input(after_path)

    added, removed, changed = diff_components(before_components, after_components)
    risks = evaluate_risks(added, changed, allowlist=["pypi.org", "files.pythonhosted.org", "github.com"])
    policy, policy_path = build_policy(policy_path=(Path("examples") / policy_name) if policy_name else None)
    policy_evaluation = evaluate_policy(
        policy,
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

    report = CompareReport(
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
    return report, before_path, after_path


def _normalize_sarif_golden(value: str) -> str:
    return re.sub(
        r"file:///[^\"\r\n]+/tools/sbom-diff-and-risk(?:-real)?/",
        "file:///__PROJECT_ROOT__/",
        value,
    )
