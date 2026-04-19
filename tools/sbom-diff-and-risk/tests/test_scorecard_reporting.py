from __future__ import annotations

import json
from pathlib import Path

from sbom_diff_risk.diffing import component_key
from sbom_diff_risk.models import (
    CompareReport,
    Component,
    ComponentChange,
    ReportComponents,
    ReportEnrichmentMetadata,
    ReportMetadata,
    ReportSummary,
    RepositoryMapping,
    ScorecardCheck,
    ScorecardEvidence,
    ScorecardStatus,
    RiskBucket,
    RiskFinding,
)
from sbom_diff_risk.policy_evaluator import evaluate_policy
from sbom_diff_risk.policy_models import PolicyConfig
from sbom_diff_risk.report_json import render_report_json
from sbom_diff_risk.report_md import render_report_markdown
from sbom_diff_risk.report_sarif import render_report_sarif, sarif_rule_id_for_policy_violation
from sbom_diff_risk.risk import summarize_risks


def test_scorecard_report_json_matches_golden() -> None:
    report, _, _ = _build_sample_scorecard_report()

    rendered = render_report_json(report)
    expected = _read_example("sample-scorecard-report.json")

    assert rendered == expected


def test_scorecard_report_markdown_matches_golden() -> None:
    report, _, _ = _build_sample_scorecard_report()

    rendered = render_report_markdown(report)
    expected = _read_example("sample-scorecard-report.md")

    assert rendered == expected


def test_scorecard_sarif_matches_golden() -> None:
    report, before_path, after_path = _build_sample_scorecard_report()
    project_root = Path(__file__).resolve().parents[1]

    rendered = render_report_sarif(report, before_path=before_path, after_path=after_path, base_dir=project_root)
    expected = _read_example("sample-scorecard-report.sarif")

    assert _normalize_sarif_snapshot(rendered) == _normalize_sarif_snapshot(expected)


def test_scorecard_sarif_rule_id_is_stable() -> None:
    assert sarif_rule_id_for_policy_violation("scorecard_below_threshold") == "sdr.policy_violation.scorecard_below_threshold"


def test_scorecard_only_evidence_does_not_become_sarif_alert_without_policy_gate() -> None:
    component = Component(
        name="requests",
        version="2.32.0",
        ecosystem="pypi",
        scorecard=_scorecard(
            canonical_name="github.com/psf/requests",
            score=4.5,
            status=ScorecardStatus.SCORECARD_AVAILABLE,
        ),
    )
    report = CompareReport(
        summary=ReportSummary(added=1, removed=0, changed=0, risk_counts=summarize_risks([])),
        components=ReportComponents(added=[component], removed=[], changed=[]),
        risks=[],
        metadata=ReportMetadata(
            before_format="requirements-txt",
            after_format="requirements-txt",
            generated_at=None,
            strict=False,
            stub=False,
            policy_evaluation=evaluate_policy(
                PolicyConfig(version=3, minimum_scorecard_score=7.0),
                policy_path="policy.yml",
                added=[component],
                changed=[],
                findings=[],
            ),
            enrichment=ReportEnrichmentMetadata(
                mode="opt_in_scorecard",
                scorecard_enabled=True,
                scorecard_timeout_seconds=3.0,
                scorecard_network_access_performed=True,
                network_access_performed=True,
                scorecard_candidate_components=1,
                scorecard_supported_components=1,
                scorecard_status_counts={"scorecard_available": 1},
            ),
        ),
        notes=["OpenSSF Scorecard enrichment was requested explicitly."],
    )
    project_root = Path(__file__).resolve().parents[1]
    examples = project_root / "examples"

    payload = json.loads(
        render_report_sarif(report, before_path=examples / "requirements_before.txt", after_path=examples / "requirements_after.txt", base_dir=project_root)
    )

    assert payload["runs"][0]["results"] == []


def _build_sample_scorecard_report() -> tuple[CompareReport, Path, Path]:
    project_root = Path(__file__).resolve().parents[1]
    examples = project_root / "examples"
    before_path = examples / "requirements_before.txt"
    after_path = examples / "requirements_after.txt"

    requests = Component(
        name="requests",
        version="2.32.0",
        ecosystem="pypi",
        purl="pkg:pypi/requests@2.32.0",
        source_url="https://github.com/psf/requests",
        scorecard=_scorecard(
            canonical_name="github.com/psf/requests",
            score=6.0,
            status=ScorecardStatus.SCORECARD_AVAILABLE,
        ),
    )
    urllib3 = Component(
        name="urllib3",
        version="2.2.1",
        ecosystem="pypi",
        purl="pkg:pypi/urllib3@2.2.1",
        source_url="https://pypi.org/project/urllib3/2.2.1/",
        scorecard=_scorecard(
            canonical_name=None,
            score=None,
            status=ScorecardStatus.REPOSITORY_UNMAPPED,
        ),
    )
    certifi_before = Component(
        name="certifi",
        version="2025.1.0",
        ecosystem="pypi",
        purl="pkg:pypi/certifi@2025.1.0",
    )
    certifi_after = Component(
        name="certifi",
        version="2026.1.1",
        ecosystem="pypi",
        purl="pkg:pypi/certifi@2026.1.1",
        source_url="https://github.com/certifi/python-certifi",
        scorecard=_scorecard(
            canonical_name="github.com/certifi/python-certifi",
            score=8.4,
            status=ScorecardStatus.SCORECARD_AVAILABLE,
        ),
    )
    certifi_change = ComponentChange(
        key=component_key(certifi_after),
        before=certifi_before,
        after=certifi_after,
        classification="version_changed",
    )

    risks = [
        RiskFinding(
            bucket=RiskBucket.NEW_PACKAGE,
            component_key=component_key(requests),
            component=requests,
            rationale="Component was not present in the before input.",
        ),
        RiskFinding(
            bucket=RiskBucket.NEW_PACKAGE,
            component_key=component_key(urllib3),
            component=urllib3,
            rationale="Component was not present in the before input.",
        ),
    ]
    policy = PolicyConfig(
        version=3,
        warn_on=("scorecard_below_threshold",),
        minimum_scorecard_score=7.0,
    )
    policy_evaluation = evaluate_policy(
        policy,
        policy_path="examples/policy-scorecard-minimal.yml",
        added=[requests, urllib3],
        changed=[certifi_change],
        findings=risks,
    )
    report = CompareReport(
        summary=ReportSummary(
            added=2,
            removed=0,
            changed=1,
            risk_counts=summarize_risks(risks),
        ),
        components=ReportComponents(
            added=[requests, urllib3],
            removed=[],
            changed=[certifi_change],
        ),
        risks=risks,
        metadata=ReportMetadata(
            before_format="requirements-txt",
            after_format="requirements-txt",
            generated_at=None,
            strict=False,
            stub=False,
            policy_evaluation=policy_evaluation,
            enrichment=ReportEnrichmentMetadata(
                mode="opt_in_scorecard",
                scorecard_enabled=True,
                scorecard_timeout_seconds=3.0,
                scorecard_network_access_performed=True,
                network_access_performed=True,
                scorecard_candidate_components=3,
                scorecard_supported_components=2,
                scorecard_status_counts={
                    "repository_unmapped": 1,
                    "scorecard_available": 2,
                },
            ),
        ),
        notes=[
            "This tool uses heuristic risk classification.",
            "OpenSSF Scorecard enrichment was requested explicitly.",
        ],
    )
    return report, before_path, after_path


def _scorecard(
    *,
    canonical_name: str | None,
    score: float | None,
    status: ScorecardStatus,
) -> ScorecardEvidence:
    repository = None
    note = None
    checks: tuple[ScorecardCheck, ...] = ()
    if canonical_name is not None:
        _, owner, repo = canonical_name.split("/", 2)
        repository = RepositoryMapping(
            platform="github.com",
            owner=owner,
            repo=repo,
            canonical_name=canonical_name,
            repository_url=f"https://{canonical_name}",
            source="component.source_url",
        )
        checks = (
            ScorecardCheck(name="Maintained", score=10, reason="Project is active."),
            ScorecardCheck(name="Binary-Artifacts", score=8, reason="No unexpected artifacts were found."),
        )
    else:
        note = "No high-confidence source repository mapping was available from explicit component metadata."

    return ScorecardEvidence(
        provider="openssf-scorecard",
        requested=True,
        repository=repository,
        statuses=(status,),
        score=score,
        date="2026-04-10T00:00:00Z" if score is not None else None,
        scorecard_version="5.0.0" if score is not None else None,
        scorecard_commit="def456" if score is not None else None,
        repository_commit="abc123" if score is not None else None,
        checks=checks,
        note=note,
    )


def _read_example(name: str) -> str:
    examples = Path(__file__).resolve().parents[1] / "examples"
    return (examples / name).read_text(encoding="utf-8")


def _normalize_sarif_snapshot(content: str) -> str:
    payload = json.loads(content)
    payload["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]["uri"] = "file:///__PROJECT_ROOT__/"
    return json.dumps(payload, indent=2) + "\n"
