from __future__ import annotations

import json
from pathlib import Path

from sbom_diff_risk.diffing import component_key
from sbom_diff_risk.models import (
    CompareReport,
    Component,
    ComponentChange,
    ProvenanceEvidence,
    ProvenanceFileEvidence,
    ProvenanceStatus,
    ReportComponents,
    ReportEnrichmentMetadata,
    ReportMetadata,
    ReportSummary,
    RiskBucket,
    RiskFinding,
)
from sbom_diff_risk.policy_evaluator import evaluate_policy
from sbom_diff_risk.policy_models import PolicyConfig
from sbom_diff_risk.report_json import render_report_json
from sbom_diff_risk.report_md import render_report_markdown
from sbom_diff_risk.report_sarif import (
    render_report_sarif,
    sarif_rule_id_for_policy_violation,
)
from sbom_diff_risk.risk import summarize_risks


def test_provenance_report_json_matches_golden() -> None:
    report, _, _ = _build_sample_provenance_report()

    rendered = render_report_json(report)
    expected = _read_example("sample-provenance-report.json")

    assert rendered == expected


def test_provenance_report_markdown_matches_golden() -> None:
    report, _, _ = _build_sample_provenance_report()

    rendered = render_report_markdown(report)
    expected = _read_example("sample-provenance-report.md")

    assert rendered == expected


def test_provenance_report_json_includes_provenance_policy_summary() -> None:
    report, _, _ = _build_sample_provenance_report()

    payload = json.loads(render_report_json(report))

    assert payload["summary"]["policy"] == {
        "status": "fail",
        "blocking": 2,
        "warning": 1,
        "suppressed": 0,
    }
    assert payload["summary"]["enrichment"] == {
        "status": "used",
        "mode": "opt_in_pypi",
        "pypi": {
            "candidate_components": 3,
            "supported_components": 3,
            "status_counts": {
                "attestation_available": 2,
                "attestation_unavailable": 1,
                "provenance_available": 2,
            },
        },
    }
    assert payload["provenance_policy"]["configured"] is True
    assert payload["provenance_policy_impact"] == payload["provenance_policy"]
    assert payload["provenance_policy"]["requirements"]["require_attestations_for_new_packages"] is True
    assert payload["provenance_policy"]["requirements"]["allow_provenance_publishers"] == ["github actions"]
    assert payload["provenance_policy"]["counts"] == {"blocking": 2, "warning": 1, "suppressed": 0}
    assert payload["enrichment_metadata"]["pypi_network_access_performed"] is True


def test_provenance_component_evidence_includes_lookup_and_file_totals() -> None:
    report, _, _ = _build_sample_provenance_report()

    payload = json.loads(render_report_json(report))
    urllib3_provenance = payload["components"]["added"][0]["evidence"]["provenance"]
    mystery_lib_provenance = payload["components"]["added"][1]["evidence"]["provenance"]

    assert urllib3_provenance["supported"] is True
    assert urllib3_provenance["lookup_performed"] is True
    assert urllib3_provenance["files_evaluated"] == 1
    assert urllib3_provenance["files_with_attestations"] == 1
    assert urllib3_provenance["files_without_attestations"] == 0
    assert mystery_lib_provenance["supported"] is True
    assert mystery_lib_provenance["lookup_performed"] is True
    assert mystery_lib_provenance["files_evaluated"] == 1
    assert mystery_lib_provenance["files_with_attestations"] == 0
    assert mystery_lib_provenance["files_without_attestations"] == 1


def test_blocking_missing_attestation_emits_sarif_alert() -> None:
    component = Component(
        name="urllib3",
        version="2.2.1",
        ecosystem="pypi",
        provenance=_provenance(
            name="urllib3",
            version="2.2.1",
            statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
            file_statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
            attestation_count=0,
        ),
    )
    policy = PolicyConfig(version=2, block_on=("missing_attestation",))
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
            policy_evaluation=evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[]),
            enrichment=ReportEnrichmentMetadata(
                mode="opt_in_pypi",
                pypi_enabled=True,
                pypi_timeout_seconds=3.0,
                pypi_network_access_performed=True,
                network_access_performed=True,
                candidate_components=1,
                supported_components=1,
                status_counts={"attestation_unavailable": 1},
            ),
        ),
        notes=["PyPI provenance enrichment was requested explicitly."],
    )
    project_root = Path(__file__).resolve().parents[1]
    examples = project_root / "examples"

    payload = json.loads(
        render_report_sarif(report, before_path=examples / "requirements_before.txt", after_path=examples / "requirements_after.txt", base_dir=project_root)
    )

    results = payload["runs"][0]["results"]

    assert [result["ruleId"] for result in results] == ["sdr.policy_violation.missing_attestation"]
    assert results[0]["message"]["text"] == "urllib3: No PyPI attestations were published for this release."
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "examples/requirements_after.txt"


def test_provenance_sarif_matches_golden() -> None:
    report, before_path, after_path = _build_sample_provenance_report()
    project_root = Path(__file__).resolve().parents[1]

    rendered = render_report_sarif(report, before_path=before_path, after_path=after_path, base_dir=project_root)
    expected = _read_example("sample-provenance-report.sarif")

    assert _normalize_sarif_snapshot(rendered) == _normalize_sarif_snapshot(expected)


def test_provenance_sarif_rule_ids_are_stable() -> None:
    assert sarif_rule_id_for_policy_violation("provenance_required") == "sdr.policy_violation.provenance_required"
    assert sarif_rule_id_for_policy_violation("missing_attestation") == "sdr.policy_violation.missing_attestation"
    assert sarif_rule_id_for_policy_violation("unverified_provenance") == "sdr.policy_violation.unverified_provenance"
    assert sarif_rule_id_for_policy_violation("provenance_unavailable") is None


def test_non_blocking_missing_attestation_does_not_automatically_become_sarif_alert() -> None:
    component = Component(
        name="urllib3",
        version="2.2.1",
        ecosystem="pypi",
        provenance=_provenance(
            name="urllib3",
            version="2.2.1",
            statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
            file_statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
            attestation_count=0,
        ),
    )
    policy = PolicyConfig(version=2, warn_on=("missing_attestation",))
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
            policy_evaluation=evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[]),
            enrichment=ReportEnrichmentMetadata(
                mode="opt_in_pypi",
                pypi_enabled=True,
                pypi_timeout_seconds=3.0,
                pypi_network_access_performed=True,
                network_access_performed=True,
                candidate_components=1,
                supported_components=1,
                status_counts={"attestation_unavailable": 1},
            ),
        ),
        notes=["PyPI provenance enrichment was requested explicitly."],
    )
    project_root = Path(__file__).resolve().parents[1]
    examples = project_root / "examples"

    payload = json.loads(
        render_report_sarif(report, before_path=examples / "requirements_before.txt", after_path=examples / "requirements_after.txt", base_dir=project_root)
    )

    assert payload["runs"][0]["results"] == []


def test_provenance_sarif_prefers_primary_policy_alert_when_requirement_already_blocks() -> None:
    report, before_path, after_path = _build_sample_provenance_report()
    project_root = Path(__file__).resolve().parents[1]

    payload = json.loads(
        render_report_sarif(report, before_path=before_path, after_path=after_path, base_dir=project_root)
    )

    results = payload["runs"][0]["results"]

    assert [result["ruleId"] for result in results] == [
        "sdr.policy_violation.provenance_required",
        "sdr.policy_violation.unverified_provenance",
    ]
    assert results[0]["message"]["text"] == "mystery-lib: Provenance required for new package; no attestations were published."
    assert results[1]["message"]["text"] == "legacy-lib: PyPI attestation publisher could not be verified by policy."
    assert all(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "examples/requirements_after.txt"
        for result in results
    )


def test_provenance_required_for_suspicious_source_emits_concise_sarif_alert() -> None:
    component = Component(
        name="mystery-lib",
        version="1.0.0",
        ecosystem="pypi",
        source_url="http://example.test/mystery-lib",
    )
    finding = RiskFinding(
        bucket=RiskBucket.SUSPICIOUS_SOURCE,
        component_key="coord:pypi:mystery-lib",
        component=component,
        rationale="Source provenance is suspicious.",
    )
    policy = PolicyConfig(version=2, require_provenance_for_suspicious_sources=True)
    report = CompareReport(
        summary=ReportSummary(added=1, removed=0, changed=0, risk_counts=summarize_risks([finding])),
        components=ReportComponents(added=[component], removed=[], changed=[]),
        risks=[finding],
        metadata=ReportMetadata(
            before_format="requirements-txt",
            after_format="requirements-txt",
            generated_at=None,
            strict=False,
            stub=False,
            policy_evaluation=evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[finding]),
            enrichment=ReportEnrichmentMetadata(
                mode="offline_default",
                pypi_enabled=False,
                pypi_network_access_performed=False,
                network_access_performed=False,
            ),
        ),
        notes=["No network enrichment was performed."],
    )
    project_root = Path(__file__).resolve().parents[1]
    examples = project_root / "examples"

    payload = json.loads(
        render_report_sarif(report, before_path=examples / "requirements_before.txt", after_path=examples / "requirements_after.txt", base_dir=project_root)
    )

    results = payload["runs"][0]["results"]

    assert [result["ruleId"] for result in results] == ["sdr.policy_violation.provenance_required"]
    assert results[0]["message"]["text"] == "mystery-lib: Provenance required for suspicious source; provenance evidence was unavailable."
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "examples/requirements_after.txt"


def _build_sample_provenance_report() -> tuple[CompareReport, Path, Path]:
    project_root = Path(__file__).resolve().parents[1]
    examples = project_root / "examples"
    before_path = examples / "requirements_before.txt"
    after_path = examples / "requirements_after.txt"

    urllib3 = Component(
        name="urllib3",
        version="2.2.1",
        ecosystem="pypi",
        purl="pkg:pypi/urllib3@2.2.1",
        source_url="https://pypi.org/project/urllib3/2.2.1/",
        provenance=_provenance(
            name="urllib3",
            version="2.2.1",
            statuses=(ProvenanceStatus.PROVENANCE_AVAILABLE, ProvenanceStatus.ATTESTATION_AVAILABLE),
            file_statuses=(ProvenanceStatus.PROVENANCE_AVAILABLE, ProvenanceStatus.ATTESTATION_AVAILABLE),
            attestation_count=1,
            publisher_kinds=("github actions",),
            predicate_types=("https://example.test/attestation/v1",),
        ),
    )
    mystery_lib = Component(
        name="mystery-lib",
        version="1.0.0",
        ecosystem="pypi",
        purl="pkg:pypi/mystery-lib@1.0.0",
        source_url="https://pypi.org/project/mystery-lib/1.0.0/",
        provenance=_provenance(
            name="mystery-lib",
            version="1.0.0",
            statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
            file_statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
            attestation_count=0,
        ),
    )
    legacy_before = Component(
        name="legacy-lib",
        version="1.0.0",
        ecosystem="pypi",
        purl="pkg:pypi/legacy-lib@1.0.0",
    )
    legacy_after = Component(
        name="legacy-lib",
        version="1.1.0",
        ecosystem="pypi",
        purl="pkg:pypi/legacy-lib@1.1.0",
        provenance=_provenance(
            name="legacy-lib",
            version="1.1.0",
            statuses=(ProvenanceStatus.PROVENANCE_AVAILABLE, ProvenanceStatus.ATTESTATION_AVAILABLE),
            file_statuses=(ProvenanceStatus.PROVENANCE_AVAILABLE, ProvenanceStatus.ATTESTATION_AVAILABLE),
            attestation_count=1,
            publisher_kinds=("manual upload",),
            predicate_types=("https://example.test/attestation/v1",),
        ),
    )
    legacy_change = ComponentChange(
        key=component_key(legacy_after),
        before=legacy_before,
        after=legacy_after,
        classification="version_changed",
    )

    risks = [
        RiskFinding(
            bucket=RiskBucket.NEW_PACKAGE,
            component_key=component_key(urllib3),
            component=urllib3,
            rationale="Component was not present in the before input.",
        ),
        RiskFinding(
            bucket=RiskBucket.NEW_PACKAGE,
            component_key=component_key(mystery_lib),
            component=mystery_lib,
            rationale="Component was not present in the before input.",
        ),
        RiskFinding(
            bucket=RiskBucket.VERSION_CHANGE_UNCLASSIFIED,
            component_key=component_key(legacy_after),
            component=legacy_after,
            rationale="Version changed but did not qualify as a parseable SemVer major upgrade.",
        ),
    ]
    policy = PolicyConfig(
        version=2,
        block_on=("provenance_required", "unverified_provenance"),
        warn_on=("missing_attestation",),
        require_attestations_for_new_packages=True,
        allow_provenance_publishers=("github actions",),
    )
    policy_evaluation = evaluate_policy(
        policy,
        policy_path="examples/policy-provenance-strict.yml",
        added=[urllib3, mystery_lib],
        changed=[legacy_change],
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
            added=[urllib3, mystery_lib],
            removed=[],
            changed=[legacy_change],
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
                mode="opt_in_pypi",
                pypi_enabled=True,
                pypi_timeout_seconds=3.0,
                pypi_network_access_performed=True,
                network_access_performed=True,
                candidate_components=3,
                supported_components=3,
                status_counts={
                    "attestation_available": 2,
                    "attestation_unavailable": 1,
                    "provenance_available": 2,
                },
            ),
        ),
        notes=[
            "This tool uses heuristic risk classification.",
            "PyPI provenance enrichment was requested explicitly.",
        ],
    )
    return report, before_path, after_path


def _provenance(
    *,
    name: str,
    version: str,
    statuses: tuple[ProvenanceStatus, ...],
    file_statuses: tuple[ProvenanceStatus, ...],
    attestation_count: int,
    publisher_kinds: tuple[str, ...] = (),
    predicate_types: tuple[str, ...] = (),
) -> ProvenanceEvidence:
    return ProvenanceEvidence(
        provider="pypi",
        requested=True,
        supported=True,
        lookup_performed=True,
        package_name=name,
        package_version=version,
        release_url=f"https://pypi.org/project/{name}/{version}/",
        statuses=statuses,
        files=(
            ProvenanceFileEvidence(
                filename=f"{name}-{version}.tar.gz",
                url=f"https://files.pythonhosted.org/packages/{name}-{version}.tar.gz",
                sha256="deadbeef",
                upload_time="2026-04-01T00:00:00.000000Z",
                yanked=False,
                statuses=file_statuses,
                attestation_count=attestation_count,
                predicate_types=predicate_types,
                publisher_kinds=publisher_kinds,
            ),
        ),
        files_evaluated=1,
        files_with_attestations=1 if attestation_count > 0 else 0,
        files_without_attestations=0 if attestation_count > 0 else 1,
    )


def _read_example(name: str) -> str:
    examples = Path(__file__).resolve().parents[1] / "examples"
    return (examples / name).read_text(encoding="utf-8")


def _normalize_sarif_snapshot(content: str) -> str:
    payload = json.loads(content)
    payload["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]["uri"] = "file:///__PROJECT_ROOT__/"
    return json.dumps(payload, indent=2) + "\n"
