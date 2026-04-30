from __future__ import annotations

import json
from pathlib import Path

from sbom_diff_risk import cli
from sbom_diff_risk.models import ReportEnrichmentMetadata


def test_cli_summary_json_writes_summary_only_file(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    summary_path = tmp_path / "summary.json"

    exit_code = cli.main(
        [
            "compare",
            "--before",
            str(project_root / "examples" / "cdx_before.json"),
            "--after",
            str(project_root / "examples" / "cdx_after.json"),
            "--summary-json",
            str(summary_path),
        ]
    )

    payload = json.loads(summary_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload == {
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
    assert "unchanged" not in payload
    assert summary_path.read_text(encoding="utf-8").endswith("\n")


def test_cli_summary_json_matches_full_report_summary(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    report_path = tmp_path / "report.json"
    summary_path = tmp_path / "summary.json"

    exit_code = cli.main(
        [
            "compare",
            "--before",
            str(project_root / "examples" / "cdx_before.json"),
            "--after",
            str(project_root / "examples" / "cdx_after.json"),
            "--out-json",
            str(report_path),
            "--summary-json",
            str(summary_path),
        ]
    )

    report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    summary_payload = json.loads(summary_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert summary_payload == report_payload["summary"]


def test_cli_summary_json_includes_policy_summary_when_policy_is_used(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    summary_path = tmp_path / "summary.json"

    exit_code = cli.main(
        [
            "compare",
            "--before",
            str(project_root / "examples" / "cdx_before.json"),
            "--after",
            str(project_root / "examples" / "cdx_after.json"),
            "--policy",
            str(project_root / "examples" / "policy-minimal.yml"),
            "--summary-json",
            str(summary_path),
        ]
    )

    payload = json.loads(summary_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["policy"] == {
        "status": "warn",
        "blocking": 0,
        "warning": 1,
        "suppressed": 0,
    }
    assert "enrichment" not in payload


def test_cli_summary_json_includes_enrichment_summary_when_enrichment_is_used(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    summary_path = tmp_path / "summary.json"

    class RecordingPyPIEnricher:
        def __init__(self, *args, timeout_seconds: float, **kwargs) -> None:  # noqa: ANN002, ANN003
            self.timeout_seconds = timeout_seconds

        def enrich_components(self, components):  # noqa: ANN001
            return components

        def build_report_metadata(self) -> ReportEnrichmentMetadata:
            return ReportEnrichmentMetadata(
                mode="opt_in_pypi",
                pypi_enabled=True,
                pypi_timeout_seconds=self.timeout_seconds,
                pypi_network_access_performed=False,
                network_access_performed=False,
                candidate_components=2,
                supported_components=2,
                status_counts={
                    "provenance_available": 1,
                    "attestation_unavailable": 1,
                },
            )

    monkeypatch.setattr(cli, "PyPIProvenanceEnricher", RecordingPyPIEnricher)

    exit_code = cli.main(
        [
            "compare",
            "--before",
            str(project_root / "examples" / "requirements_before.txt"),
            "--after",
            str(project_root / "examples" / "requirements_after.txt"),
            "--enrich-pypi",
            "--summary-json",
            str(summary_path),
        ]
    )

    payload = json.loads(summary_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["enrichment"] == {
        "status": "used",
        "mode": "opt_in_pypi",
        "pypi": {
            "candidate_components": 2,
            "supported_components": 2,
            "status_counts": {
                "attestation_unavailable": 1,
                "provenance_available": 1,
            },
        },
    }
    assert "policy" not in payload


def test_cli_summary_json_includes_scorecard_enrichment_summary_when_scorecard_is_used(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    summary_path = tmp_path / "summary.json"

    class RecordingScorecardEnricher:
        def __init__(self, *args, timeout_seconds: float, **kwargs) -> None:  # noqa: ANN002, ANN003
            self.timeout_seconds = timeout_seconds

        def enrich_components(self, components):  # noqa: ANN001
            return components

        def build_report_metadata(self) -> ReportEnrichmentMetadata:
            return ReportEnrichmentMetadata(
                mode="opt_in_scorecard",
                scorecard_enabled=True,
                scorecard_timeout_seconds=self.timeout_seconds,
                scorecard_network_access_performed=False,
                network_access_performed=False,
                scorecard_candidate_components=2,
                scorecard_supported_components=1,
                scorecard_status_counts={
                    "scorecard_available": 1,
                    "repository_unmapped": 1,
                },
            )

    monkeypatch.setattr(cli, "ScorecardEnricher", RecordingScorecardEnricher)

    exit_code = cli.main(
        [
            "compare",
            "--before",
            str(project_root / "examples" / "requirements_before.txt"),
            "--after",
            str(project_root / "examples" / "requirements_after.txt"),
            "--enrich-scorecard",
            "--summary-json",
            str(summary_path),
        ]
    )

    payload = json.loads(summary_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["enrichment"] == {
        "status": "used",
        "mode": "opt_in_scorecard",
        "scorecard": {
            "candidate_components": 2,
            "supported_components": 1,
            "status_counts": {
                "repository_unmapped": 1,
                "scorecard_available": 1,
            },
        },
    }
    assert "policy" not in payload


def test_cli_summary_json_omitted_does_not_write_summary_file(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    report_path = tmp_path / "report.json"
    summary_path = tmp_path / "summary.json"

    exit_code = cli.main(
        [
            "compare",
            "--before",
            str(project_root / "examples" / "cdx_before.json"),
            "--after",
            str(project_root / "examples" / "cdx_after.json"),
            "--out-json",
            str(report_path),
        ]
    )

    assert exit_code == 0
    assert report_path.is_file()
    assert not summary_path.exists()
