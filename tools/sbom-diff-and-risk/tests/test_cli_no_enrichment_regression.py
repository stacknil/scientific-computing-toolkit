from __future__ import annotations

import json
from pathlib import Path

from sbom_diff_risk import cli
from sbom_diff_risk.models import ReportEnrichmentMetadata


def test_compare_stays_offline_and_deterministic_without_enrichment_flags(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    before = project_root / "examples" / "requirements_before.txt"
    after = project_root / "examples" / "requirements_after.txt"
    first_out = tmp_path / "first.json"
    second_out = tmp_path / "second.json"

    class UnexpectedPyPIEnricher:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            raise AssertionError("PyPI enrichment should remain disabled unless --enrich-pypi is set.")

    class UnexpectedScorecardEnricher:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            raise AssertionError("Scorecard enrichment should remain disabled unless --enrich-scorecard is set.")

    monkeypatch.setattr(cli, "PyPIProvenanceEnricher", UnexpectedPyPIEnricher)
    monkeypatch.setattr(cli, "ScorecardEnricher", UnexpectedScorecardEnricher)

    first_exit = cli.main(
        [
            "compare",
            "--before",
            str(before),
            "--after",
            str(after),
            "--out-json",
            str(first_out),
        ]
    )
    second_exit = cli.main(
        [
            "compare",
            "--before",
            str(before),
            "--after",
            str(after),
            "--out-json",
            str(second_out),
        ]
    )

    assert first_exit == 0
    assert second_exit == 0
    assert first_out.read_text(encoding="utf-8") == second_out.read_text(encoding="utf-8")

    payload = json.loads(first_out.read_text(encoding="utf-8"))
    assert payload["metadata"]["enrichment"]["mode"] == "offline_default"
    assert payload["metadata"]["enrichment"]["pypi_enabled"] is False
    assert payload["metadata"]["enrichment"]["network_access_performed"] is False
    assert payload["trust_signal_notes"] == [
        "PyPI components are present, but provenance enrichment was not enabled for this run."
    ]


def test_compare_runs_pypi_enrichment_only_when_requested(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    before = project_root / "examples" / "requirements_before.txt"
    after = project_root / "examples" / "requirements_after.txt"
    out_json = tmp_path / "enriched.json"

    class RecordingPyPIEnricher:
        instances: list["RecordingPyPIEnricher"] = []

        def __init__(self, *args, timeout_seconds: float, **kwargs) -> None:  # noqa: ANN002, ANN003
            self.timeout_seconds = timeout_seconds
            self.enrich_calls = 0
            self.__class__.instances.append(self)

        def enrich_components(self, components):  # noqa: ANN001
            self.enrich_calls += 1
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
                status_counts={"attestation_unavailable": 2},
            )

    class UnexpectedScorecardEnricher:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            raise AssertionError("Scorecard enrichment should remain disabled unless --enrich-scorecard is set.")

    monkeypatch.setattr(cli, "PyPIProvenanceEnricher", RecordingPyPIEnricher)
    monkeypatch.setattr(cli, "ScorecardEnricher", UnexpectedScorecardEnricher)

    exit_code = cli.main(
        [
            "compare",
            "--before",
            str(before),
            "--after",
            str(after),
            "--enrich-pypi",
            "--pypi-timeout",
            "2.5",
            "--out-json",
            str(out_json),
        ]
    )

    payload = json.loads(out_json.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert len(RecordingPyPIEnricher.instances) == 1
    assert RecordingPyPIEnricher.instances[0].timeout_seconds == 2.5
    assert RecordingPyPIEnricher.instances[0].enrich_calls == 2
    assert payload["metadata"]["enrichment"]["mode"] == "opt_in_pypi"
    assert payload["metadata"]["enrichment"]["pypi_enabled"] is True
    assert payload["metadata"]["enrichment"]["pypi_timeout_seconds"] == 2.5
    assert payload["notes"][1] == "PyPI provenance enrichment was requested explicitly."
    assert payload["trust_signal_notes"] == []


def test_compare_runs_scorecard_enrichment_only_when_requested(
    monkeypatch,
    tmp_path: Path,
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    before = project_root / "examples" / "requirements_before.txt"
    after = project_root / "examples" / "requirements_after.txt"
    out_json = tmp_path / "scorecard.json"

    class UnexpectedPyPIEnricher:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            raise AssertionError("PyPI enrichment should remain disabled unless --enrich-pypi is set.")

    class RecordingScorecardEnricher:
        instances: list["RecordingScorecardEnricher"] = []

        def __init__(self, *args, timeout_seconds: float, **kwargs) -> None:  # noqa: ANN002, ANN003
            self.timeout_seconds = timeout_seconds
            self.enrich_calls = 0
            self.__class__.instances.append(self)

        def enrich_components(self, components):  # noqa: ANN001
            self.enrich_calls += 1
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
                scorecard_status_counts={"repository_unmapped": 1},
            )

    monkeypatch.setattr(cli, "PyPIProvenanceEnricher", UnexpectedPyPIEnricher)
    monkeypatch.setattr(cli, "ScorecardEnricher", RecordingScorecardEnricher)

    exit_code = cli.main(
        [
            "compare",
            "--before",
            str(before),
            "--after",
            str(after),
            "--enrich-scorecard",
            "--scorecard-timeout",
            "4.25",
            "--out-json",
            str(out_json),
        ]
    )

    payload = json.loads(out_json.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert len(RecordingScorecardEnricher.instances) == 1
    assert RecordingScorecardEnricher.instances[0].timeout_seconds == 4.25
    assert RecordingScorecardEnricher.instances[0].enrich_calls == 2
    assert payload["metadata"]["enrichment"]["mode"] == "opt_in_scorecard"
    assert payload["metadata"]["enrichment"]["scorecard_enabled"] is True
    assert payload["metadata"]["enrichment"]["scorecard_timeout_seconds"] == 4.25
    assert payload["notes"][1] == "OpenSSF Scorecard enrichment was requested explicitly."
