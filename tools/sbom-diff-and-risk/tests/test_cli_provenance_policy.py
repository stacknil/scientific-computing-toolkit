from __future__ import annotations

import argparse
import json
from pathlib import Path

from sbom_diff_risk.cli import run_compare
from sbom_diff_risk.models import ProvenanceEvidence, ProvenanceFileEvidence, ProvenanceStatus, ReportEnrichmentMetadata


def test_run_compare_blocks_on_provenance_required_with_mocked_enrichment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        "\n".join(
            [
                "version: 2",
                "block_on:",
                "  - provenance_required",
                "require_attestations_for_new_packages: true",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("sbom_diff_risk.cli.PyPIProvenanceEnricher", FakeMissingAttestationEnricher)

    exit_code = run_compare(
        argparse.Namespace(
            before=project_root / "examples" / "requirements_before.txt",
            after=project_root / "examples" / "requirements_after.txt",
            format="auto",
            before_format=None,
            after_format=None,
            pyproject_group=None,
            out_json=tmp_path / "report.json",
            out_md=None,
            out_sarif=None,
            policy=policy_path,
            fail_on=None,
            warn_on=None,
            strict=False,
            enrich_pypi=True,
            pypi_timeout=2.0,
            source_allowlist="pypi.org,files.pythonhosted.org,github.com",
        )
    )

    payload = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))

    assert exit_code == 1
    assert any(item["rule_id"] == "provenance_required" for item in payload["blocking_findings"])


def test_run_compare_passes_when_package_is_allowlisted_for_missing_attestation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        "\n".join(
            [
                "version: 2",
                "block_on:",
                "  - provenance_required",
                "require_attestations_for_new_packages: true",
                "allow_unattested_packages:",
                "  - urllib3",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("sbom_diff_risk.cli.PyPIProvenanceEnricher", FakeMissingAttestationEnricher)

    exit_code = run_compare(
        argparse.Namespace(
            before=project_root / "examples" / "requirements_before.txt",
            after=project_root / "examples" / "requirements_after.txt",
            format="auto",
            before_format=None,
            after_format=None,
            pyproject_group=None,
            out_json=tmp_path / "report.json",
            out_md=None,
            out_sarif=None,
            policy=policy_path,
            fail_on=None,
            warn_on=None,
            strict=False,
            enrich_pypi=True,
            pypi_timeout=2.0,
            source_allowlist="pypi.org,files.pythonhosted.org,github.com",
        )
    )

    payload = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["blocking_findings"] == []


def test_run_compare_blocks_on_unverified_provenance_with_publisher_override_alias(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        "\n".join(
            [
                "version: 2",
                "block_on:",
                "  - unverified_provenance",
                "allow_unattested_publishers:",
                "  - github actions",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("sbom_diff_risk.cli.PyPIProvenanceEnricher", FakeUnverifiedPublisherEnricher)

    exit_code = run_compare(
        argparse.Namespace(
            before=project_root / "examples" / "requirements_before.txt",
            after=project_root / "examples" / "requirements_after.txt",
            format="auto",
            before_format=None,
            after_format=None,
            pyproject_group=None,
            out_json=tmp_path / "report.json",
            out_md=None,
            out_sarif=None,
            policy=policy_path,
            fail_on=None,
            warn_on=None,
            strict=False,
            enrich_pypi=True,
            pypi_timeout=2.0,
            source_allowlist="pypi.org,files.pythonhosted.org,github.com",
        )
    )

    payload = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))

    assert exit_code == 1
    assert any(item["rule_id"] == "unverified_provenance" for item in payload["blocking_findings"])


def test_run_compare_keeps_provenance_unavailable_blocking_even_for_allowlisted_package(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        "\n".join(
            [
                "version: 2",
                "block_on:",
                "  - provenance_unavailable",
                "allow_unattested_packages:",
                "  - urllib3",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("sbom_diff_risk.cli.PyPIProvenanceEnricher", FakeUnavailableProvenanceEnricher)

    exit_code = run_compare(
        argparse.Namespace(
            before=project_root / "examples" / "requirements_before.txt",
            after=project_root / "examples" / "requirements_after.txt",
            format="auto",
            before_format=None,
            after_format=None,
            pyproject_group=None,
            out_json=tmp_path / "report.json",
            out_md=None,
            out_sarif=None,
            policy=policy_path,
            fail_on=None,
            warn_on=None,
            strict=False,
            enrich_pypi=True,
            pypi_timeout=2.0,
            source_allowlist="pypi.org,files.pythonhosted.org,github.com",
        )
    )

    payload = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))

    assert exit_code == 1
    assert any(item["rule_id"] == "provenance_unavailable" for item in payload["blocking_findings"])


class FakeMissingAttestationEnricher:
    def __init__(self, *, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds

    def enrich_components(self, components):  # noqa: ANN001
        for component in components:
            if component.ecosystem.strip().lower() != "pypi":
                continue
            component.provenance = ProvenanceEvidence(
                provider="pypi",
                requested=True,
                package_name=component.name,
                package_version=component.version,
                release_url=f"https://pypi.org/project/{component.name}/{component.version}/",
                statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
                files=(
                    ProvenanceFileEvidence(
                        filename=f"{component.name}-{component.version}.tar.gz",
                        statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
                        attestation_count=0,
                    ),
                ),
            )
        return components

    def build_report_metadata(self) -> ReportEnrichmentMetadata:
        return ReportEnrichmentMetadata(
            mode="opt_in_pypi",
            pypi_enabled=True,
            pypi_timeout_seconds=self.timeout_seconds,
            network_access_performed=True,
            candidate_components=3,
            supported_components=3,
            status_counts={"attestation_unavailable": 3},
        )


class FakeUnverifiedPublisherEnricher:
    def __init__(self, *, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds

    def enrich_components(self, components):  # noqa: ANN001
        for component in components:
            if component.ecosystem.strip().lower() != "pypi":
                continue
            component.provenance = ProvenanceEvidence(
                provider="pypi",
                requested=True,
                package_name=component.name,
                package_version=component.version,
                release_url=f"https://pypi.org/project/{component.name}/{component.version}/",
                statuses=(ProvenanceStatus.PROVENANCE_AVAILABLE, ProvenanceStatus.ATTESTATION_AVAILABLE),
                files=(
                    ProvenanceFileEvidence(
                        filename=f"{component.name}-{component.version}.tar.gz",
                        statuses=(ProvenanceStatus.PROVENANCE_AVAILABLE, ProvenanceStatus.ATTESTATION_AVAILABLE),
                        attestation_count=1,
                        publisher_kinds=("manual upload",),
                    ),
                ),
            )
        return components

    def build_report_metadata(self) -> ReportEnrichmentMetadata:
        return ReportEnrichmentMetadata(
            mode="opt_in_pypi",
            pypi_enabled=True,
            pypi_timeout_seconds=self.timeout_seconds,
            pypi_network_access_performed=True,
            network_access_performed=True,
            candidate_components=3,
            supported_components=3,
            status_counts={
                "attestation_available": 3,
                "provenance_available": 3,
            },
        )


class FakeUnavailableProvenanceEnricher:
    def __init__(self, *, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds

    def enrich_components(self, components):  # noqa: ANN001
        for component in components:
            if component.ecosystem.strip().lower() != "pypi":
                continue
            component.provenance = ProvenanceEvidence(
                provider="pypi",
                requested=True,
                package_name=component.name,
                package_version=component.version,
                release_url=f"https://pypi.org/project/{component.name}/{component.version}/",
                statuses=(ProvenanceStatus.ENRICHMENT_ERROR,),
                error="PyPI provenance evidence could not be fetched due to an enrichment error.",
            )
        return components

    def build_report_metadata(self) -> ReportEnrichmentMetadata:
        return ReportEnrichmentMetadata(
            mode="opt_in_pypi",
            pypi_enabled=True,
            pypi_timeout_seconds=self.timeout_seconds,
            pypi_network_access_performed=True,
            network_access_performed=True,
            candidate_components=3,
            supported_components=3,
            status_counts={"enrichment_error": 3},
        )
