from __future__ import annotations

import base64
import json

from sbom_diff_risk.enrichment import PyPIProvenanceEnricher, normalize_provenance_file
from sbom_diff_risk.models import Component, ProvenanceEvidence, ProvenanceStatus
from sbom_diff_risk.pypi_integrity_client import (
    PyPIAttestation,
    PyPIClientError,
    PyPIFileProvenance,
    PyPIRelease,
    PyPIReleaseFile,
)
from sbom_diff_risk.pypi_provenance import provenance_evidence_to_dict


def test_normalize_provenance_file_decodes_predicate_type() -> None:
    release_file = _release_file()
    provenance = PyPIFileProvenance(
        filename=release_file.filename,
        attestation_count=1,
        attestations=(
            PyPIAttestation(
                statement=_encoded_statement({"predicateType": "https://example.test/attestation/v1"}),
                publisher_kind="GitHub Actions",
            ),
        ),
    )

    normalized = normalize_provenance_file(release_file=release_file, provenance=provenance)

    assert normalized.statuses == (
        ProvenanceStatus.PROVENANCE_AVAILABLE,
        ProvenanceStatus.ATTESTATION_AVAILABLE,
    )
    assert normalized.predicate_types == ("https://example.test/attestation/v1",)
    assert normalized.publisher_kinds == ("GitHub Actions",)


def test_enricher_records_attestation_available_for_supported_package() -> None:
    client = FakePyPIClient(
        releases={
            ("requests", "2.31.0"): PyPIRelease(
                project="requests",
                version="2.31.0",
                release_url="https://pypi.org/project/requests/2.31.0/",
                files=(_release_file(filename="requests-2.31.0.tar.gz"),),
            )
        },
        provenance={
            ("requests", "2.31.0", "requests-2.31.0.tar.gz"): PyPIFileProvenance(
                filename="requests-2.31.0.tar.gz",
                attestation_count=1,
                attestations=(
                    PyPIAttestation(
                        statement=_encoded_statement({"predicateType": "https://example.test/attestation/v1"}),
                        publisher_kind="GitHub Actions",
                    ),
                ),
            )
        },
    )
    enricher = PyPIProvenanceEnricher(client=client, timeout_seconds=2.5)

    [component] = enricher.enrich_components([Component(name="requests", version="2.31.0", ecosystem="pypi")])
    metadata = enricher.build_report_metadata()

    assert component.provenance is not None
    assert component.provenance.statuses == (
        ProvenanceStatus.PROVENANCE_AVAILABLE,
        ProvenanceStatus.ATTESTATION_AVAILABLE,
    )
    assert component.provenance.supported is True
    assert component.provenance.lookup_performed is True
    assert component.provenance.files_evaluated == 1
    assert component.provenance.files_with_attestations == 1
    assert component.provenance.files_without_attestations == 0
    assert component.provenance.files[0].attestation_count == 1
    assert metadata.mode == "opt_in_pypi"
    assert metadata.network_access_performed is True
    assert metadata.supported_components == 1
    assert metadata.status_counts == {
        "attestation_available": 1,
        "provenance_available": 1,
    }


def test_enricher_marks_attestation_unavailable_when_provenance_endpoint_returns_none() -> None:
    client = FakePyPIClient(
        releases={
            ("urllib3", "2.2.1"): PyPIRelease(
                project="urllib3",
                version="2.2.1",
                release_url="https://pypi.org/project/urllib3/2.2.1/",
                files=(_release_file(filename="urllib3-2.2.1.tar.gz"),),
            )
        },
        provenance={
            ("urllib3", "2.2.1", "urllib3-2.2.1.tar.gz"): None,
        },
    )
    enricher = PyPIProvenanceEnricher(client=client)

    [component] = enricher.enrich_components([Component(name="urllib3", version="2.2.1", ecosystem="pypi")])

    assert component.provenance is not None
    assert component.provenance.statuses == (ProvenanceStatus.ATTESTATION_UNAVAILABLE,)
    assert component.provenance.supported is True
    assert component.provenance.lookup_performed is True
    assert component.provenance.files_evaluated == 1
    assert component.provenance.files_with_attestations == 0
    assert component.provenance.files_without_attestations == 1
    assert component.provenance.files[0].statuses == (ProvenanceStatus.ATTESTATION_UNAVAILABLE,)


def test_enricher_marks_unsupported_for_non_pypi_component_without_network_access() -> None:
    client = FakePyPIClient()
    enricher = PyPIProvenanceEnricher(client=client)

    [component] = enricher.enrich_components([Component(name="left-pad", version="1.3.0", ecosystem="npm")])
    metadata = enricher.build_report_metadata()

    assert component.provenance is not None
    assert component.provenance.statuses == (ProvenanceStatus.UNSUPPORTED_FOR_PACKAGE,)
    assert component.provenance.supported is False
    assert component.provenance.lookup_performed is False
    assert client.release_calls == []
    assert metadata.network_access_performed is False
    assert metadata.supported_components == 0
    assert metadata.status_counts == {"unsupported_for_package": 1}


def test_enricher_captures_timeout_error_as_evidence() -> None:
    client = FakePyPIClient(
        release_errors={
            ("certifi", "2026.1.1"): PyPIClientError(
                "PyPI request timed out after 2.5 seconds for https://pypi.org/pypi/certifi/2026.1.1/json.",
                is_timeout=True,
            )
        }
    )
    enricher = PyPIProvenanceEnricher(client=client, timeout_seconds=2.5)

    [component] = enricher.enrich_components([Component(name="certifi", version="2026.1.1", ecosystem="pypi")])
    metadata = enricher.build_report_metadata()

    assert component.provenance is not None
    assert component.provenance.statuses == (ProvenanceStatus.ENRICHMENT_ERROR,)
    assert "timed out" in (component.provenance.error or "")
    assert metadata.network_access_performed is True
    assert metadata.status_counts == {"enrichment_error": 1}


def test_enricher_records_lookup_when_release_is_missing_after_explicit_opt_in() -> None:
    client = FakePyPIClient(
        release_errors={
            ("ghost-package", "9.9.9"): PyPIClientError(
                "PyPI request failed with HTTP 404 for https://pypi.org/pypi/ghost-package/9.9.9/json.",
                status_code=404,
            )
        }
    )
    enricher = PyPIProvenanceEnricher(client=client)

    [component] = enricher.enrich_components([Component(name="ghost-package", version="9.9.9", ecosystem="pypi")])
    metadata = enricher.build_report_metadata()

    assert component.provenance is not None
    assert component.provenance.statuses == (ProvenanceStatus.UNSUPPORTED_FOR_PACKAGE,)
    assert component.provenance.supported is False
    assert component.provenance.lookup_performed is True
    assert client.release_calls == [("ghost-package", "9.9.9")]
    assert metadata.network_access_performed is True
    assert metadata.supported_components == 0
    assert metadata.status_counts == {"unsupported_for_package": 1}


def test_provenance_evidence_to_dict_includes_lookup_and_file_counts() -> None:
    provenance = ProvenanceEvidence(
        provider="pypi",
        requested=True,
        supported=True,
        lookup_performed=True,
        package_name="requests",
        package_version="2.31.0",
        release_url="https://pypi.org/project/requests/2.31.0/",
        statuses=(
            ProvenanceStatus.PROVENANCE_AVAILABLE,
            ProvenanceStatus.ATTESTATION_AVAILABLE,
        ),
        files=(
            normalize_provenance_file(
                release_file=_release_file(filename="requests-2.31.0.tar.gz"),
                provenance=PyPIFileProvenance(
                    filename="requests-2.31.0.tar.gz",
                    attestation_count=1,
                    attestations=(
                        PyPIAttestation(
                            statement=_encoded_statement({"predicateType": "https://example.test/attestation/v1"}),
                            publisher_kind="GitHub Actions",
                        ),
                    ),
                ),
            ),
        ),
        files_evaluated=1,
        files_with_attestations=1,
        files_without_attestations=0,
    )

    payload = provenance_evidence_to_dict(provenance)

    assert payload is not None
    assert payload["supported"] is True
    assert payload["lookup_performed"] is True
    assert payload["files_evaluated"] == 1
    assert payload["files_with_attestations"] == 1
    assert payload["files_without_attestations"] == 0


class FakePyPIClient:
    def __init__(
        self,
        *,
        releases: dict[tuple[str, str], PyPIRelease] | None = None,
        provenance: dict[tuple[str, str, str], PyPIFileProvenance | None] | None = None,
        release_errors: dict[tuple[str, str], Exception] | None = None,
        provenance_errors: dict[tuple[str, str, str], Exception] | None = None,
    ) -> None:
        self._releases = releases or {}
        self._provenance = provenance or {}
        self._release_errors = release_errors or {}
        self._provenance_errors = provenance_errors or {}
        self.release_calls: list[tuple[str, str]] = []
        self.provenance_calls: list[tuple[str, str, str]] = []

    def fetch_release(self, project: str, version: str) -> PyPIRelease:
        key = (project, version)
        self.release_calls.append(key)
        if key in self._release_errors:
            raise self._release_errors[key]
        return self._releases[key]

    def fetch_provenance(self, project: str, version: str, filename: str) -> PyPIFileProvenance | None:
        key = (project, version, filename)
        self.provenance_calls.append(key)
        if key in self._provenance_errors:
            raise self._provenance_errors[key]
        return self._provenance[key]


def _release_file(*, filename: str = "example-1.0.0.tar.gz") -> PyPIReleaseFile:
    return PyPIReleaseFile(
        filename=filename,
        url=f"https://files.pythonhosted.org/packages/source/{filename}",
        sha256="deadbeef",
        upload_time="2026-04-01T00:00:00.000000Z",
        yanked=False,
    )


def _encoded_statement(payload: dict[str, object]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    return encoded.rstrip("=")
