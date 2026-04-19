from __future__ import annotations

import base64
import binascii
import json

from .models import (
    Component,
    ProvenanceEvidence,
    ProvenanceFileEvidence,
    ProvenanceStatus,
)
from .pypi_integrity_client import (
    PyPIClientError,
    PyPIFileProvenance,
    PyPIIntegrityClient,
    PyPIRelease,
)

_STATUS_ORDER = {
    ProvenanceStatus.PROVENANCE_AVAILABLE: 0,
    ProvenanceStatus.ATTESTATION_AVAILABLE: 1,
    ProvenanceStatus.ATTESTATION_UNAVAILABLE: 2,
    ProvenanceStatus.ENRICHMENT_ERROR: 3,
    ProvenanceStatus.UNSUPPORTED_FOR_PACKAGE: 4,
}


def normalize_pypi_provenance(component: Component, *, client: PyPIIntegrityClient) -> ProvenanceEvidence:
    if component.ecosystem.strip().lower() != "pypi":
        return _unsupported_provenance(component)
    if not component.name.strip() or not component.version or not component.version.strip():
        return _unsupported_provenance(component)

    try:
        release = client.fetch_release(component.name, component.version)
    except PyPIClientError as exc:
        if exc.status_code == 404:
            return _unsupported_provenance(component, lookup_performed=True)
        return ProvenanceEvidence(
            provider="pypi",
            requested=True,
            supported=True,
            lookup_performed=True,
            package_name=component.name,
            package_version=component.version,
            release_url=_release_url(component.name, component.version),
            statuses=(ProvenanceStatus.ENRICHMENT_ERROR,),
            error=str(exc),
        )

    return _normalize_release_provenance(component, release=release, client=client)


def normalize_provenance_file(
    *,
    release_file,
    provenance: PyPIFileProvenance | None,
) -> ProvenanceFileEvidence:
    if provenance is None:
        return ProvenanceFileEvidence(
            filename=release_file.filename,
            url=release_file.url,
            sha256=release_file.sha256,
            upload_time=release_file.upload_time,
            yanked=release_file.yanked,
            statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
            attestation_count=0,
        )

    predicate_types = sorted(
        {
            predicate_type
            for predicate_type in (_decode_statement_predicate_type(item.statement) for item in provenance.attestations)
            if predicate_type
        }
    )
    publisher_kinds = sorted({item.publisher_kind for item in provenance.attestations if item.publisher_kind})
    statuses = [ProvenanceStatus.PROVENANCE_AVAILABLE]
    if provenance.attestation_count > 0:
        statuses.append(ProvenanceStatus.ATTESTATION_AVAILABLE)
    else:
        statuses.append(ProvenanceStatus.ATTESTATION_UNAVAILABLE)

    return ProvenanceFileEvidence(
        filename=release_file.filename,
        url=release_file.url,
        sha256=release_file.sha256,
        upload_time=release_file.upload_time,
        yanked=release_file.yanked,
        statuses=tuple(statuses),
        attestation_count=provenance.attestation_count,
        predicate_types=tuple(predicate_types),
        publisher_kinds=tuple(publisher_kinds),
    )


def provenance_evidence_to_dict(provenance: ProvenanceEvidence | None) -> dict[str, object] | None:
    if provenance is None:
        return None
    return {
        "provider": provenance.provider,
        "requested": provenance.requested,
        "supported": provenance.supported,
        "lookup_performed": provenance.lookup_performed,
        "package_name": provenance.package_name,
        "package_version": provenance.package_version,
        "release_url": provenance.release_url,
        "statuses": [status.value for status in provenance.statuses],
        "files": [
            {
                "filename": item.filename,
                "url": item.url,
                "sha256": item.sha256,
                "upload_time": item.upload_time,
                "yanked": item.yanked,
                "statuses": [status.value for status in item.statuses],
                "attestation_count": item.attestation_count,
                "predicate_types": list(item.predicate_types),
                "publisher_kinds": list(item.publisher_kinds),
                "error": item.error,
            }
            for item in provenance.files
        ],
        "files_evaluated": provenance.files_evaluated,
        "files_with_attestations": provenance.files_with_attestations,
        "files_without_attestations": provenance.files_without_attestations,
        "error": provenance.error,
    }


def _normalize_release_provenance(
    component: Component,
    *,
    release: PyPIRelease,
    client: PyPIIntegrityClient,
) -> ProvenanceEvidence:
    if not release.files:
        return _unsupported_provenance(component, lookup_performed=True)

    component_statuses: set[ProvenanceStatus] = set()
    file_evidence: list[ProvenanceFileEvidence] = []
    first_error: str | None = None

    for release_file in release.files:
        try:
            provenance = client.fetch_provenance(component.name, component.version or "", release_file.filename)
        except PyPIClientError as exc:
            component_statuses.add(ProvenanceStatus.ENRICHMENT_ERROR)
            if first_error is None:
                first_error = str(exc)
            file_evidence.append(
                ProvenanceFileEvidence(
                    filename=release_file.filename,
                    url=release_file.url,
                    sha256=release_file.sha256,
                    upload_time=release_file.upload_time,
                    yanked=release_file.yanked,
                    statuses=(ProvenanceStatus.ENRICHMENT_ERROR,),
                    error=str(exc),
                )
            )
            continue

        normalized_file = normalize_provenance_file(release_file=release_file, provenance=provenance)
        file_evidence.append(normalized_file)
        component_statuses.update(normalized_file.statuses)

    files_evaluated = len(file_evidence)
    files_with_attestations = sum(1 for item in file_evidence if item.attestation_count > 0)
    return ProvenanceEvidence(
        provider="pypi",
        requested=True,
        supported=True,
        lookup_performed=True,
        package_name=component.name,
        package_version=component.version,
        release_url=release.release_url or _release_url(component.name, component.version or ""),
        statuses=_sorted_statuses(component_statuses or {ProvenanceStatus.ATTESTATION_UNAVAILABLE}),
        files=tuple(file_evidence),
        files_evaluated=files_evaluated,
        files_with_attestations=files_with_attestations,
        files_without_attestations=files_evaluated - files_with_attestations,
        error=first_error,
    )


def _unsupported_provenance(
    component: Component,
    *,
    lookup_performed: bool = False,
) -> ProvenanceEvidence:
    return ProvenanceEvidence(
        provider="pypi",
        requested=True,
        supported=False,
        lookup_performed=lookup_performed,
        package_name=component.name,
        package_version=component.version,
        release_url=_release_url(component.name, component.version or ""),
        statuses=(ProvenanceStatus.UNSUPPORTED_FOR_PACKAGE,),
    )


def _release_url(name: str, version: str) -> str:
    if version:
        return f"https://pypi.org/project/{name}/{version}/"
    return f"https://pypi.org/project/{name}/"


def _decode_statement_predicate_type(statement: str | None) -> str | None:
    if not statement:
        return None

    padding = (-len(statement)) % 4
    encoded = statement + ("=" * padding)
    try:
        decoded = base64.urlsafe_b64decode(encoded.encode("utf-8"))
    except (ValueError, binascii.Error):
        return None

    try:
        payload = json.loads(decoded)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    predicate_type = payload.get("predicateType")
    if not isinstance(predicate_type, str):
        return None
    stripped = predicate_type.strip()
    return stripped or None


def _sorted_statuses(statuses: set[ProvenanceStatus]) -> tuple[ProvenanceStatus, ...]:
    return tuple(sorted(statuses, key=lambda item: (_STATUS_ORDER[item], item.value)))
