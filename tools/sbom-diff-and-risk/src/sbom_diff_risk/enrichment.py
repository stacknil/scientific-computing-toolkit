from __future__ import annotations

from collections import Counter
from dataclasses import replace

from .models import (
    Component,
    ProvenanceEvidence,
    ReportEnrichmentMetadata,
)
from .pypi_integrity_client import PyPIIntegrityClient
from .pypi_provenance import (
    normalize_provenance_file,
    normalize_pypi_provenance,
    provenance_evidence_to_dict,
)

DEFAULT_PYPI_TIMEOUT_SECONDS = 5.0


class PyPIProvenanceEnricher:
    def __init__(
        self,
        *,
        client: PyPIIntegrityClient | None = None,
        timeout_seconds: float = DEFAULT_PYPI_TIMEOUT_SECONDS,
    ) -> None:
        self.client = client or PyPIIntegrityClient(timeout_seconds=timeout_seconds)
        self.timeout_seconds = timeout_seconds
        self._cache: dict[tuple[str, str, str], ProvenanceEvidence] = {}
        self._seen_keys: set[tuple[str, str, str]] = set()

    def enrich_components(self, components: list[Component]) -> list[Component]:
        enriched: list[Component] = []
        for component in components:
            key = _component_identity(component)
            if key not in self._cache:
                self._seen_keys.add(key)
                self._cache[key] = normalize_pypi_provenance(component, client=self.client)
            enriched.append(replace(component, provenance=self._cache[key]))
        return enriched

    def build_report_metadata(self) -> ReportEnrichmentMetadata:
        if not self._seen_keys:
            return ReportEnrichmentMetadata(
                mode="opt_in_pypi",
                pypi_enabled=True,
                pypi_timeout_seconds=self.timeout_seconds,
                pypi_network_access_performed=False,
                network_access_performed=False,
                candidate_components=0,
                supported_components=0,
                status_counts={},
            )

        evidences = [self._cache[key] for key in sorted(self._seen_keys)]
        counter = Counter(
            status.value
            for evidence in evidences
            for status in evidence.statuses
        )
        pypi_network_access_performed = any(evidence.lookup_performed for evidence in evidences)
        return ReportEnrichmentMetadata(
            mode="opt_in_pypi",
            pypi_enabled=True,
            pypi_timeout_seconds=self.timeout_seconds,
            pypi_network_access_performed=pypi_network_access_performed,
            network_access_performed=pypi_network_access_performed,
            candidate_components=len(evidences),
            supported_components=sum(1 for evidence in evidences if evidence.supported),
            status_counts={key: counter[key] for key in sorted(counter)},
        )


def merge_enrichment_metadata(*metadata_items: ReportEnrichmentMetadata | None) -> ReportEnrichmentMetadata:
    items = [item for item in metadata_items if item is not None]
    if not items:
        return ReportEnrichmentMetadata()

    merged = ReportEnrichmentMetadata(
        mode=_combined_enrichment_mode(items),
        pypi_enabled=any(item.pypi_enabled for item in items),
        pypi_timeout_seconds=_first_non_none(item.pypi_timeout_seconds for item in items),
        pypi_network_access_performed=any(item.pypi_network_access_performed for item in items),
        scorecard_enabled=any(item.scorecard_enabled for item in items),
        scorecard_timeout_seconds=_first_non_none(item.scorecard_timeout_seconds for item in items),
        scorecard_network_access_performed=any(item.scorecard_network_access_performed for item in items),
        network_access_performed=any(item.network_access_performed for item in items),
        candidate_components=sum(item.candidate_components for item in items),
        supported_components=sum(item.supported_components for item in items),
        status_counts=_merge_status_counts(item.status_counts for item in items),
        scorecard_candidate_components=sum(item.scorecard_candidate_components for item in items),
        scorecard_supported_components=sum(item.scorecard_supported_components for item in items),
        scorecard_status_counts=_merge_status_counts(item.scorecard_status_counts for item in items),
    )
    return merged


def enrichment_metadata_to_dict(metadata: ReportEnrichmentMetadata) -> dict[str, object]:
    return {
        "mode": metadata.mode,
        "pypi_enabled": metadata.pypi_enabled,
        "pypi_timeout_seconds": metadata.pypi_timeout_seconds,
        "pypi_network_access_performed": metadata.pypi_network_access_performed,
        "network_access_performed": metadata.network_access_performed,
        "candidate_components": metadata.candidate_components,
        "supported_components": metadata.supported_components,
        "status_counts": dict(metadata.status_counts),
        "scorecard_enabled": metadata.scorecard_enabled,
        "scorecard_timeout_seconds": metadata.scorecard_timeout_seconds,
        "scorecard_network_access_performed": metadata.scorecard_network_access_performed,
        "scorecard_candidate_components": metadata.scorecard_candidate_components,
        "scorecard_supported_components": metadata.scorecard_supported_components,
        "scorecard_status_counts": dict(metadata.scorecard_status_counts),
    }


def _component_identity(component: Component) -> tuple[str, str, str]:
    return (
        component.ecosystem.strip().lower(),
        component.name.strip().lower(),
        (component.version or "").strip().lower(),
    )


def _combined_enrichment_mode(metadata_items: list[ReportEnrichmentMetadata]) -> str:
    pypi_enabled = any(item.pypi_enabled for item in metadata_items)
    scorecard_enabled = any(item.scorecard_enabled for item in metadata_items)
    if pypi_enabled and scorecard_enabled:
        return "opt_in_pypi_and_scorecard"
    if pypi_enabled:
        return "opt_in_pypi"
    if scorecard_enabled:
        return "opt_in_scorecard"
    return "offline_default"


def _merge_status_counts(status_count_dicts) -> dict[str, int]:  # noqa: ANN001
    counter: Counter[str] = Counter()
    for status_counts in status_count_dicts:
        counter.update(status_counts)
    return {key: counter[key] for key in sorted(counter)}


def _first_non_none(values) -> float | None:  # noqa: ANN001
    for value in values:
        if value is not None:
            return value
    return None
