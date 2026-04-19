from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable
from urllib.parse import urlparse

from .models import Component, RepositoryMapping, RepositoryMappingConfidence

_SUPPORTED_SCORECARD_PLATFORMS = {"github.com"}
_REF_SOURCE_PRIORITY = {
    "cyclonedx.externalReferences.vcs": 0,
    "spdx.externalRefs.vcs": 1,
    "component.source_url": 2,
    "cyclonedx.externalReferences.website": 10,
    "cyclonedx.externalReferences.distribution": 10,
    "spdx.externalRefs": 11,
    "spdx.homepage": 12,
    "spdx.downloadLocation": 12,
}
_HIGH_CONFIDENCE_SOURCES = {
    "cyclonedx.externalReferences.vcs",
    "spdx.externalRefs.vcs",
    "component.source_url",
}


@dataclass(slots=True, frozen=True)
class RepositoryMappingCandidate:
    mapping: RepositoryMapping
    priority: int


@dataclass(slots=True, frozen=True)
class RepositoryMappingAssessment:
    mapping: RepositoryMapping | None
    confidence: RepositoryMappingConfidence | None
    reason: str
    candidates: tuple[RepositoryMappingCandidate, ...] = ()


def map_component_to_repository(component: Component) -> RepositoryMapping | None:
    return assess_component_repository_mapping(component).mapping


def assess_component_repository_mapping(component: Component) -> RepositoryMappingAssessment:
    candidates = tuple(_repository_candidates(component))
    if not candidates:
        return RepositoryMappingAssessment(
            mapping=None,
            confidence=None,
            reason="no_repository_candidates",
        )

    high_confidence_candidates = tuple(
        candidate
        for candidate in candidates
        if candidate.mapping.confidence is RepositoryMappingConfidence.HIGH
    )
    if not high_confidence_candidates:
        return RepositoryMappingAssessment(
            mapping=None,
            confidence=RepositoryMappingConfidence.LOW,
            reason="only_low_confidence_candidates",
            candidates=candidates,
        )

    canonical_names = {candidate.mapping.canonical_name for candidate in high_confidence_candidates}
    if len(canonical_names) != 1:
        return RepositoryMappingAssessment(
            mapping=None,
            confidence=RepositoryMappingConfidence.HIGH,
            reason="ambiguous_high_confidence_candidates",
            candidates=high_confidence_candidates,
        )

    selected = min(
        high_confidence_candidates,
        key=lambda candidate: (
            candidate.priority,
            candidate.mapping.source,
            candidate.mapping.canonical_name,
        ),
    )
    return RepositoryMappingAssessment(
        mapping=selected.mapping,
        confidence=selected.mapping.confidence,
        reason="mapped",
        candidates=high_confidence_candidates,
    )


def repository_mapping_cache_key(component: Component) -> tuple[str, str, str, tuple[tuple[str, str], ...]]:
    return (
        component.ecosystem.strip().lower(),
        component.name.strip().lower(),
        (component.version or "").strip().lower(),
        tuple(sorted((source, raw_url.strip()) for raw_url, source in _candidate_urls(component))),
    )


def _repository_candidates(component: Component) -> list[RepositoryMappingCandidate]:
    candidates: list[RepositoryMappingCandidate] = []
    for raw_url, source in _candidate_urls(component):
        mapping = _normalize_repository_url(raw_url, source=source)
        if mapping is None:
            continue
        candidates.append(
            RepositoryMappingCandidate(
                mapping=mapping,
                priority=_REF_SOURCE_PRIORITY.get(source, 99),
            )
        )
    return _dedupe_candidates(candidates)


def _candidate_urls(component: Component) -> Iterable[tuple[str, str]]:
    source_format = component.evidence.get("source_format")
    if source_format == "cyclonedx-json":
        raw_component = component.evidence.get("component")
        if isinstance(raw_component, dict):
            yield from _cyclonedx_reference_urls(raw_component)
            return
    elif source_format == "spdx-json":
        raw_package = component.evidence.get("package")
        if isinstance(raw_package, dict):
            yield from _spdx_reference_urls(raw_package)
            return

    if component.source_url:
        yield component.source_url, "component.source_url"


def _cyclonedx_reference_urls(raw_component: dict[str, object]) -> Iterable[tuple[str, str]]:
    raw_refs = raw_component.get("externalReferences")
    if not isinstance(raw_refs, list):
        return ()

    urls: list[tuple[str, str]] = []
    for raw_ref in raw_refs:
        if not isinstance(raw_ref, dict):
            continue
        raw_url = raw_ref.get("url")
        raw_type = raw_ref.get("type")
        if not isinstance(raw_url, str) or not raw_url.strip():
            continue
        if raw_type == "vcs":
            urls.append((raw_url, "cyclonedx.externalReferences.vcs"))
        elif raw_type == "website":
            urls.append((raw_url, "cyclonedx.externalReferences.website"))
        elif raw_type == "distribution":
            urls.append((raw_url, "cyclonedx.externalReferences.distribution"))
    return tuple(urls)


def _spdx_reference_urls(raw_package: dict[str, object]) -> Iterable[tuple[str, str]]:
    urls: list[tuple[str, str]] = []

    homepage = raw_package.get("homepage")
    if isinstance(homepage, str) and homepage.strip() and homepage != "NOASSERTION":
        urls.append((homepage, "spdx.homepage"))

    download_location = raw_package.get("downloadLocation")
    if isinstance(download_location, str) and download_location.strip() and download_location != "NOASSERTION":
        urls.append((download_location, "spdx.downloadLocation"))

    raw_refs = raw_package.get("externalRefs")
    if not isinstance(raw_refs, list):
        return tuple(urls)

    for raw_ref in raw_refs:
        if not isinstance(raw_ref, dict):
            continue
        reference_type = raw_ref.get("referenceType")
        locator = raw_ref.get("referenceLocator")
        if reference_type == "purl":
            continue
        if not isinstance(locator, str) or not locator.strip():
            continue
        urls.append((locator, _spdx_reference_source(reference_type)))

    return tuple(urls)


def _spdx_reference_source(reference_type: object) -> str:
    if not isinstance(reference_type, str):
        return "spdx.externalRefs"
    normalized = reference_type.strip().lower()
    tokens = tuple(token for token in re.split(r"[^a-z]+", normalized) if token)
    if any(token in {"vcs", "scm", "git"} for token in tokens):
        return "spdx.externalRefs.vcs"
    return "spdx.externalRefs"


def _normalize_repository_url(raw_url: str, *, source: str) -> RepositoryMapping | None:
    url = raw_url.strip()
    if not url:
        return None

    normalized = url
    while normalized.startswith("git+"):
        normalized = normalized[4:]

    if normalized.startswith("git@"):
        normalized = f"ssh://{normalized.replace(':', '/', 1)}"

    parsed = urlparse(normalized)
    host = (parsed.hostname or "").strip().lower()
    if host not in _SUPPORTED_SCORECARD_PLATFORMS:
        return None

    path_segments = [segment for segment in parsed.path.split("/") if segment]
    if len(path_segments) != 2:
        return None

    owner = path_segments[0].strip()
    repo = path_segments[1].strip()
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return None

    canonical_name = f"{host}/{owner}/{repo}"
    return RepositoryMapping(
        platform=host,
        owner=owner,
        repo=repo,
        canonical_name=canonical_name,
        repository_url=f"https://{canonical_name}",
        source=source,
        confidence=_source_confidence(source),
    )


def _dedupe_candidates(candidates: list[RepositoryMappingCandidate]) -> list[RepositoryMappingCandidate]:
    deduped: dict[tuple[str, str], RepositoryMappingCandidate] = {}
    for candidate in candidates:
        key = (candidate.mapping.canonical_name, candidate.mapping.source)
        existing = deduped.get(key)
        if existing is None or candidate.priority < existing.priority:
            deduped[key] = candidate
    return list(deduped.values())


def _source_confidence(source: str) -> RepositoryMappingConfidence:
    if source in _HIGH_CONFIDENCE_SOURCES:
        return RepositoryMappingConfidence.HIGH
    return RepositoryMappingConfidence.LOW
