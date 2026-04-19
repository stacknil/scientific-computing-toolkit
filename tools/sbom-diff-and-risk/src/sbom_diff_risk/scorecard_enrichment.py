from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace

from .models import (
    Component,
    ReportEnrichmentMetadata,
    RepositoryMapping,
    ScorecardCheck,
    ScorecardEvidence,
    ScorecardStatus,
)
from .repository_mapping import assess_component_repository_mapping, repository_mapping_cache_key
from .scorecard_client import ScorecardClient, ScorecardClientError, ScorecardProjectResult

DEFAULT_SCORECARD_TIMEOUT_SECONDS = 5.0

_STATUS_ORDER = {
    ScorecardStatus.SCORECARD_AVAILABLE: 0,
    ScorecardStatus.SCORECARD_UNAVAILABLE: 1,
    ScorecardStatus.REPOSITORY_UNMAPPED: 2,
    ScorecardStatus.ENRICHMENT_ERROR: 3,
}


@dataclass(slots=True, frozen=True)
class _ScorecardFetchOutcome:
    status: ScorecardStatus
    result: ScorecardProjectResult | None = None
    note: str | None = None
    error: str | None = None


class ScorecardEnricher:
    def __init__(
        self,
        *,
        client: ScorecardClient | None = None,
        timeout_seconds: float = DEFAULT_SCORECARD_TIMEOUT_SECONDS,
    ) -> None:
        self.client = client or ScorecardClient(timeout_seconds=timeout_seconds)
        self.timeout_seconds = timeout_seconds
        self._component_cache: dict[tuple[str, str, str, tuple[tuple[str, str], ...]], ScorecardEvidence] = {}
        self._repo_cache: dict[str, _ScorecardFetchOutcome] = {}
        self._seen_keys: set[tuple[str, str, str, tuple[tuple[str, str], ...]]] = set()

    def enrich_components(self, components: list[Component]) -> list[Component]:
        enriched: list[Component] = []
        for component in components:
            key = _component_identity(component)
            if key not in self._component_cache:
                self._seen_keys.add(key)
                self._component_cache[key] = self._enrich_component(component)
            enriched.append(replace(component, scorecard=self._component_cache[key]))
        return enriched

    def build_report_metadata(self) -> ReportEnrichmentMetadata:
        if not self._seen_keys:
            return ReportEnrichmentMetadata(
                mode="opt_in_scorecard",
                scorecard_enabled=True,
                scorecard_timeout_seconds=self.timeout_seconds,
                scorecard_network_access_performed=False,
                network_access_performed=False,
                scorecard_candidate_components=0,
                scorecard_supported_components=0,
                scorecard_status_counts={},
            )

        evidences = [self._component_cache[key] for key in sorted(self._seen_keys)]
        counter = Counter(
            status.value
            for evidence in evidences
            for status in evidence.statuses
        )
        scorecard_network_access_performed = any(
            ScorecardStatus.REPOSITORY_UNMAPPED not in evidence.statuses
            for evidence in evidences
        )
        return ReportEnrichmentMetadata(
            mode="opt_in_scorecard",
            scorecard_enabled=True,
            scorecard_timeout_seconds=self.timeout_seconds,
            scorecard_network_access_performed=scorecard_network_access_performed,
            network_access_performed=scorecard_network_access_performed,
            scorecard_candidate_components=len(evidences),
            scorecard_supported_components=sum(
                1 for evidence in evidences if ScorecardStatus.REPOSITORY_UNMAPPED not in evidence.statuses
            ),
            scorecard_status_counts={key: counter[key] for key in sorted(counter)},
        )

    def _enrich_component(self, component: Component) -> ScorecardEvidence:
        mapping_assessment = assess_component_repository_mapping(component)
        mapping = mapping_assessment.mapping
        if mapping is None:
            return ScorecardEvidence(
                provider="openssf-scorecard",
                requested=True,
                repository=None,
                statuses=(ScorecardStatus.REPOSITORY_UNMAPPED,),
                note="No high-confidence source repository mapping was available from explicit component metadata.",
            )

        outcome = self._repo_cache.get(mapping.canonical_name)
        if outcome is None:
            outcome = self._fetch_scorecard(mapping)
            self._repo_cache[mapping.canonical_name] = outcome
        return _scorecard_evidence_from_outcome(mapping, outcome)

    def _fetch_scorecard(self, mapping: RepositoryMapping) -> _ScorecardFetchOutcome:
        try:
            result = self.client.fetch_project(mapping.platform, mapping.owner, mapping.repo)
        except ScorecardClientError as exc:
            if exc.status_code == 404:
                return _ScorecardFetchOutcome(
                    status=ScorecardStatus.SCORECARD_UNAVAILABLE,
                    note="Scorecard data is not available for the mapped repository.",
                )
            return _ScorecardFetchOutcome(
                status=ScorecardStatus.ENRICHMENT_ERROR,
                error=str(exc),
            )

        return _ScorecardFetchOutcome(
            status=ScorecardStatus.SCORECARD_AVAILABLE,
            result=result,
        )


def scorecard_evidence_to_dict(evidence: ScorecardEvidence | None) -> dict[str, object] | None:
    if evidence is None:
        return None
    repository = None
    if evidence.repository is not None:
        repository = {
            "platform": evidence.repository.platform,
            "owner": evidence.repository.owner,
            "repo": evidence.repository.repo,
            "canonical_name": evidence.repository.canonical_name,
            "repository_url": evidence.repository.repository_url,
            "source": evidence.repository.source,
            "confidence": evidence.repository.confidence.value,
        }
    return {
        "provider": evidence.provider,
        "requested": evidence.requested,
        "repository": repository,
        "statuses": [status.value for status in evidence.statuses],
        "score": evidence.score,
        "date": evidence.date,
        "scorecard_version": evidence.scorecard_version,
        "scorecard_commit": evidence.scorecard_commit,
        "repository_commit": evidence.repository_commit,
        "checks": [
            {
                "name": check.name,
                "score": check.score,
                "reason": check.reason,
                "documentation_url": check.documentation_url,
                "documentation_short": check.documentation_short,
            }
            for check in evidence.checks
        ],
        "note": evidence.note,
        "error": evidence.error,
    }


def _scorecard_evidence_from_outcome(
    mapping: RepositoryMapping,
    outcome: _ScorecardFetchOutcome,
) -> ScorecardEvidence:
    if outcome.status is ScorecardStatus.SCORECARD_AVAILABLE:
        assert outcome.result is not None
        return ScorecardEvidence(
            provider="openssf-scorecard",
            requested=True,
            repository=mapping,
            statuses=(ScorecardStatus.SCORECARD_AVAILABLE,),
            score=outcome.result.score,
            date=outcome.result.date,
            scorecard_version=outcome.result.scorecard_version,
            scorecard_commit=outcome.result.scorecard_commit,
            repository_commit=outcome.result.repository_commit,
            checks=tuple(
                sorted(
                    outcome.result.checks,
                    key=lambda item: (item.score, item.name.lower()),
                )
            ),
        )

    return ScorecardEvidence(
        provider="openssf-scorecard",
        requested=True,
        repository=mapping,
        statuses=(outcome.status,),
        checks=(),
        note=outcome.note,
        error=outcome.error,
    )


def _component_identity(component: Component) -> tuple[str, str, str]:
    return repository_mapping_cache_key(component)


def _sorted_statuses(statuses: set[ScorecardStatus]) -> tuple[ScorecardStatus, ...]:
    return tuple(sorted(statuses, key=lambda item: (_STATUS_ORDER[item], item.value)))
