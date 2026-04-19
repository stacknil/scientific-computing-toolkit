from __future__ import annotations

from sbom_diff_risk.models import Component, ScorecardCheck, ScorecardStatus
from sbom_diff_risk.scorecard_client import ScorecardClientError, ScorecardProjectResult
from sbom_diff_risk.scorecard_enrichment import ScorecardEnricher


def test_scorecard_enricher_records_available_scorecard_for_mapped_repository() -> None:
    client = FakeScorecardClient(
        responses={
            ("github.com", "psf", "requests"): ScorecardProjectResult(
                canonical_name="github.com/psf/requests",
                score=7.8,
                date="2026-04-10T00:00:00Z",
                scorecard_version="5.0.0",
                scorecard_commit="def456",
                repository_commit="abc123",
                checks=(
                    ScorecardCheck(name="Maintained", score=10, reason="Project is active."),
                    ScorecardCheck(name="Branch-Protection", score=6, reason="Not all protections are enabled."),
                ),
            )
        }
    )
    enricher = ScorecardEnricher(client=client, timeout_seconds=2.5)

    [component] = enricher.enrich_components(
        [Component(name="requests", version="2.32.0", ecosystem="pypi", source_url="https://github.com/psf/requests")]
    )
    metadata = enricher.build_report_metadata()

    assert component.scorecard is not None
    assert component.scorecard.statuses == (ScorecardStatus.SCORECARD_AVAILABLE,)
    assert component.scorecard.repository is not None
    assert component.scorecard.repository.canonical_name == "github.com/psf/requests"
    assert component.scorecard.score == 7.8
    assert client.calls == [("github.com", "psf", "requests")]
    assert metadata.mode == "opt_in_scorecard"
    assert metadata.scorecard_enabled is True
    assert metadata.scorecard_network_access_performed is True
    assert metadata.scorecard_status_counts == {"scorecard_available": 1}


def test_scorecard_enricher_marks_repository_unmapped_without_network_access() -> None:
    client = FakeScorecardClient()
    enricher = ScorecardEnricher(client=client)

    [component] = enricher.enrich_components(
        [Component(name="urllib3", version="2.2.1", ecosystem="pypi", source_url="https://pypi.org/project/urllib3/2.2.1/")]
    )
    metadata = enricher.build_report_metadata()

    assert component.scorecard is not None
    assert component.scorecard.statuses == (ScorecardStatus.REPOSITORY_UNMAPPED,)
    assert client.calls == []
    assert metadata.scorecard_network_access_performed is False
    assert metadata.scorecard_supported_components == 0
    assert metadata.scorecard_status_counts == {"repository_unmapped": 1}


def test_scorecard_enricher_skips_low_confidence_repository_hints_without_network_access() -> None:
    client = FakeScorecardClient()
    enricher = ScorecardEnricher(client=client)

    [component] = enricher.enrich_components(
        [
            Component(
                name="requests",
                version="2.32.0",
                ecosystem="pypi",
                source_url="https://github.com/psf/requests",
                evidence={
                    "source_format": "cyclonedx-json",
                    "component": {
                        "externalReferences": [
                            {"type": "website", "url": "https://github.com/psf/requests"},
                        ]
                    },
                },
            )
        ]
    )
    metadata = enricher.build_report_metadata()

    assert component.scorecard is not None
    assert component.scorecard.statuses == (ScorecardStatus.REPOSITORY_UNMAPPED,)
    assert client.calls == []
    assert metadata.scorecard_network_access_performed is False
    assert metadata.scorecard_status_counts == {"repository_unmapped": 1}


def test_scorecard_enricher_marks_scorecard_unavailable_for_404() -> None:
    client = FakeScorecardClient(
        errors={
            ("github.com", "psf", "requests"): ScorecardClientError(
                "Scorecard request failed with HTTP 404 for https://api.securityscorecards.dev/projects/github.com/psf/requests.",
                status_code=404,
            )
        }
    )
    enricher = ScorecardEnricher(client=client)

    [component] = enricher.enrich_components(
        [Component(name="requests", version="2.32.0", ecosystem="pypi", source_url="https://github.com/psf/requests")]
    )

    assert component.scorecard is not None
    assert component.scorecard.statuses == (ScorecardStatus.SCORECARD_UNAVAILABLE,)
    assert component.scorecard.note == "Scorecard data is not available for the mapped repository."


def test_scorecard_enricher_captures_timeout_as_enrichment_error() -> None:
    client = FakeScorecardClient(
        errors={
            ("github.com", "psf", "requests"): ScorecardClientError(
                "Scorecard request timed out after 2.5 seconds for https://api.securityscorecards.dev/projects/github.com/psf/requests.",
                is_timeout=True,
            )
        }
    )
    enricher = ScorecardEnricher(client=client, timeout_seconds=2.5)

    [component] = enricher.enrich_components(
        [Component(name="requests", version="2.32.0", ecosystem="pypi", source_url="https://github.com/psf/requests")]
    )
    metadata = enricher.build_report_metadata()

    assert component.scorecard is not None
    assert component.scorecard.statuses == (ScorecardStatus.ENRICHMENT_ERROR,)
    assert "timed out" in (component.scorecard.error or "")
    assert metadata.scorecard_network_access_performed is True
    assert metadata.scorecard_status_counts == {"enrichment_error": 1}


def test_scorecard_enricher_re_evaluates_same_package_identity_when_repository_hints_differ() -> None:
    client = FakeScorecardClient(
        responses={
            ("github.com", "psf", "requests"): ScorecardProjectResult(
                canonical_name="github.com/psf/requests",
                score=7.8,
                date="2026-04-10T00:00:00Z",
                scorecard_version="5.0.0",
                scorecard_commit="def456",
                repository_commit="abc123",
                checks=(ScorecardCheck(name="Maintained", score=10, reason="Project is active."),),
            )
        }
    )
    enricher = ScorecardEnricher(client=client)

    weak_component = Component(
        name="requests",
        version="2.32.0",
        ecosystem="pypi",
        source_url="https://github.com/psf/requests",
        evidence={
            "source_format": "cyclonedx-json",
            "component": {
                "externalReferences": [
                    {"type": "website", "url": "https://github.com/psf/requests"},
                ]
            },
        },
    )
    strong_component = Component(
        name="requests",
        version="2.32.0",
        ecosystem="pypi",
        source_url="https://github.com/psf/requests",
    )

    weak_enriched, strong_enriched = enricher.enrich_components([weak_component, strong_component])

    assert weak_enriched.scorecard is not None
    assert weak_enriched.scorecard.statuses == (ScorecardStatus.REPOSITORY_UNMAPPED,)
    assert strong_enriched.scorecard is not None
    assert strong_enriched.scorecard.statuses == (ScorecardStatus.SCORECARD_AVAILABLE,)
    assert client.calls == [("github.com", "psf", "requests")]


class FakeScorecardClient:
    def __init__(
        self,
        *,
        responses: dict[tuple[str, str, str], ScorecardProjectResult] | None = None,
        errors: dict[tuple[str, str, str], Exception] | None = None,
    ) -> None:
        self._responses = responses or {}
        self._errors = errors or {}
        self.calls: list[tuple[str, str, str]] = []

    def fetch_project(self, platform: str, owner: str, repo: str) -> ScorecardProjectResult:
        key = (platform, owner, repo)
        self.calls.append(key)
        if key in self._errors:
            raise self._errors[key]
        return self._responses[key]
