from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .policy_models import PolicyEvaluation


class RiskBucket(StrEnum):
    NEW_PACKAGE = "new_package"
    MAJOR_UPGRADE = "major_upgrade"
    VERSION_CHANGE_UNCLASSIFIED = "version_change_unclassified"
    UNKNOWN_LICENSE = "unknown_license"
    STALE_PACKAGE = "stale_package"
    SUSPICIOUS_SOURCE = "suspicious_source"
    NOT_EVALUATED = "not_evaluated"


class ProvenanceStatus(StrEnum):
    PROVENANCE_AVAILABLE = "provenance_available"
    ATTESTATION_AVAILABLE = "attestation_available"
    ATTESTATION_UNAVAILABLE = "attestation_unavailable"
    ENRICHMENT_ERROR = "enrichment_error"
    UNSUPPORTED_FOR_PACKAGE = "unsupported_for_package"


class RepositoryMappingConfidence(StrEnum):
    HIGH = "high"
    LOW = "low"


@dataclass(slots=True, frozen=True)
class RepositoryMapping:
    platform: str
    owner: str
    repo: str
    canonical_name: str
    repository_url: str
    source: str
    confidence: RepositoryMappingConfidence = RepositoryMappingConfidence.HIGH


class ScorecardStatus(StrEnum):
    SCORECARD_AVAILABLE = "scorecard_available"
    SCORECARD_UNAVAILABLE = "scorecard_unavailable"
    REPOSITORY_UNMAPPED = "repository_unmapped"
    ENRICHMENT_ERROR = "enrichment_error"


@dataclass(slots=True, frozen=True)
class ProvenanceFileEvidence:
    filename: str
    url: str | None = None
    sha256: str | None = None
    upload_time: str | None = None
    yanked: bool | None = None
    statuses: tuple[ProvenanceStatus, ...] = ()
    attestation_count: int = 0
    predicate_types: tuple[str, ...] = ()
    publisher_kinds: tuple[str, ...] = ()
    error: str | None = None


@dataclass(slots=True, frozen=True)
class ProvenanceEvidence:
    provider: str
    requested: bool
    supported: bool = False
    lookup_performed: bool = False
    package_name: str | None = None
    package_version: str | None = None
    release_url: str | None = None
    statuses: tuple[ProvenanceStatus, ...] = ()
    files: tuple[ProvenanceFileEvidence, ...] = ()
    files_evaluated: int = 0
    files_with_attestations: int = 0
    files_without_attestations: int = 0
    error: str | None = None


@dataclass(slots=True, frozen=True)
class ScorecardCheck:
    name: str
    score: int
    reason: str | None = None
    documentation_url: str | None = None
    documentation_short: str | None = None


@dataclass(slots=True, frozen=True)
class ScorecardEvidence:
    provider: str
    requested: bool
    repository: RepositoryMapping | None = None
    statuses: tuple[ScorecardStatus, ...] = ()
    score: float | None = None
    date: str | None = None
    scorecard_version: str | None = None
    scorecard_commit: str | None = None
    repository_commit: str | None = None
    checks: tuple[ScorecardCheck, ...] = ()
    note: str | None = None
    error: str | None = None


@dataclass(slots=True)
class ReportEnrichmentMetadata:
    mode: str = "offline_default"
    pypi_enabled: bool = False
    pypi_timeout_seconds: float | None = None
    pypi_network_access_performed: bool = False
    network_access_performed: bool = False
    candidate_components: int = 0
    supported_components: int = 0
    status_counts: dict[str, int] = field(default_factory=dict)
    scorecard_enabled: bool = False
    scorecard_timeout_seconds: float | None = None
    scorecard_network_access_performed: bool = False
    scorecard_candidate_components: int = 0
    scorecard_supported_components: int = 0
    scorecard_status_counts: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class Component:
    name: str
    version: str | None
    ecosystem: str
    purl: str | None = None
    license_id: str | None = None
    supplier: str | None = None
    source_url: str | None = None
    bom_ref: str | None = None
    raw_type: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    provenance: ProvenanceEvidence | None = None
    scorecard: ScorecardEvidence | None = None


@dataclass(slots=True)
class ComponentChange:
    key: str
    before: Component
    after: Component
    classification: str = "changed"


@dataclass(slots=True)
class RiskFinding:
    bucket: RiskBucket
    component_key: str
    component: Component
    rationale: str


@dataclass(slots=True)
class ReportSummary:
    added: int = 0
    removed: int = 0
    changed: int = 0
    risk_counts: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class ReportComponents:
    added: list[Component] = field(default_factory=list)
    removed: list[Component] = field(default_factory=list)
    changed: list[ComponentChange] = field(default_factory=list)


@dataclass(slots=True)
class ReportMetadata:
    before_format: str
    after_format: str
    generated_at: str | None = None
    strict: bool = False
    stub: bool = True
    policy_evaluation: PolicyEvaluation | None = None
    enrichment: ReportEnrichmentMetadata = field(default_factory=ReportEnrichmentMetadata)


@dataclass(slots=True)
class CompareReport:
    summary: ReportSummary
    components: ReportComponents
    risks: list[RiskFinding]
    metadata: ReportMetadata
    notes: list[str] = field(default_factory=list)
