from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RiskBucket(StrEnum):
    NEW_PACKAGE = "new_package"
    MAJOR_UPGRADE = "major_upgrade"
    VERSION_CHANGE_UNCLASSIFIED = "version_change_unclassified"
    UNKNOWN_LICENSE = "unknown_license"
    STALE_PACKAGE = "stale_package"
    SUSPICIOUS_SOURCE = "suspicious_source"
    NOT_EVALUATED = "not_evaluated"


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


@dataclass(slots=True)
class CompareReport:
    summary: ReportSummary
    components: ReportComponents
    risks: list[RiskFinding]
    metadata: ReportMetadata
    notes: list[str] = field(default_factory=list)
