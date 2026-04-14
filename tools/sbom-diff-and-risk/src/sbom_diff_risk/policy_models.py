from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class PolicyLevel(StrEnum):
    BLOCK = "block"
    WARN = "warn"


SUPPORTED_POLICY_RULE_IDS = (
    "new_package",
    "major_upgrade",
    "version_change_unclassified",
    "unknown_license",
    "suspicious_source",
    "stale_package",
    "max_added_packages",
    "allow_sources",
)


@dataclass(slots=True, frozen=True)
class PolicyConfig:
    version: int
    block_on: tuple[str, ...] = ()
    warn_on: tuple[str, ...] = ()
    max_added_packages: int | None = None
    allow_sources: tuple[str, ...] = ()
    ignore_rules: tuple[str, ...] = ()


@dataclass(slots=True)
class PolicyViolation:
    rule_id: str
    level: PolicyLevel
    message: str
    component_key: str | None = None
    component_name: str | None = None
    finding_bucket: str | None = None


@dataclass(slots=True)
class PolicyEvaluation:
    applied: bool
    policy_path: str | None = None
    effective_policy: PolicyConfig | None = None
    blocking_violations: list[PolicyViolation] = field(default_factory=list)
    warning_violations: list[PolicyViolation] = field(default_factory=list)
    ignored_checks: int = 0
    exit_code: int = 0
