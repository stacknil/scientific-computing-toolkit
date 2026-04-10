from __future__ import annotations

import re
from collections import Counter
from ipaddress import ip_address
from typing import Iterable, Sequence
from urllib.parse import urlparse

from .diffing import component_key
from .models import Component, ComponentChange, RiskBucket, RiskFinding

_UNKNOWN_LICENSES = {"", "unknown", "noassertion"}
_SEMVER_RE = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)"
    r"\.(?P<minor>0|[1-9]\d*)"
    r"\.(?P<patch>0|[1-9]\d*)"
    r"(?:[-+][0-9A-Za-z.-]+)?$"
)


def summarize_risks(findings: Iterable[RiskFinding]) -> dict[str, int]:
    counts = Counter(finding.bucket.value for finding in findings)
    return {bucket.value: counts.get(bucket.value, 0) for bucket in RiskBucket}


def evaluate_risks(
    added: Iterable[Component],
    changed: Iterable[ComponentChange],
    allowlist: Sequence[str] | None = None,
    *,
    stale_enrichment_enabled: bool = False,
) -> list[RiskFinding]:
    normalized_allowlist = {entry.strip().lower() for entry in (allowlist or ()) if entry.strip()}
    findings: list[RiskFinding] = []

    for component in added:
        findings.append(
            RiskFinding(
                bucket=RiskBucket.NEW_PACKAGE,
                component_key=component_key(component),
                component=component,
                rationale="Component was not present in the before input.",
            )
        )
        findings.extend(_component_hygiene_findings(component, normalized_allowlist))
        findings.extend(_stale_package_findings(component, stale_enrichment_enabled))

    for change in changed:
        findings.extend(_version_change_findings(change))
        findings.extend(_component_hygiene_findings(change.after, normalized_allowlist))
        findings.extend(_stale_package_findings(change.after, stale_enrichment_enabled))

    findings.sort(key=lambda finding: (finding.bucket.value, finding.component_key, finding.component.name.lower()))
    return findings


def _version_change_findings(change: ComponentChange) -> list[RiskFinding]:
    if change.before.version == change.after.version:
        return []

    semver_delta = _semver_major_delta(change.before.version, change.after.version)
    if semver_delta is not None and semver_delta > 0:
        return [
            RiskFinding(
                bucket=RiskBucket.MAJOR_UPGRADE,
                component_key=change.key,
                component=change.after,
                rationale=(
                    f"Version changed from {change.before.version or 'unknown'} "
                    f"to {change.after.version or 'unknown'} with a higher major version."
                ),
            )
        ]

    if change.before.version and change.after.version:
        return [
            RiskFinding(
                bucket=RiskBucket.VERSION_CHANGE_UNCLASSIFIED,
                component_key=change.key,
                component=change.after,
                rationale="Version changed but did not qualify as a parseable SemVer major upgrade.",
            )
        ]

    return []


def _component_hygiene_findings(
    component: Component,
    allowlist: set[str],
) -> list[RiskFinding]:
    findings: list[RiskFinding] = []

    if _is_unknown_license(component.license_id):
        findings.append(
            RiskFinding(
                bucket=RiskBucket.UNKNOWN_LICENSE,
                component_key=component_key(component),
                component=component,
                rationale="License is missing, empty, UNKNOWN, or NOASSERTION.",
            )
        )

    if _is_suspicious_source(component, allowlist):
        findings.append(
            RiskFinding(
                bucket=RiskBucket.SUSPICIOUS_SOURCE,
                component_key=component_key(component),
                component=component,
                rationale="Source provenance is missing or uses a suspicious location or scheme.",
            )
        )

    return findings


def _is_unknown_license(license_id: str | None) -> bool:
    if license_id is None:
        return True
    return license_id.strip().lower() in _UNKNOWN_LICENSES


def _semver_major_delta(before: str | None, after: str | None) -> int | None:
    before_major = _semver_major(before)
    after_major = _semver_major(after)
    if before_major is None or after_major is None:
        return None
    return after_major - before_major


def _semver_major(version: str | None) -> int | None:
    if not version:
        return None
    match = _SEMVER_RE.match(version.strip())
    if not match:
        return None
    return int(match.group("major"))


def _is_suspicious_source(component: Component, allowlist: set[str]) -> bool:
    source_url = (component.source_url or "").strip()
    if not component.purl and not source_url:
        return True
    if not source_url:
        return False

    lowered = source_url.lower()
    if lowered.startswith("http://"):
        return True
    if lowered.startswith("git+") or lowered.startswith("file://"):
        return True
    if lowered.startswith("git://") or lowered.startswith("ssh://"):
        return True
    if lowered.startswith(".") or lowered.startswith("/") or re.match(r"^[a-zA-Z]:\\", source_url):
        return True

    parsed = urlparse(source_url)
    host = (parsed.hostname or "").lower()
    if not host:
        return True
    if _is_ip_address(host):
        return True
    if host in {"localhost", "localdomain"} or host.endswith(".local"):
        return True
    if allowlist and host not in allowlist and "." not in host:
        return True

    return False


def _stale_package_findings(component: Component, stale_enrichment_enabled: bool) -> list[RiskFinding]:
    if stale_enrichment_enabled:
        return []

    return [
        RiskFinding(
            bucket=RiskBucket.NOT_EVALUATED,
            component_key=component_key(component),
            component=component,
            rationale="stale_package was not evaluated because enrichment mode is disabled.",
        )
    ]


def _is_ip_address(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True
