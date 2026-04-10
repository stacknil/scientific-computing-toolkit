from __future__ import annotations

from sbom_diff_risk.diffing import component_key
from sbom_diff_risk.models import Component, ComponentChange, RiskBucket
from sbom_diff_risk.risk import evaluate_risks, summarize_risks


def test_empty_risk_evaluation_is_stable() -> None:
    findings = evaluate_risks([], [], allowlist=["pypi.org"])
    assert findings == []
    counts = summarize_risks(findings)
    assert counts["new_package"] == 0
    assert counts["major_upgrade"] == 0
    assert counts["suspicious_source"] == 0


def test_new_package_rule_marks_added_component() -> None:
    component = _component("urllib3", "2.2.1", purl="pkg:pypi/urllib3@2.2.1", license_id="MIT")

    findings = evaluate_risks([component], [], allowlist=["pypi.org"])

    assert _bucket_count(findings, RiskBucket.NEW_PACKAGE) == 1
    assert any(finding.component.name == "urllib3" for finding in findings if finding.bucket is RiskBucket.NEW_PACKAGE)


def test_major_upgrade_requires_reliable_semver() -> None:
    change = _change("requests", "1.2.3", "2.0.0")

    findings = evaluate_risks([], [change], allowlist=["pypi.org"])

    assert _bucket_count(findings, RiskBucket.MAJOR_UPGRADE) == 1
    assert _bucket_count(findings, RiskBucket.VERSION_CHANGE_UNCLASSIFIED) == 0


def test_version_change_is_unclassified_when_semver_is_not_reliable() -> None:
    change = _change("requests", "1.2", "2.0")

    findings = evaluate_risks([], [change], allowlist=["pypi.org"])

    assert _bucket_count(findings, RiskBucket.MAJOR_UPGRADE) == 0
    assert _bucket_count(findings, RiskBucket.VERSION_CHANGE_UNCLASSIFIED) == 1


def test_unknown_license_rule_marks_missing_license() -> None:
    component = _component("urllib3", "2.2.1", purl="pkg:pypi/urllib3@2.2.1", license_id=None)

    findings = evaluate_risks([component], [], allowlist=["pypi.org"])

    assert _bucket_count(findings, RiskBucket.UNKNOWN_LICENSE) == 1


def test_suspicious_source_rule_marks_http_source() -> None:
    component = _component(
        "internal-lib",
        "1.0.0",
        purl="pkg:pypi/internal-lib@1.0.0",
        license_id="MIT",
        source_url="http://example.com/internal-lib-1.0.0.tar.gz",
    )

    findings = evaluate_risks([component], [], allowlist=["pypi.org", "example.com"])

    assert _bucket_count(findings, RiskBucket.SUSPICIOUS_SOURCE) == 1


def test_suspicious_source_rule_marks_missing_purl_and_source() -> None:
    component = _component("mystery-lib", "1.0.0", purl=None, license_id="MIT", source_url=None)

    findings = evaluate_risks([component], [], allowlist=["pypi.org"])

    assert _bucket_count(findings, RiskBucket.SUSPICIOUS_SOURCE) == 1


def test_suspicious_source_rule_skips_allowlisted_https_source() -> None:
    component = _component(
        "requests",
        "2.31.0",
        purl="pkg:pypi/requests@2.31.0",
        license_id="Apache-2.0",
        source_url="https://pypi.org/project/requests/",
    )

    findings = evaluate_risks([component], [], allowlist=["pypi.org"])

    assert _bucket_count(findings, RiskBucket.SUSPICIOUS_SOURCE) == 0


def test_stale_package_defaults_to_not_evaluated() -> None:
    component = _component("requests", "2.31.0", purl="pkg:pypi/requests@2.31.0", license_id="Apache-2.0")

    findings = evaluate_risks([component], [], allowlist=["pypi.org"])

    assert _bucket_count(findings, RiskBucket.NOT_EVALUATED) == 1
    stale_note = next(finding for finding in findings if finding.bucket is RiskBucket.NOT_EVALUATED)
    assert "stale_package was not evaluated" in stale_note.rationale


def test_stale_package_not_evaluated_is_suppressed_when_enrichment_flag_is_set() -> None:
    component = _component("requests", "2.31.0", purl="pkg:pypi/requests@2.31.0", license_id="Apache-2.0")

    findings = evaluate_risks([component], [], allowlist=["pypi.org"], stale_enrichment_enabled=True)

    assert _bucket_count(findings, RiskBucket.NOT_EVALUATED) == 0


def _component(
    name: str,
    version: str | None,
    *,
    purl: str | None,
    license_id: str | None,
    source_url: str | None = None,
) -> Component:
    return Component(
        name=name,
        version=version,
        ecosystem="pypi",
        purl=purl,
        license_id=license_id,
        source_url=source_url,
    )


def _change(name: str, before_version: str | None, after_version: str | None) -> ComponentChange:
    before = _component(name, before_version, purl=f"pkg:pypi/{name}@{before_version}", license_id="Apache-2.0")
    after = _component(name, after_version, purl=f"pkg:pypi/{name}@{after_version}", license_id="Apache-2.0")
    return ComponentChange(
        key=component_key(after),
        before=before,
        after=after,
        classification="version_changed",
    )


def _bucket_count(findings: list, bucket: RiskBucket) -> int:
    return sum(1 for finding in findings if finding.bucket is bucket)
