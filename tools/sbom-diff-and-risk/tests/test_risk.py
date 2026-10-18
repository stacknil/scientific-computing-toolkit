from __future__ import annotations

import pytest
from sbom_diff_risk.diffing import component_key, diff_components
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


@pytest.mark.parametrize("identity_source", ["purl-only", "explicit-and-purl", "versionless-purl", "opaque"])
@pytest.mark.parametrize(
    ("before_version", "after_version", "expected_bucket"),
    [
        ("1.2.3", "2.0.0", RiskBucket.MAJOR_UPGRADE),
        ("release-a", "release-b", RiskBucket.VERSION_CHANGE_UNCLASSIFIED),
        ("1.2", "2.0", RiskBucket.VERSION_CHANGE_UNCLASSIFIED),
        ("1.2.3", "1.3.0", RiskBucket.VERSION_CHANGE_UNCLASSIFIED),
        ("2.0.0", "1.2.3", RiskBucket.VERSION_CHANGE_UNCLASSIFIED),
    ],
)
def test_version_risks_follow_canonical_evidence(
    identity_source: str,
    before_version: str,
    after_version: str,
    expected_bucket: RiskBucket,
) -> None:
    components = []
    for version in (before_version, after_version):
        purl = None if identity_source == "opaque" else "pkg:pypi/sample-lib"
        if identity_source in {"purl-only", "explicit-and-purl"}:
            purl = f"{purl}@{version}"
        components.append(
            Component(
                name="sample-lib",
                version=None if identity_source == "purl-only" else version,
                ecosystem="pypi",
                purl=purl,
                bom_ref="Component-A",
                license_id="MIT",
            )
        )
    before, after = components
    added, removed, changed = diff_components([before], [after])

    findings = evaluate_risks(added, changed)

    assert added == removed == []
    assert changed[0].classification == "version_changed"
    version_findings = [
        finding
        for finding in findings
        if finding.bucket
        in {
            RiskBucket.MAJOR_UPGRADE,
            RiskBucket.VERSION_CHANGE_UNCLASSIFIED,
        }
    ]
    assert [finding.bucket for finding in version_findings] == [expected_bucket]
    assert version_findings[0].component is after
    if identity_source == "purl-only":
        assert before.version is after.version is None
    if expected_bucket is RiskBucket.MAJOR_UPGRADE:
        assert f"from {before_version} to {after_version}" in version_findings[0].rationale


@pytest.mark.parametrize(
    ("before_version", "after_version", "purl", "classification"),
    [
        (None, None, "pkg:pypi/sample-lib", "metadata_changed"),
        (None, "2.0.0", "pkg:pypi/sample-lib", "version_changed"),
        ("1.2.3", None, "pkg:pypi/sample-lib", "version_changed"),
        ("1.2.3", "1.2.3", "pkg:pypi/sample-lib@1.2.3", "metadata_changed"),
        (" 1.2.3 ", "1.2.3", "pkg:pypi/sample-lib@1.2.3", "metadata_changed"),
        (None, None, None, "metadata_changed"),
    ],
)
def test_unknown_or_equal_canonical_versions_do_not_invent_version_risks(
    before_version: str | None,
    after_version: str | None,
    purl: str | None,
    classification: str,
) -> None:
    before = Component(
        "sample-lib", before_version, "pypi", purl=purl, bom_ref="pkg:pypi/sample-lib@1.2.3", supplier="Supplier A"
    )
    after = Component("sample-lib", after_version, "pypi", purl=purl, bom_ref=before.bom_ref, supplier="Supplier B")
    added, removed, changed = diff_components([before], [after])

    findings = evaluate_risks(added, changed)

    assert added == removed == []
    assert changed[0].classification == classification
    assert _bucket_count(findings, RiskBucket.MAJOR_UPGRADE) == 0
    assert _bucket_count(findings, RiskBucket.VERSION_CHANGE_UNCLASSIFIED) == 0


@pytest.mark.parametrize(
    ("before_version", "after_version", "expected_bucket"),
    [("Release-A", "release-a", RiskBucket.VERSION_CHANGE_UNCLASSIFIED), ("1.2.3", "2.0.0", RiskBucket.MAJOR_UPGRADE)],
)
def test_unknown_ecosystem_uses_only_the_existing_syntactic_version_heuristic(
    before_version: str,
    after_version: str,
    expected_bucket: RiskBucket,
) -> None:
    before = Component("CaseSensitiveLib", None, "custom", purl=f"pkg:custom/CaseSensitiveLib@{before_version}")
    after = Component("CaseSensitiveLib", None, "custom", purl=f"pkg:custom/CaseSensitiveLib@{after_version}")
    added, removed, changed = diff_components([before], [after])

    findings = evaluate_risks(added, changed)

    assert added == removed == []
    assert changed[0].key == "purl:pkg:custom/CaseSensitiveLib"
    assert _bucket_count(findings, expected_bucket) == 1


def test_purl_only_version_findings_are_independent_of_input_order() -> None:
    changes = [_change("zulu", "1.2.3", "2.0.0"), _change("alpha", "1.2.3", "2.0.0")]
    for change in changes:
        change.before.version = change.after.version = None

    findings = evaluate_risks([], changes)

    assert findings == evaluate_risks([], reversed(changes))
    assert [finding.component.name for finding in findings if finding.bucket is RiskBucket.MAJOR_UPGRADE] == [
        "alpha",
        "zulu",
    ]


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
