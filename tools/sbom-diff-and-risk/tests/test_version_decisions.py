"""Independent SemVer 2.0.0 grammar oracle; no production parser is reused.

https://semver.org/spec/v2.0.0.html, rules 2, 9, 10 and the BNF.
The existing tool extensions are outer whitespace and one lowercase ``v``.
Only major numbers are compared; this is not ecosystem version precedence.
"""

from __future__ import annotations

from dataclasses import asdict
from string import ascii_letters, digits

import pytest
from sbom_diff_risk.diffing import diff_components
from sbom_diff_risk.models import Component
from sbom_diff_risk.risk import evaluate_risks


def reference_major(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip().removeprefix("v")
    core_and_pre, plus, build = value.partition("+")
    core, dash, pre = core_and_pre.partition("-")
    numbers = core.split(".")
    if len(numbers) != 3 or any(not numeric_id(part) for part in numbers):
        return None
    for present, suffix, numeric_zero_rule in ((dash, pre, True), (plus, build, False)):
        if not present:
            continue
        for part in suffix.split("."):
            if not part or any(c not in ascii_letters + digits + "-" for c in part):
                return None
            if numeric_zero_rule and all(c in digits for c in part) and not numeric_id(part):
                return None
    return numbers[0]


def numeric_id(value: str) -> bool:
    return bool(value) and all(c in digits for c in value) and (value == "0" or value[0] != "0")


def expected_bucket(before: str | None, after: str | None) -> str | None:
    before, after = (value.strip() or None if value is not None else None for value in (before, after))
    if not before or not after or before == after:
        return None
    left, right = reference_major(before), reference_major(after)
    if left is not None and right is not None and (len(right), right) > (len(left), left):
        return "major_upgrade"
    return "version_change_unclassified"


SYNTAX_CASES = [
    ("zero", "0.0.0", True),
    ("plain", "1.2.3", True),
    ("major", "2.0.0", True),
    ("prefix", "v2.0.0", True),
    ("outer-space", " \t2.0.0\n", True),
    ("major-zero", "02.0.0", False),
    ("minor-zero", "2.01.0", False),
    ("patch-zero", "2.0.01", False),
    ("missing", "2.0", False),
    ("extra-core", "2.0.0.0", False),
    ("inner-space", "2. 0.0", False),
    ("unicode-digit", "2.0.1\u0662", False),
    ("uppercase-prefix", "V2.0.0", False),
    ("pre", "2.0.0-alpha.1", True),
    ("pre-zero", "2.0.0-0", True),
    ("pre-leading-zero", "2.0.0-01", False),
    ("pre-alphanumeric", "2.0.0-01a", True),
    ("pre-hyphens", "2.0.0-x-y.--", True),
    ("empty-pre", "2.0.0-", False),
    ("pre-empty-id", "2.0.0-alpha..1", False),
    ("pre-trailing-dot", "2.0.0-alpha.", False),
    ("pre-leading-dot", "2.0.0-.alpha", False),
    ("pre-underscore", "2.0.0-alpha_1", False),
    ("build", "2.0.0+build.01", True),
    ("both", "2.0.0-rc.1+build.01", True),
    ("empty-build", "2.0.0+", False),
    ("build-empty-id", "2.0.0+a..b", False),
    ("build-trailing-dot", "2.0.0+a.", False),
    ("build-leading-dot", "2.0.0+.a", False),
    ("double-plus", "2.0.0+a+b", False),
    ("build-underscore", "2.0.0+a_b", False),
    ("pep440", "2.0rc1", False),
    ("maven", "2.0-SNAPSHOT", False),
    ("nuget-four-part", "2.0.0.1", False),
    ("opaque", "release-b", False),
    ("huge-major", "9" * 5000 + ".0.0", True),
    ("huge-minor", "2." + "9" * 5000 + ".0", True),
    ("huge-patch", "2.0." + "9" * 5000, True),
]


@pytest.mark.parametrize("label,version,eligible", SYNTAX_CASES, ids=[row[0] for row in SYNTAX_CASES])
def test_oracle_grammar_anchors(label: str, version: str, eligible: bool) -> None:
    assert (reference_major(version) is not None) is eligible


@pytest.mark.parametrize("label,version,eligible", SYNTAX_CASES, ids=[row[0] for row in SYNTAX_CASES])
@pytest.mark.parametrize("reverse", [False, True])
def test_version_risk_matches_independent_grammar(label, version, eligible, reverse) -> None:
    before, after = (version, "9.0.0") if reverse else ("0.0.0", version)
    assert_transition(before, after, "explicit", "pypi")


TRANSITIONS = [
    ("equal", "1.2.3", "1.2.3"),
    ("major-up", "1.2.3", "2.0.0"),
    ("major-down", "2.0.0", "1.2.3"),
    ("minor", "1.2.3", "1.3.0"),
    ("patch", "1.2.3", "1.2.4"),
    ("pre-final", "2.0.0-rc.1", "2.0.0"),
    ("final-pre", "2.0.0", "2.0.0-rc.1"),
    ("build-only", "2.0.0+a", "2.0.0+b"),
    ("both-unknown", None, None),
    ("lose-evidence", "1.2.3", None),
    ("gain-evidence", None, "2.0.0"),
    ("opaque", "release-a", "release-b"),
    ("lose-semver", "1.2.3", "release-b"),
    ("gain-semver", "release-a", "2.0.0"),
    ("valid-suffix", "1.2.3-rc.1+a", "2.0.0-rc.2+b"),
    ("invalid-suffix", "1.2.3", "2.0.0-01"),
    ("prefix-only", "1.2.3", "v1.2.3"),
    ("trim-only", " 1.2.3 ", "1.2.3"),
    ("decimal-boundary", "9.9.9", "10.0.0"),
]


@pytest.mark.parametrize("label,before,after", TRANSITIONS, ids=[row[0] for row in TRANSITIONS])
@pytest.mark.parametrize("source", ["explicit", "purl", "both"])
def test_transition_families(label, before, after, source) -> None:
    assert_transition(before, after, source, "pypi")


@pytest.mark.parametrize("ecosystem", ["pypi", "npm", "maven", "nuget", "generic", "custom"])
@pytest.mark.parametrize("before,after", [("1.2.3", "2.0.0-rc.1+build"), ("2.0.0", "1.2.3")])
def test_ecosystem_does_not_imply_version_precedence(ecosystem, before, after) -> None:
    assert_transition(before, after, "both", ecosystem)


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:pypi/sample_lib@2.0.0-rc.1%2Bbuild.01",
        "pkg:pypi/sample-lib@2.0.0-rc.1+build.01?os=linux&arch=any",
    ],
)
def test_equivalent_purl_representation_preserves_version_evidence(purl) -> None:
    before = Component("sample-lib", None, "pypi", purl="pkg:pypi/sample-lib@1.2.3")
    after = Component("sample-lib", None, "pypi", purl=purl)
    added, removed, changed = diff_components([before], [after])
    findings = evaluate_risks(added, changed)
    assert added == removed == []
    assert changed[0].key == "purl:pkg:pypi/sample-lib"
    assert [f.bucket.value for f in findings if f.bucket.value == "major_upgrade"] == ["major_upgrade"]
    assert after.purl == purl and after.version is None


def assert_transition(before_version, after_version, source, ecosystem) -> None:
    components = []
    for version in (before_version, after_version):
        purl = f"pkg:{ecosystem}/sample-lib"
        if source != "explicit" and version and version.strip():
            purl += "@" + version.strip()
        components.append(
            Component("sample-lib", None if source == "purl" else version, ecosystem, purl=purl, license_id="MIT")
        )
    original = [asdict(item) for item in components]
    added, removed, changed = diff_components(components[:1], components[1:])
    findings = evaluate_risks(added, changed)
    assert added == removed == []
    assert [asdict(item) for item in components] == original
    expected = expected_bucket(before_version, after_version)
    actual = [f.bucket.value for f in findings if f.bucket.value in {"major_upgrade", "version_change_unclassified"}]
    assert actual == ([] if expected is None else [expected])
    if changed:
        left, right = (v.strip() or None if v is not None else None for v in (before_version, after_version))
        assert changed[0].key == f"purl:pkg:{ecosystem}/sample-lib"
        assert changed[0].classification == ("version_changed" if left != right else "metadata_changed")
