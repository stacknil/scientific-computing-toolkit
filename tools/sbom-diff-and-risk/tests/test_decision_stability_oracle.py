"""Hand-authored qualification expectations. This module imports no product code.

Rows are preregistered microcases, not a second general policy implementation.
The small assertion protocol is also used by deliberately corrupted observations.
"""

from dataclasses import dataclass


KEY = "purl:pkg:pypi/qualification-alpha"
NAME = "qualification-alpha"
UNAVAILABLE = (False, True, False, ())
MISSING = (False, False, False, ())
UNVERIFIED = (True, False, False, ())
GITHUB = (True, False, True, ("github actions",))
MANUAL = (True, False, True, ("manual upload",))


@dataclass(frozen=True)
class Row:
    rule: str
    level: str | None
    reason: str
    source: str | None
    observed: object
    threshold: object = None
    key: str | None = KEY
    name: str | None = NAME
    bucket: str | None = None
    confidence: str = "policy_matched"
    group: str = "blocking"
    suppression: str | None = None


def risk(
    level="block", source="block_on", group="blocking", rule="new_package", bucket=None
):
    return Row(
        rule,
        level,
        "risk_finding_matched_policy_rule",
        source,
        bucket or rule,
        bucket=bucket or rule,
        group=group,
        suppression="ignored_by_policy" if group == "suppressed" else None,
    )


def maximum(level="block", source="default_block", group="blocking"):
    return Row(
        "max_added_packages",
        level,
        "added_package_count_exceeded_threshold",
        source,
        1,
        0,
        key=None,
        name=None,
        group=group,
        suppression="ignored_by_policy" if group == "suppressed" else None,
    )


def source_row(
    host="github.com",
    allowed=None,
    level="block",
    source="default_block",
    group="blocking",
):
    return Row(
        "allow_sources",
        level,
        "source_host_not_allowed",
        source,
        host,
        ["pypi.org"] if allowed is None else allowed,
        group=group,
    )


def unavailable(recorded=False):
    return Row(
        "provenance_unavailable",
        "block",
        "provenance_evidence_unavailable",
        "block_on",
        "unavailable",
        confidence="provenance_recorded" if recorded else "policy_matched",
    )


def missing():
    return Row(
        "missing_attestation",
        "block",
        "attestation_not_published",
        "block_on",
        False,
        confidence="provenance_recorded",
    )


def unverified(publishers=(), allowed=None):
    return Row(
        "unverified_provenance",
        "block",
        "provenance_publisher_not_verified",
        "block_on",
        list(publishers),
        allowed,
        confidence="provenance_recorded",
    )


def required(
    observed="provenance_unavailable",
    recorded=False,
    level="block",
    source="default_block",
    group="blocking",
):
    return Row(
        "provenance_required",
        level,
        "required_provenance_not_satisfied",
        source,
        observed,
        confidence="provenance_recorded" if recorded else "policy_matched",
        group=group,
        suppression="ignored_by_policy" if group == "suppressed" else None,
    )


def score_row(level="block", source="block_on", group="blocking"):
    return Row(
        "scorecard_below_threshold",
        level,
        "scorecard_score_below_threshold",
        source,
        6.9,
        7.0,
        confidence="scorecard_recorded",
        group=group,
        suppression="ignored_by_policy" if group == "suppressed" else None,
    )


@dataclass(frozen=True)
class Case:
    id: str
    family: str
    policy: dict | None
    rows: tuple[Row, ...] = ()
    findings: tuple[str, ...] = ()
    provenance: str = "none"
    publishers: tuple[str, ...] = ()
    assessment: tuple = UNAVAILABLE
    score: float | None = None
    score_available: bool = True
    source_url: str | None = "https://github.com/example/qualification"
    scope: str = "added"
    fail_on: str | None = None
    warn_on: str | None = None
    effective_version: int | None = None
    invalid: bool = False
    expected_decision: str = "PASS"
    note: str = ""


CASES = (
    Case(
        "M01",
        "defaults",
        None,
        findings=("new_package",),
        expected_decision="NOT_APPLIED",
    ),
    Case("M02", "defaults", {"version": 1}, findings=("new_package",)),
    Case(
        "M03",
        "explicit-severity",
        {"version": 1, "block_on": ["new_package"]},
        (risk(),),
        ("new_package",),
        expected_decision="FAIL",
    ),
    Case(
        "M04",
        "explicit-severity",
        {"version": 1, "warn_on": ["new_package"]},
        (risk("warn", "warn_on", "warning"),),
        ("new_package",),
        expected_decision="WARN",
    ),
    Case(
        "M05",
        "explicit-severity",
        {"version": 1, "block_on": ["new_package"], "warn_on": ["new_package"]},
        (risk(),),
        ("new_package",),
        expected_decision="FAIL",
    ),
    Case(
        "M06",
        "ignore",
        {
            "version": 1,
            "block_on": ["new_package"],
            "warn_on": ["new_package"],
            "ignore_rules": ["new_package"],
        },
        (risk(group="suppressed"),),
        ("new_package",),
    ),
    Case(
        "M07",
        "ignore",
        {"version": 1, "ignore_rules": ["new_package"]},
        (risk(None, None, "suppressed"),),
        ("new_package",),
    ),
    Case(
        "M08",
        "maximum",
        {"version": 1, "max_added_packages": 0},
        (maximum(),),
        expected_decision="FAIL",
    ),
    Case("M09", "maximum", {"version": 1, "max_added_packages": 1}),
    Case("M10", "maximum", {"version": 1, "max_added_packages": 2}),
    Case(
        "M11",
        "maximum",
        {"version": 1, "max_added_packages": 0, "warn_on": ["max_added_packages"]},
        (maximum("warn", "warn_on", "warning"),),
        expected_decision="WARN",
    ),
    Case(
        "M12",
        "maximum",
        {"version": 1, "max_added_packages": 0, "ignore_rules": ["max_added_packages"]},
        (maximum(group="suppressed"),),
    ),
    Case("M13", "sources", {"version": 1, "allow_sources": ["github.com"]}),
    Case(
        "M14",
        "sources",
        {"version": 1, "allow_sources": ["pypi.org"]},
        (source_row(),),
        expected_decision="FAIL",
    ),
    Case(
        "M15",
        "sources",
        {"version": 1, "allow_sources": ["github.com"], "warn_on": ["allow_sources"]},
        (source_row("missing", ["github.com"], "warn", "warn_on", "warning"),),
        source_url=None,
        expected_decision="WARN",
    ),
    Case("M16", "sources", {"version": 1, "allow_sources": []}, source_url=None),
    Case(
        "M17",
        "unavailable",
        {"version": 2, "block_on": ["provenance_unavailable"]},
        (unavailable(),),
        expected_decision="FAIL",
    ),
    Case(
        "M18",
        "unavailable",
        {"version": 2, "block_on": ["provenance_unavailable"]},
        (unavailable(True),),
        provenance="error",
        expected_decision="FAIL",
    ),
    Case(
        "M19",
        "unavailable",
        {"version": 2, "block_on": ["provenance_unavailable"]},
        (unavailable(True),),
        provenance="unsupported",
        expected_decision="FAIL",
    ),
    Case(
        "M20",
        "missing-attestation",
        {"version": 2, "block_on": ["missing_attestation"]},
        (missing(),),
        provenance="missing",
        assessment=MISSING,
        expected_decision="FAIL",
    ),
    Case(
        "M21",
        "missing-attestation",
        {"version": 2, "block_on": ["provenance_unavailable"]},
        provenance="missing",
        assessment=MISSING,
    ),
    Case(
        "M22",
        "unverified",
        {"version": 2, "block_on": ["unverified_provenance"]},
        (unverified(),),
        provenance="attested",
        assessment=UNVERIFIED,
        expected_decision="FAIL",
    ),
    Case(
        "M23",
        "publishers",
        {"version": 2, "block_on": ["unverified_provenance"]},
        provenance="attested",
        publishers=("manual upload",),
        assessment=MANUAL,
        note="Recorded publisher kind, not cryptographic verification.",
    ),
    Case(
        "M24",
        "publishers",
        {
            "version": 2,
            "block_on": ["unverified_provenance"],
            "allow_provenance_publishers": ["manual upload"],
        },
        (unverified(("github actions",), ["manual upload"]),),
        provenance="attested",
        publishers=("github actions",),
        assessment=(True, False, False, ("github actions",)),
        expected_decision="FAIL",
    ),
    Case(
        "M25",
        "publishers",
        {
            "version": 2,
            "block_on": ["unverified_provenance"],
            "allow_provenance_publishers": ["github actions"],
        },
        provenance="attested",
        publishers=("github actions",),
        assessment=GITHUB,
    ),
    Case(
        "M26",
        "publishers",
        {
            "version": 2,
            "block_on": ["unverified_provenance"],
            "allow_provenance_publishers": ["github actions"],
        },
        provenance="attested",
        publishers=("manual upload", "github actions"),
        assessment=(True, False, True, ("github actions", "manual upload")),
    ),
    Case(
        "M27",
        "required",
        {"version": 2, "require_attestations_for_new_packages": True},
        (required(),),
        expected_decision="FAIL",
    ),
    Case(
        "M28",
        "required",
        {"version": 2, "require_attestations_for_new_packages": True},
        (required("attestation_missing", True),),
        provenance="missing",
        assessment=MISSING,
        expected_decision="FAIL",
    ),
    Case(
        "M29",
        "required",
        {"version": 2, "require_attestations_for_new_packages": True},
        (required("provenance_unverified", True),),
        provenance="attested",
        assessment=UNVERIFIED,
        expected_decision="FAIL",
    ),
    Case(
        "M30",
        "required",
        {"version": 2, "require_attestations_for_new_packages": True},
        provenance="attested",
        publishers=("github actions",),
        assessment=GITHUB,
    ),
    Case(
        "M31",
        "required",
        {
            "version": 2,
            "require_attestations_for_new_packages": True,
            "warn_on": ["provenance_required"],
        },
        (required(level="warn", source="warn_on", group="warning"),),
        expected_decision="WARN",
    ),
    Case(
        "M32",
        "required",
        {
            "version": 2,
            "require_attestations_for_new_packages": True,
            "ignore_rules": ["provenance_required"],
        },
        (required(group="suppressed"),),
    ),
    Case("M33", "required", {"version": 2, "block_on": ["provenance_required"]}),
    Case(
        "M34",
        "package-exception",
        {
            "version": 2,
            "block_on": ["missing_attestation"],
            "require_attestations_for_new_packages": True,
            "allow_unattested_packages": [NAME],
        },
        provenance="missing",
        assessment=MISSING,
    ),
    Case(
        "M35",
        "package-exception",
        {
            "version": 2,
            "block_on": ["provenance_unavailable"],
            "require_attestations_for_new_packages": True,
            "allow_unattested_packages": [NAME],
        },
        (required(), unavailable()),
        expected_decision="FAIL",
    ),
    Case(
        "M36",
        "package-exception",
        {
            "version": 2,
            "block_on": ["unverified_provenance"],
            "allow_unattested_packages": [NAME],
        },
        (unverified(),),
        provenance="attested",
        assessment=UNVERIFIED,
        expected_decision="FAIL",
    ),
    Case(
        "M37",
        "required",
        {"version": 2, "require_provenance_for_suspicious_sources": True},
        (required("attestation_missing", True),),
        findings=("suspicious_source",),
        provenance="missing",
        assessment=MISSING,
        expected_decision="FAIL",
    ),
    Case(
        "M38",
        "required",
        {"version": 2, "require_provenance_for_suspicious_sources": True},
    ),
    Case(
        "M39",
        "scope",
        {"version": 2, "require_attestations_for_new_packages": True},
        scope="changed",
    ),
    Case(
        "M40",
        "scope",
        {"version": 2, "block_on": ["missing_attestation"]},
        provenance="missing",
        assessment=MISSING,
        scope="unchanged",
    ),
    Case(
        "M41",
        "contradiction",
        {
            "version": 2,
            "block_on": ["provenance_unavailable"],
            "require_attestations_for_new_packages": True,
        },
        (required(recorded=True), unavailable(True)),
        provenance="error-and-attested",
        publishers=("github actions",),
        expected_decision="FAIL",
    ),
    Case("M42", "scorecard", {"version": 3, "minimum_scorecard_score": 7}, score=6.9),
    Case(
        "M43",
        "scorecard",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        (score_row(),),
        score=6.9,
        expected_decision="FAIL",
    ),
    Case(
        "M44",
        "scorecard",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score=7.0,
    ),
    Case(
        "M45",
        "scorecard",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score=7.1,
    ),
    Case(
        "M46",
        "scorecard",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
    ),
    Case(
        "M47",
        "scorecard",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "warn_on": ["scorecard_below_threshold"],
        },
        (score_row("warn", "warn_on", "warning"),),
        score=6.9,
        expected_decision="WARN",
    ),
    Case(
        "M48",
        "scorecard",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "ignore_rules": ["scorecard_below_threshold"],
        },
        (score_row(None, None, "suppressed"),),
        score=6.9,
    ),
    Case(
        "M49",
        "scorecard",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score=6.9,
        score_available=False,
    ),
    Case(
        "M50",
        "version-eligibility",
        {"version": 1, "block_on": ["missing_attestation"]},
        invalid=True,
        expected_decision="INVALID_INPUT",
    ),
    Case(
        "M51",
        "version-eligibility",
        {"version": 2, "block_on": ["scorecard_below_threshold"]},
        invalid=True,
        expected_decision="INVALID_INPUT",
    ),
    Case(
        "M52",
        "version-eligibility",
        {"version": 1, "allow_unattested_packages": [NAME]},
        invalid=True,
        expected_decision="INVALID_INPUT",
    ),
    Case(
        "M53",
        "version-eligibility",
        {"version": 2, "minimum_scorecard_score": 7},
        invalid=True,
        expected_decision="INVALID_INPUT",
    ),
    Case(
        "M54",
        "cli-merge",
        {"version": 1},
        fail_on="scorecard_below_threshold",
        effective_version=3,
    ),
    Case(
        "M55",
        "cli-merge",
        {"version": 1, "warn_on": ["new_package"]},
        (risk(),),
        ("new_package",),
        fail_on="new_package",
        expected_decision="FAIL",
    ),
    Case(
        "M56",
        "cli-merge",
        {"version": 1, "block_on": ["new_package"]},
        (risk(),),
        ("new_package",),
        warn_on="new_package",
        expected_decision="FAIL",
    ),
    Case(
        "M57",
        "cli-merge",
        None,
        fail_on="provenance_unavailable",
        effective_version=2,
        rows=(unavailable(),),
        expected_decision="FAIL",
    ),
    Case(
        "M58",
        "risk-alias",
        {"version": 1, "warn_on": ["stale_package"]},
        (risk("warn", "warn_on", "warning", "stale_package", "not_evaluated"),),
        ("not_evaluated",),
        expected_decision="WARN",
    ),
    Case(
        "M59",
        "publisher-alias",
        {
            "version": 2,
            "allow_unattested_publishers": [" GITHUB ACTIONS "],
            "block_on": ["unverified_provenance"],
        },
        provenance="attested",
        publishers=(" GitHub Actions ",),
        assessment=GITHUB,
    ),
    Case(
        "M60",
        "scope",
        {"version": 1, "allow_sources": ["pypi.org"]},
        (source_row(),),
        scope="changed",
        expected_decision="FAIL",
    ),
    Case(
        "M61",
        "sources",
        {"version": 1, "allow_sources": ["github.com"]},
        (source_row("sub.github.com", ["github.com"]),),
        source_url="https://sub.github.com/example/qualification",
        expected_decision="FAIL",
    ),
    Case(
        "M62",
        "invalid-types",
        {"version": 1.0},
        invalid=True,
        expected_decision="INVALID_INPUT",
    ),
    Case(
        "M63",
        "invalid-types",
        {"version": 3, "minimum_scorecard_score": True},
        invalid=True,
        expected_decision="INVALID_INPUT",
    ),
    Case(
        "M64",
        "cli-merge",
        None,
        warn_on="new_package",
        effective_version=1,
        rows=(risk("warn", "warn_on", "warning"),),
        findings=("new_package",),
        expected_decision="WARN",
    ),
    Case(
        "M65",
        "package-exception",
        {
            "version": 2,
            "require_attestations_for_new_packages": True,
            "allow_unattested_packages": [NAME],
        },
        provenance="missing",
        assessment=MISSING,
    ),
    Case(
        "M66",
        "package-exception",
        {
            "version": 2,
            "block_on": ["missing_attestation"],
            "allow_unattested_packages": [NAME],
        },
        provenance="missing",
        assessment=MISSING,
    ),
    Case(
        "M67",
        "package-exception",
        {
            "version": 2,
            "require_attestations_for_new_packages": True,
            "allow_unattested_packages": [NAME],
        },
        (required(),),
        expected_decision="FAIL",
    ),
    Case(
        "M68",
        "package-exception",
        {
            "version": 2,
            "block_on": ["unverified_provenance"],
            "allow_unattested_packages": [NAME],
        },
        (unverified(),),
        provenance="attested",
        assessment=UNVERIFIED,
        expected_decision="FAIL",
    ),
    Case(
        "M69",
        "contradiction",
        {
            "version": 2,
            "block_on": ["provenance_unavailable"],
            "require_attestations_for_new_packages": True,
        },
        provenance="attested",
        publishers=("github actions",),
        assessment=GITHUB,
    ),
    Case(
        "M70",
        "scorecard",
        {
            "version": 3,
            "minimum_scorecard_score": 6,
            "block_on": ["scorecard_below_threshold"],
        },
        score=6.9,
    ),
    Case(
        "M71",
        "version-eligibility",
        {"version": 2, "block_on": ["new_package"]},
        (risk(),),
        ("new_package",),
        expected_decision="FAIL",
    ),
    Case(
        "M72",
        "version-eligibility",
        {"version": 3, "block_on": ["scorecard_below_threshold"]},
    ),
)
CASE_BY_ID = {case.id: case for case in CASES}


class OracleMismatch(AssertionError):
    def __init__(self, code, actual, expected):
        super().__init__(f"{code}: actual={actual!r}, expected={expected!r}")
        self.code = code


def require(code, actual, expected):
    if not evidence_equal(actual, expected):
        raise OracleMismatch(code, actual, expected)


def evidence_equal(actual, expected):
    """Retain numeric equality, but never treat a boolean as numeric evidence."""
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, dict) and isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(
            evidence_equal(actual[key], expected[key]) for key in expected
        )
    if isinstance(actual, (list, tuple)) and isinstance(expected, type(actual)):
        return len(actual) == len(expected) and all(
            evidence_equal(left, right) for left, right in zip(actual, expected)
        )
    return actual == expected


def expected_row(row):
    return {
        "rule": row.rule,
        "level": row.level,
        "reason": row.reason,
        "source": row.source,
        "observed": row.observed,
        "threshold": row.threshold,
        "key": row.key,
        "name": row.name,
        "bucket": row.bucket,
        "confidence": row.confidence,
        "group": row.group,
        "suppression": row.suppression,
        "policy_rule": row.rule,
    }


def validate_case(case, actual):
    require("decision", actual["decision"], case.expected_decision)
    require(
        "exit",
        actual["exit_code"],
        2 if case.invalid else 1 if case.expected_decision == "FAIL" else 0,
    )
    if case.invalid:
        require("invalid-type", actual["error_type"], "PolicyError")
        return
    require("identity", actual["identity"], KEY)
    require("assessment", actual["assessment"], case.assessment)
    expected = [expected_row(row) for row in case.rows]
    sort_key = lambda row: (
        row["group"],
        row["rule"],
        row["key"] or "",
        row["name"] or "",
    )
    require(
        "violation-identity",
        [
            (row["group"], row["rule"], row["key"])
            for row in sorted(actual["rows"], key=sort_key)
        ],
        [
            (row["group"], row["rule"], row["key"])
            for row in sorted(expected, key=sort_key)
        ],
    )
    for got, want in zip(
        sorted(actual["rows"], key=sort_key), sorted(expected, key=sort_key)
    ):
        for name in want:
            require(f"explanation-{name}", got[name], want[name])
    require(
        "suppression-accounting",
        actual["ignored_checks"],
        sum(row.group == "suppressed" for row in case.rows),
    )
    if case.effective_version is not None:
        require(
            "effective-version", actual["effective_version"], case.effective_version
        )
