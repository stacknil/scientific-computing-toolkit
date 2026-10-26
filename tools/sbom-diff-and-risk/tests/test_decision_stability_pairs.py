"""Preregistered single-dimension transitions, including non-monotonic cases."""

import random
from copy import deepcopy
from dataclasses import dataclass

import pytest

from sbom_diff_risk.component_identity import canonicalize_component_identity
from sbom_diff_risk.normalize import normalize_input

from test_decision_stability import observe_case, render_bundle
from test_decision_stability_oracle import CASE_BY_ID, require, validate_case
from test_decision_stability_reports import (
    cdx_component,
    consumer_decision,
    run_cli,
    validate_bundle,
)


@dataclass(frozen=True)
class Transition:
    id: str
    left: str
    right: str
    dimension: str
    expected: str
    reason: str


TRANSITIONS = tuple(
    Transition(f"P{index:02d}", *values)
    for index, values in enumerate(
        (
            (
                "M02",
                "M03",
                "activate block rule",
                "JUSTIFIED_REVERSAL",
                "A local finding is enforced only by an explicit rule.",
            ),
            (
                "M03",
                "M04",
                "explicit severity",
                "JUSTIFIED_REVERSAL",
                "Configured severity changes enforcement.",
            ),
            (
                "M04",
                "M05",
                "overlapping block rule",
                "JUSTIFIED_REVERSAL",
                "Explicit block wins over an existing warn.",
            ),
            (
                "M05",
                "M06",
                "add ignore",
                "JUSTIFIED_REVERSAL",
                "Ignore takes precedence but retains suppression evidence.",
            ),
            (
                "M08",
                "M09",
                "count threshold 0 to 1",
                "JUSTIFIED_REVERSAL",
                "One added component does not exceed a threshold of one.",
            ),
            (
                "M09",
                "M10",
                "count threshold 1 to 2",
                "STABLE",
                "Neither threshold is exceeded.",
            ),
            (
                "M08",
                "M11",
                "explicit warning override",
                "JUSTIFIED_REVERSAL",
                "Warn overrides implicit default block.",
            ),
            (
                "M08",
                "M12",
                "ignore implicit block",
                "JUSTIFIED_REVERSAL",
                "The omitted block is accounted for as a suppression.",
            ),
            (
                "M13",
                "M14",
                "source allowlist membership",
                "JUSTIFIED_REVERSAL",
                "Observed host falls outside the narrowed allowed set.",
            ),
            (
                "M17",
                "M18",
                "disabled to failed provenance",
                "STABLE",
                "Both evidence states remain unavailable; confidence describes record presence.",
            ),
            (
                "M18",
                "M19",
                "failed to unsupported provenance",
                "STABLE",
                "Neither state supplies available provenance.",
            ),
            (
                "M17",
                "M21",
                "successful metadata without attestation",
                "JUSTIFIED_REVERSAL",
                "Unavailable-only policy stops blocking once a lookup succeeds; this is not verified provenance.",
            ),
            (
                "M22",
                "M23",
                "recorded publisher supplied",
                "JUSTIFIED_REVERSAL",
                "A nonempty publisher kind satisfies the current recorded-metadata contract without an allowlist.",
            ),
            (
                "M24",
                "M25",
                "publisher allowlist membership",
                "JUSTIFIED_REVERSAL",
                "The recorded publisher is explicitly authorized.",
            ),
            (
                "M25",
                "M26",
                "additional publisher kind",
                "STABLE",
                "The existing allowlist contract requires any matching kind.",
            ),
            (
                "M27",
                "M28",
                "unknown to known missing attestation",
                "STABLE",
                "Required provenance remains unsatisfied; explanation evidence changes.",
            ),
            (
                "M28",
                "M29",
                "missing to unverified attestation",
                "STABLE",
                "Presence alone does not satisfy a provenance requirement.",
            ),
            (
                "M29",
                "M30",
                "recorded publisher identity supplied",
                "JUSTIFIED_REVERSAL",
                "Recorded publisher metadata satisfies the existing requirement, without a cryptographic claim.",
            ),
            (
                "M27",
                "M31",
                "required rule warning override",
                "JUSTIFIED_REVERSAL",
                "Explicit warn overrides implicit blocking.",
            ),
            (
                "M27",
                "M32",
                "ignore required rule",
                "JUSTIFIED_REVERSAL",
                "An explicit suppression is retained.",
            ),
            (
                "M28",
                "M65",
                "authorize package exception",
                "JUSTIFIED_REVERSAL",
                "A name exception may satisfy a requirement caused solely by missing attestations.",
            ),
            (
                "M20",
                "M66",
                "authorize missing-attestation exception",
                "JUSTIFIED_REVERSAL",
                "Only the missing-attestation check is waived.",
            ),
            (
                "M27",
                "M67",
                "add exception to unavailable evidence",
                "STABLE",
                "A package exception does not waive unavailable provenance.",
            ),
            (
                "M22",
                "M68",
                "add exception to unverified evidence",
                "STABLE",
                "A package exception does not waive an unverified publisher.",
            ),
            (
                "M69",
                "M41",
                "add contradictory enrichment error",
                "JUSTIFIED_REVERSAL",
                "An explicit error dominates attestation availability.",
            ),
            (
                "M42",
                "M43",
                "activate Scorecard enforcement",
                "JUSTIFIED_REVERSAL",
                "A threshold alone is advisory; the block rule activates enforcement.",
            ),
            (
                "M43",
                "M44",
                "score reaches threshold",
                "JUSTIFIED_REVERSAL",
                "Equality is permitted; only a lower score violates.",
            ),
            (
                "M44",
                "M45",
                "score above threshold",
                "STABLE",
                "Both scores meet the minimum.",
            ),
            (
                "M43",
                "M47",
                "Scorecard severity",
                "JUSTIFIED_REVERSAL",
                "Explicit warn changes the policy decision but does not erase evidence.",
            ),
            (
                "M42",
                "M48",
                "ignore advisory Scorecard",
                "STABLE",
                "Decision stays pass while ignored evidence becomes visible.",
            ),
            (
                "M43",
                "M49",
                "Scorecard availability lost",
                "JUSTIFIED_REVERSAL",
                "Unknown scores are not fabricated into threshold violations under current policy.",
            ),
            (
                "M43",
                "M70",
                "lower Scorecard threshold",
                "JUSTIFIED_REVERSAL",
                "6.9 meets a configured minimum of 6.",
            ),
            (
                "M03",
                "M71",
                "policy version 1 to 2",
                "STABLE",
                "An existing local rule retains its severity across capability versions.",
            ),
            (
                "M51",
                "M72",
                "policy version 2 to 3",
                "INVALID_INPUT",
                "A Scorecard rule is rejected in v2 and eligible in v3.",
            ),
        ),
        1,
    )
)


def exercise_transition(transition, directory, seed=103):
    left, right = CASE_BY_ID[transition.left], CASE_BY_ID[transition.right]
    observations = []
    for label, case in (("left", left), ("right", right)):
        observation, report = observe_case(case, directory / label, seed)
        validate_case(case, observation)
        if report is not None:
            validate_bundle(
                render_bundle(report), observation["exit_code"], expected_rows=case.rows
            )
        observations.append(observation)
    a, b = observations
    observed = (
        "INVALID_INPUT"
        if left.invalid or right.invalid
        else "STABLE"
        if a["decision"] == b["decision"]
        else "JUSTIFIED_REVERSAL"
    )
    require("transition-classification", observed, transition.expected)
    return {
        "id": transition.id,
        "original_case_id": left.id,
        "perturbed_case_id": right.id,
        "perturbation": transition.dimension,
        "before_canonical_identity": a.get("identity"),
        "after_canonical_identity": b.get("identity"),
        "source_evidence_changes": {
            "provenance": [left.provenance, right.provenance],
            "publishers": [left.publishers, right.publishers],
            "score": [left.score, right.score],
            "score_available": [left.score_available, right.score_available],
        },
        "active_policy": {"before": left.policy, "after": right.policy},
        "previous_decision": a["decision"],
        "resulting_decision": b["decision"],
        "expected_classification": transition.expected,
        "observed_classification": observed,
        "reason": transition.reason,
        "before": a,
        "after": b,
    }


@pytest.mark.parametrize("transition", TRANSITIONS, ids=lambda item: item.id)
def test_policy_evidence_transition(transition, tmp_path):
    exercise_transition(transition, tmp_path)


def policy_projection(bundle):
    """Raw evidence and presentation paths may differ under representation changes."""
    result = {
        key: deepcopy(bundle["report"][key])
        for key in (
            "summary",
            "blocking_findings",
            "warning_findings",
            "suppressed_findings",
        )
    }
    for section in ("blocking_findings", "warning_findings", "suppressed_findings"):
        for row in result[section]:
            row.pop("component_name")  # Observed spelling is deliberately preserved.
    return result


def exercise_representation(case_id, directory, seed=103):
    base = cdx_component()
    empty = {"bomFormat": "CycloneDX", "components": []}
    before = {"bomFormat": "CycloneDX", "components": [deepcopy(base)]}
    left_after = {"bomFormat": "CycloneDX", "components": [deepcopy(base)]}
    right_after = deepcopy(left_after)
    policy = {"version": 1, "block_on": ["new_package"]}
    expected_decisions = ("FAIL", "FAIL")
    expected_ids = (
        ["purl:pkg:pypi/qualification-alpha"],
        ["purl:pkg:pypi/qualification-alpha"],
    )
    expected_class = "STABLE"
    reason = "Supported identity equivalence preserves enforcement; original evidence remains observable."
    left_before = right_before = empty
    if case_id == "R01":
        right_after["components"][0]["name"] = "Qualification_Alpha"
    elif case_id == "R02":
        for record in (left_after["components"][0], right_after["components"][0]):
            record.update(
                name="Qualification", purl="pkg:npm/%40scope/Qualification@1.0.0"
            )
        right_after["components"][0].update(
            name="qualification", purl="pkg:npm/%40scope/qualification@1.0.0"
        )
        expected_ids = (["purl:pkg:npm/%40scope/qualification"],) * 2
    elif case_id == "R03":
        policy = {"version": 1, "block_on": ["major_upgrade"]}
        left_before = right_before = before
        left_after["components"][0].update(
            version=None, purl="pkg:pypi/qualification-alpha@2.0.0"
        )
        right_after["components"][0].update(
            version="2.0.0", purl="pkg:pypi/qualification-alpha@2.0.0"
        )
    elif case_id == "R04":
        left_after["components"][0]["bom-ref"] = "opaque:qualification"
    elif case_id in {"R05", "R06"}:
        right_after["components"].append(deepcopy(base))
        if case_id == "R06":
            right_after["components"][1]["licenses"] = [
                {"license": {"id": "BSD-3-Clause"}}
            ]
        expected_decisions = ("FAIL", "INVALID_INPUT")
        expected_class = "INVALID_INPUT"
        reason = "Duplicate or conflicting identities must be rejected before report completion."
        expected_ids = (expected_ids[0], None)
    elif case_id == "R07":
        right_after["components"][0]["version"] = "2.0.0"
        expected_decisions, expected_class = ("FAIL", "INVALID_INPUT"), "INVALID_INPUT"
        expected_ids = (expected_ids[0], None)
        reason = "An explicit version conflicts with its PURL version."
    elif case_id == "R08":
        right_after["components"][0]["name"] = "another-package"
        expected_decisions, expected_class = ("FAIL", "INVALID_INPUT"), "INVALID_INPUT"
        expected_ids = (expected_ids[0], None)
        reason = "An explicit name conflicts with its PURL name."
    elif case_id == "R09":
        for record in (left_after["components"][0], right_after["components"][0]):
            record.pop("purl")
        left_after["components"][0]["bom-ref"] = "Opaque:X"
        right_after["components"][0]["bom-ref"] = "opaque:x"
        expected_ids = (["bom-ref:Opaque:X"], ["bom-ref:opaque:x"])
        reason = "Opaque references remain distinct; identical policy outcomes do not assert identity equivalence."
    elif case_id == "R10":
        left_after["components"][0].update(
            name="Qualification", purl="pkg:generic/Qualification@1.0.0"
        )
        right_after["components"][0].update(
            name="qualification", purl="pkg:generic/qualification@1.0.0"
        )
        expected_ids = (
            ["purl:pkg:generic/Qualification"],
            ["purl:pkg:generic/qualification"],
        )
        reason = "Unsupported ecosystem case equivalence is not invented."
    elif case_id == "R11":
        for record in (left_after["components"][0], right_after["components"][0]):
            record.update(version=None, purl="pkg:generic/qualification-alpha")
        right_after["components"][0]["description"] = "Irrelevant synthetic description"
        expected_ids = (["purl:pkg:generic/qualification-alpha"],) * 2
    elif case_id == "R12":
        right_after["components"][0]["purl"] = "not-a-purl"
        expected_decisions, expected_class = ("FAIL", "INVALID_INPUT"), "INVALID_INPUT"
        expected_ids = (expected_ids[0], None)
        reason = "Malformed identity is rejected rather than silently falling back."
    elif case_id == "R13":
        right_before = {"spdxVersion": "SPDX-2.3", "packages": []}
        right_after = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "qualification-alpha",
                    "versionInfo": "1.0.0",
                    "licenseConcluded": "MIT",
                    "downloadLocation": "https://github.com/example/qualification",
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/qualification-alpha@1.0.0",
                        }
                    ],
                }
            ],
        }
        reason = (
            "Only the shared component, version, license and source subset is compared."
        )
    elif case_id == "R14":
        names = [
            "qualification-alpha",
            "qualification-beta",
            "qualification-gamma",
            "qualification-delta",
        ]
        left_after["components"] = [cdx_component(name) for name in names]
        shuffled = list(names)
        random.Random(seed).shuffle(shuffled)
        right_after["components"] = [cdx_component(name) for name in shuffled]
        expected_ids = (sorted(f"purl:pkg:pypi/{name}" for name in names),) * 2
        reason = (
            "Record ordering is irrelevant; each round records its actual permutation."
        )
    elif case_id == "R15":
        policy = {"version": 1, "allow_sources": ["pypi.org"]}
        left_before = right_before = before
        right_after["components"][0]["description"] = "Ignored synthetic annotation"
        expected_decisions = ("PASS", "PASS")
        expected_ids = ([], [])
        reason = "Raw ignored metadata does not place an unchanged component into policy scope."
    elif case_id == "R16":
        policy = {"version": 1, "allow_sources": ["pypi.org"]}
        left_before = right_before = before
        right_after["components"][0]["licenses"] = [{"license": {"id": "BSD-3-Clause"}}]
        expected_decisions, expected_class = ("PASS", "FAIL"), "JUSTIFIED_REVERSAL"
        expected_ids = ([], expected_ids[1])
        reason = "Compared license metadata creates a changed component, so its existing disallowed source enters policy scope."
    elif case_id == "R17":
        right_after["components"][0].update(
            name=" qualification-alpha ", version=" 1.0.0 "
        )
        reason = "Supported field trimming and JSON serialization do not change identity or policy."
    elif case_id == "R18":
        right_after["components"][0]["version"] = 1
        expected_decisions, expected_class = ("FAIL", "INVALID_INPUT"), "INVALID_INPUT"
        expected_ids = (expected_ids[0], None)
        reason = "A non-string component version is invalid input."
    else:
        raise AssertionError(f"Unregistered representation case {case_id}")
    outputs, identities, decisions = [], [], []
    for label, original, changed in (
        ("left", left_before, left_after),
        ("right", right_before, right_after),
    ):
        code, bundle = run_cli(
            directory / label,
            original,
            changed,
            policy,
            whitespace=(seed % 3 + 1) if label == "right" else 0,
        )
        outputs.append(bundle)
        decisions.append(
            "INVALID_INPUT" if code == 2 else consumer_decision(bundle, code).upper()
        )
        if bundle is None:
            identities.append(None)
        else:
            current = [
                *bundle["report"]["components"]["added"],
                *[item["after"] for item in bundle["report"]["components"]["changed"]],
            ]
            from sbom_diff_risk.models import Component

            identities.append(
                sorted(
                    canonicalize_component_identity(
                        Component(
                            **{
                                key: value
                                for key, value in record.items()
                                if key != "evidence"
                            }
                        )
                    ).component_key
                    for record in current
                )
            )
    require("representation-decisions", tuple(decisions), expected_decisions)
    require("representation-identities", tuple(identities), expected_ids)
    if expected_class == "STABLE" and case_id not in {"R09", "R10"}:
        require(
            "representation-policy-evidence",
            policy_projection(outputs[0]),
            policy_projection(outputs[1]),
        )
    observed_class = (
        "INVALID_INPUT"
        if "INVALID_INPUT" in decisions
        else "STABLE"
        if decisions[0] == decisions[1]
        else "JUSTIFIED_REVERSAL"
    )
    require("representation-classification", observed_class, expected_class)
    return {
        "id": case_id,
        "original_case_id": case_id + "-left",
        "perturbation": reason,
        "before_canonical_identity": identities[0],
        "after_canonical_identity": identities[1],
        "source_evidence_changes": {"before": left_after, "after": right_after},
        "active_policy": policy,
        "previous_decision": decisions[0],
        "resulting_decision": decisions[1],
        "expected_classification": expected_class,
        "observed_classification": observed_class,
        "reason": reason,
        "record_order": [
            item.get("name") for item in right_after.get("components", [])
        ],
    }


REPRESENTATIONS = tuple(f"R{index:02d}" for index in range(1, 19))


@pytest.mark.parametrize("case_id", REPRESENTATIONS)
def test_representation_transition(case_id, tmp_path):
    exercise_representation(case_id, tmp_path)


def exercise_manifest_overlap(directory):
    policy = {"version": 1, "warn_on": ["unknown_license"]}
    projections = []
    for label, filename, content in (
        ("requirements", "requirements.txt", "qualification-alpha==1.0.0\n"),
        (
            "pyproject",
            "pyproject.toml",
            '[project]\nname = "qualification-input"\nversion = "1.0.0"\ndependencies = ["qualification-alpha==1.0.0"]\n',
        ),
    ):
        target = directory / label
        target.mkdir(parents=True, exist_ok=True)
        (target / filename).write_text(content, encoding="utf-8")
        format_name, components, notes = normalize_input(target / filename)
        require("manifest-overlap-count", len(components), 1)
        identity = canonicalize_component_identity(components[0])
        require(
            "manifest-overlap-key",
            identity.component_key,
            "purl:pkg:pypi/qualification-alpha",
        )
        require("manifest-overlap-version", identity.version, "1.0.0")
        from sbom_diff_risk.policy_evaluator import evaluate_policy
        from sbom_diff_risk.policy_models import PolicyConfig
        from sbom_diff_risk.risk import evaluate_risks

        evaluation = evaluate_policy(
            PolicyConfig(version=1, warn_on=("unknown_license",)),
            policy_path=None,
            added=components,
            changed=[],
            findings=evaluate_risks(components, [], allowlist=[]),
        )
        require(
            "manifest-overlap-warning",
            [
                (item.rule_id, item.level.value, item.component_key)
                for item in evaluation.warning_violations
            ],
            [("unknown_license", "warn", "purl:pkg:pypi/qualification-alpha")],
        )
        require("manifest-overlap-exit", evaluation.exit_code, 0)
        projections.append(
            (identity.component_key, identity.version, evaluation.exit_code)
        )
    require("manifest-overlap", projections[0], projections[1])
    return {
        "id": "R19",
        "original_case_id": "requirements-exact-pin",
        "perturbation": "requirements to pyproject exact-pin shared subset",
        "before_canonical_identity": projections[0][0],
        "after_canonical_identity": projections[1][0],
        "source_evidence_changes": "Source formats differ; optional groups, markers and unknown constraints are excluded.",
        "active_policy": policy,
        "previous_decision": "WARN",
        "resulting_decision": "WARN",
        "expected_classification": "STABLE",
        "observed_classification": "STABLE",
        "reason": "Exact pins share coordinate identity and unknown-license evidence.",
    }


def test_manifest_shared_subset(tmp_path):
    exercise_manifest_overlap(tmp_path)
