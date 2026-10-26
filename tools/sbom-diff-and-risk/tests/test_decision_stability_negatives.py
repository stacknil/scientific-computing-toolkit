"""Reached semantic result replacements validate each named oracle boundary."""

from copy import deepcopy

import pytest

from sbom_diff_risk.diffing import diff_components
from sbom_diff_risk.errors import ComponentIdentityError
from sbom_diff_risk.models import Component

from test_decision_stability import observe_case, render_bundle
from test_decision_stability_oracle import (
    CASE_BY_ID,
    OracleMismatch,
    expected_row,
    require,
    score_row,
    validate_case,
)
from test_decision_stability_reports import cdx_component, run_cli, validate_bundle


CONTROLS = (
    ("N01", "M03", "silently remove blocking violation", "decision"),
    ("N02", "M04", "upgrade warning to blocking", "decision"),
    ("N03", "M03", "downgrade blocking to warning", "decision"),
    ("N04", "M06", "drop suppression evidence", "violation-identity"),
    ("N05", "M18", "unavailable provenance becomes verified", "assessment"),
    ("N06", "M20", "missing attestation becomes unavailable", "violation-identity"),
    ("N07", "M22", "accept missing publisher identity", "decision"),
    ("N08", "M42", "enforce advisory-only Scorecard", "decision"),
    ("N09", "M09", "use greater-than-or-equal count threshold", "decision"),
    ("N10", "M03", "split canonical identity", "identity"),
    (
        "N11",
        "identity-conflict",
        "silently accept conflicting metadata",
        "identity-conflict-rejection",
    ),
    ("N12", "M03", "alter policy sidecar evidence", "policy-sidecar"),
    (
        "N13",
        "CLI-warning",
        "replace actual CLI exit with blocking exit",
        "exit-blocking",
    ),
    (
        "N14",
        "M03",
        "launder heuristic into verified safety verdict",
        "no-security-verdict",
    ),
)


def validate_conflict_boundary(diff_function=diff_components):
    records = [
        Component(
            "qualification-alpha",
            "1.0.0",
            "pypi",
            purl="pkg:pypi/qualification-alpha@1.0.0",
            license_id=license_id,
        )
        for license_id in ("MIT", "BSD-3-Clause")
    ]
    rejected = False
    try:
        diff_function([], records)
    except ComponentIdentityError as exc:
        require("conflict-diagnostic", exc.code.value, "conflicting_metadata")
        rejected = True
    require("identity-conflict-rejection", rejected, True)


def exercise_control(control, directory, seed=103):
    control_id, case_id, mutation, target_check = control
    directory.mkdir(parents=True, exist_ok=True)
    if control_id == "N11":
        validate_conflict_boundary()
        checker = lambda: validate_conflict_boundary(lambda before, after: ([], [], []))
        before = {"conflicting_metadata_rejected": True}
        after = {"conflicting_metadata_rejected": False}
    elif control_id == "N13":
        code, bundle = run_cli(
            directory,
            {"bomFormat": "CycloneDX", "components": []},
            {"bomFormat": "CycloneDX", "components": [cdx_component()]},
            {"version": 1, "warn_on": ["new_package"]},
        )
        validate_bundle(bundle, code)
        checker = lambda: validate_bundle(bundle, 1)
        before, after = (
            {"exit_code": code, "warning": 1},
            {"exit_code": 1, "warning": 1},
        )
    else:
        case = CASE_BY_ID[case_id]
        actual, report = observe_case(case, directory, seed)
        validate_case(case, actual)
        before = deepcopy(actual)
        after = deepcopy(actual)
        if control_id in {"N12", "N14"}:
            bundle = render_bundle(report)
            validate_bundle(bundle, actual["exit_code"])
            if control_id == "N12":
                bundle["policy"]["blocking_findings"][0]["observed_value"] = (
                    "corrupted-evidence"
                )
                after = {"sidecar_observed_value": "corrupted-evidence"}
            else:
                bundle["report"]["package_safety_verdict"] = "verified_safe"
                after = {"package_safety_verdict": "verified_safe"}
            checker = lambda: validate_bundle(bundle, actual["exit_code"])
        else:
            if control_id in {"N01", "N07"}:
                after.update(decision="PASS", exit_code=0, rows=[])
            elif control_id == "N02":
                after.update(decision="FAIL", exit_code=1)
                after["rows"][0].update(
                    group="blocking", level="block", source="block_on"
                )
            elif control_id == "N03":
                after.update(decision="WARN", exit_code=0)
                after["rows"][0].update(group="warning", level="warn", source="warn_on")
            elif control_id == "N04":
                after["rows"] = []
                after["ignored_checks"] = 0
            elif control_id == "N05":
                after["assessment"] = (True, False, True, ("github actions",))
            elif control_id == "N06":
                after["rows"][0].update(
                    rule="provenance_unavailable",
                    policy_rule="provenance_unavailable",
                    reason="provenance_evidence_unavailable",
                    observed="unavailable",
                )
            elif control_id == "N08":
                after.update(
                    decision="FAIL", exit_code=1, rows=[expected_row(score_row())]
                )
            elif control_id == "N09":
                after.update(
                    decision="FAIL",
                    exit_code=1,
                    rows=[
                        {
                            "group": "blocking",
                            "rule": "max_added_packages",
                            "key": None,
                            "observed": 1,
                            "threshold": 1,
                        }
                    ],
                )
            elif control_id == "N10":
                after["identity"] = "coord:pypi:Qualification_Alpha"
                after["rows"][0]["key"] = "coord:pypi:Qualification_Alpha"
            else:
                raise AssertionError(f"Unimplemented control {control_id}")
            checker = lambda: validate_case(case, after)
    detected = None
    try:
        checker()
    except OracleMismatch as exc:
        detected = exc.code
    require("negative-target-reached", detected, target_check)
    return {
        "id": control_id,
        "base_case": case_id,
        "mutation": mutation,
        "target_check": target_check,
        "green_validated": True,
        "red_detected": True,
        "detected_check": detected,
        "before": before,
        "corrupted": after,
        "mechanism": "reached semantic result replacement; no import or collection failures",
    }


@pytest.mark.parametrize("control", CONTROLS, ids=lambda item: item[0])
def test_negative_control_detects_its_target(control, tmp_path):
    result = exercise_control(control, tmp_path)
    assert result["green_validated"] and result["red_detected"]
