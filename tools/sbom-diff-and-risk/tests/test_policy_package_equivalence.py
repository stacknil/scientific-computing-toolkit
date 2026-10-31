"""C02: the approved PyPI package-name exception boundary."""

import json
from pathlib import Path

import pytest
import yaml

from sbom_diff_risk.models import (
    Component,
    ProvenanceEvidence,
    ProvenanceFileEvidence,
    ProvenanceStatus,
)
from sbom_diff_risk.policy_evaluator import (
    _package_is_unattested_allowed,
    evaluate_policy,
)
from sbom_diff_risk.policy_models import PolicyConfig
from sbom_diff_risk.policy_parser import load_policy
from sbom_diff_risk.presentation import policy_evaluation_to_dict


SPELLINGS = ("demo-pkg", "Demo_Pkg", "demo.pkg")


def component(name, state="missing", ecosystem="pypi"):
    states = {
        "missing": (
            ProvenanceStatus.PROVENANCE_AVAILABLE,
            ProvenanceStatus.ATTESTATION_UNAVAILABLE,
        ),
        "unavailable": (ProvenanceStatus.ENRICHMENT_ERROR,),
        "unverified": (
            ProvenanceStatus.PROVENANCE_AVAILABLE,
            ProvenanceStatus.ATTESTATION_AVAILABLE,
        ),
    }
    statuses = states[state]
    return Component(
        name,
        "1.0.0",
        ecosystem,
        purl=f"pkg:{ecosystem}/demo-pkg@1.0.0",
        provenance=ProvenanceEvidence(
            "synthetic-pypi",
            True,
            supported=True,
            lookup_performed=True,
            statuses=statuses,
            files=(
                ProvenanceFileEvidence(
                    "synthetic.whl",
                    statuses=statuses,
                    attestation_count=int(state == "unverified"),
                ),
            ),
        ),
    )


def policy(directory: Path, mode, entry):
    values = {
        "version": 2,
        "block_on": [
            "missing_attestation",
            "provenance_unavailable",
            "unverified_provenance",
        ],
        "require_attestations_for_new_packages": True,
        "allow_unattested_packages": [entry],
    }
    if mode == "direct":
        return PolicyConfig(
            **{
                **values,
                "allow_unattested_packages": (entry,),
                "block_on": tuple(values["block_on"]),
            }
        )
    path = directory / "policy.yml"
    path.write_text(yaml.safe_dump(values), encoding="utf-8")
    return load_policy(path)


@pytest.mark.parametrize("mode", ["direct", "yaml"])
@pytest.mark.parametrize("name", SPELLINGS)
@pytest.mark.parametrize("entry", SPELLINGS)
def test_equivalent_pypi_names_keep_missing_attestation_exception(
    tmp_path, mode, name, entry
):
    config = policy(tmp_path, mode, entry)
    evaluation = evaluate_policy(
        config, policy_path=None, added=[component(name)], changed=[], findings=[]
    )
    assert evaluation.exit_code == 0
    assert (
        evaluation.blocking_violations
        == evaluation.warning_violations
        == evaluation.suppressed_violations
        == []
    )
    serialized = policy_evaluation_to_dict(evaluation)["effective_policy"][
        "allow_unattested_packages"
    ]
    assert serialized == [entry if mode == "direct" else entry.lower()]


@pytest.mark.parametrize(
    "entry", ["demo-pkg-extra", "demopkg", "pkg:pypi/demo-pkg@1.0.0"]
)
def test_non_equivalent_names_do_not_authorize_exception(tmp_path, entry):
    evaluation = evaluate_policy(
        policy(tmp_path, "direct", entry),
        policy_path=None,
        added=[component("demo-pkg")],
        changed=[],
        findings=[],
    )
    assert evaluation.exit_code == 1
    assert [item.rule_id for item in evaluation.blocking_violations] == [
        "missing_attestation",
        "provenance_required",
    ]


@pytest.mark.parametrize("mode", ["direct", "yaml"])
@pytest.mark.parametrize(
    "state,expected",
    [
        ("unavailable", ["provenance_required", "provenance_unavailable"]),
        ("unverified", ["provenance_required", "unverified_provenance"]),
    ],
)
def test_name_exception_does_not_waive_unavailable_or_unverified(
    tmp_path, mode, state, expected
):
    evaluation = evaluate_policy(
        policy(tmp_path, mode, "Demo_Pkg"),
        policy_path=None,
        added=[component("demo.pkg", state)],
        changed=[],
        findings=[],
    )
    assert evaluation.exit_code == 1
    assert [item.rule_id for item in evaluation.blocking_violations] == expected


@pytest.mark.parametrize("ecosystem", ["npm", "generic", "maven"])
def test_package_name_exception_is_pypi_only(ecosystem):
    config = PolicyConfig(version=2, allow_unattested_packages=("demo-pkg",))
    assert (
        _package_is_unattested_allowed(
            config, component("demo-pkg", ecosystem=ecosystem)
        )
        is False
    )


def test_original_c02_reproducer(tmp_path):
    config = PolicyConfig(
        version=2,
        block_on=("missing_attestation",),
        allow_unattested_packages=("demo-pkg",),
    )
    outputs = []
    for name in SPELLINGS:
        evaluation = evaluate_policy(
            config, policy_path=None, added=[component(name)], changed=[], findings=[]
        )
        outputs.append(policy_evaluation_to_dict(evaluation))
    (tmp_path / "c02-observations.json").write_text(
        json.dumps(outputs, indent=2), encoding="utf-8"
    )
    assert [value["exit_code"] for value in outputs] == [0, 0, 0]
