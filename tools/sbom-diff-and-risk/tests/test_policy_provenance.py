from __future__ import annotations

from pathlib import Path

import pytest

from sbom_diff_risk.errors import PolicyError
from sbom_diff_risk.models import (
    Component,
    ProvenanceEvidence,
    ProvenanceFileEvidence,
    ProvenanceStatus,
    RiskBucket,
    RiskFinding,
)
from sbom_diff_risk.policy_evaluator import evaluate_policy
from sbom_diff_risk.policy_models import PolicyConfig, PolicyLevel
from sbom_diff_risk.policy_parser import build_policy, load_policy


def test_policy_parser_accepts_provenance_v2_policy() -> None:
    policy = load_policy(_example_path("policy-provenance-minimal.yml"))

    assert policy.version == 2
    assert policy.warn_on == ("missing_attestation", "provenance_required")
    assert policy.require_attestations_for_new_packages is True
    assert policy.allow_unattested_packages == ("pip",)


def test_policy_parser_rejects_v2_keys_in_version_1_policy(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text("version: 1\nrequire_attestations_for_new_packages: true\n", encoding="utf-8")

    with pytest.raises(PolicyError, match="version 1 does not support keys"):
        load_policy(path)


def test_policy_parser_rejects_v2_rule_ids_in_version_1_policy(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text("version: 1\nblock_on: [missing_attestation]\n", encoding="utf-8")

    with pytest.raises(PolicyError, match="Unknown rule id"):
        load_policy(path)


def test_policy_parser_accepts_allow_unattested_publishers_alias() -> None:
    policy = load_policy(_example_path("policy-provenance-strict.yml"))

    assert policy.allow_provenance_publishers == ("github actions",)


def test_policy_parser_rejects_conflicting_publisher_override_keys(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text(
        "\n".join(
            [
                "version: 2",
                "allow_provenance_publishers:",
                "  - github actions",
                "allow_unattested_publishers:",
                "  - manual upload",
                "",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="use either allow_provenance_publishers or allow_unattested_publishers"):
        load_policy(path)


def test_build_policy_cli_only_provenance_rule_upgrades_to_version_2() -> None:
    policy, policy_path = build_policy(fail_on="missing_attestation")

    assert policy_path is None
    assert policy is not None
    assert policy.version == 2
    assert policy.block_on == ("missing_attestation",)


def test_policy_evaluator_warns_on_provenance_unavailable_without_enrichment() -> None:
    policy = PolicyConfig(version=2, warn_on=("provenance_unavailable",))
    component = Component(name="urllib3", version="2.2.1", ecosystem="pypi")

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[])

    assert evaluation.exit_code == 0
    assert len(evaluation.warning_violations) == 1
    assert evaluation.warning_violations[0].rule_id == "provenance_unavailable"


def test_policy_evaluator_blocks_on_missing_attestation_when_release_is_unattested() -> None:
    policy = PolicyConfig(version=2, block_on=("missing_attestation",))
    component = _component_with_provenance(
        "urllib3",
        "2.2.1",
        statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
    )

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[])

    assert evaluation.exit_code == 1
    assert evaluation.blocking_violations[0].rule_id == "missing_attestation"
    assert evaluation.blocking_violations[0].level is PolicyLevel.BLOCK


def test_policy_evaluator_blocks_on_unverified_provenance_when_publishers_do_not_match() -> None:
    policy = PolicyConfig(
        version=2,
        block_on=("unverified_provenance",),
        allow_provenance_publishers=("github actions",),
    )
    component = _component_with_provenance(
        "requests",
        "2.32.0",
        statuses=(ProvenanceStatus.PROVENANCE_AVAILABLE, ProvenanceStatus.ATTESTATION_AVAILABLE),
        publisher_kinds=("manual upload",),
    )

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[])

    assert evaluation.exit_code == 1
    assert evaluation.blocking_violations[0].rule_id == "unverified_provenance"
    assert "allow_provenance_publishers" in evaluation.blocking_violations[0].message


def test_policy_evaluator_allows_explicit_unattested_package_override() -> None:
    policy = PolicyConfig(
        version=2,
        require_attestations_for_new_packages=True,
        allow_unattested_packages=("urllib3",),
    )
    component = _component_with_provenance(
        "urllib3",
        "2.2.1",
        statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
    )

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[])

    assert evaluation.exit_code == 0
    assert evaluation.blocking_violations == []
    assert evaluation.warning_violations == []


def test_policy_evaluator_allow_unattested_package_does_not_suppress_provenance_unavailable() -> None:
    policy = PolicyConfig(
        version=2,
        block_on=("provenance_unavailable",),
        allow_unattested_packages=("urllib3",),
    )
    component = Component(name="urllib3", version="2.2.1", ecosystem="pypi")

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[])

    assert evaluation.exit_code == 1
    assert [violation.rule_id for violation in evaluation.blocking_violations] == ["provenance_unavailable"]


def test_policy_evaluator_keeps_v1_behavior_when_enrichment_evidence_is_present() -> None:
    policy = PolicyConfig(version=1, warn_on=("new_package",))
    component = _component_with_provenance(
        "urllib3",
        "2.2.1",
        statuses=(ProvenanceStatus.ATTESTATION_UNAVAILABLE,),
    )
    finding = RiskFinding(
        bucket=RiskBucket.NEW_PACKAGE,
        component_key="coord:pypi:urllib3",
        component=component,
        rationale="Component was not present in the before input.",
    )

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[finding])

    assert evaluation.exit_code == 0
    assert [violation.rule_id for violation in evaluation.warning_violations] == ["new_package"]
    assert evaluation.blocking_violations == []


def test_policy_evaluator_blocks_when_suspicious_source_requires_provenance() -> None:
    policy = PolicyConfig(version=2, require_provenance_for_suspicious_sources=True)
    component = Component(name="mystery-lib", version="1.0.0", ecosystem="pypi", source_url="http://example.test/mystery-lib")
    finding = RiskFinding(
        bucket=RiskBucket.SUSPICIOUS_SOURCE,
        component_key="coord:pypi:mystery-lib",
        component=component,
        rationale="Source provenance is suspicious.",
    )

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[finding])

    assert evaluation.exit_code == 1
    assert evaluation.blocking_violations[0].rule_id == "provenance_required"
    assert "suspicious source" in evaluation.blocking_violations[0].message


def _component_with_provenance(
    name: str,
    version: str,
    *,
    statuses: tuple[ProvenanceStatus, ...],
    publisher_kinds: tuple[str, ...] = (),
) -> Component:
    return Component(
        name=name,
        version=version,
        ecosystem="pypi",
        provenance=ProvenanceEvidence(
            provider="pypi",
            requested=True,
            package_name=name,
            package_version=version,
            release_url=f"https://pypi.org/project/{name}/{version}/",
            statuses=statuses,
            files=(
                ProvenanceFileEvidence(
                    filename=f"{name}-{version}.tar.gz",
                    statuses=statuses,
                    attestation_count=1 if ProvenanceStatus.ATTESTATION_AVAILABLE in statuses else 0,
                    publisher_kinds=publisher_kinds,
                ),
            ),
        ),
    )


def _example_path(name: str) -> Path:
    return Path(__file__).resolve().parents[1] / "examples" / name
