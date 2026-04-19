from __future__ import annotations

import pytest

from sbom_diff_risk.errors import PolicyError
from sbom_diff_risk.models import (
    Component,
    RepositoryMapping,
    ScorecardCheck,
    ScorecardEvidence,
    ScorecardStatus,
)
from sbom_diff_risk.policy_evaluator import evaluate_policy
from sbom_diff_risk.policy_models import PolicyConfig
from sbom_diff_risk.policy_parser import build_policy, load_policy


def test_policy_parser_accepts_scorecard_v3_policy(tmp_path) -> None:  # noqa: ANN001
    path = tmp_path / "policy.yml"
    path.write_text(
        "\n".join(
            [
                "version: 3",
                "warn_on: [scorecard_below_threshold]",
                "minimum_scorecard_score: 7.5",
                "",
            ]
        ),
        encoding="utf-8",
    )

    policy = load_policy(path)

    assert policy.version == 3
    assert policy.warn_on == ("scorecard_below_threshold",)
    assert policy.minimum_scorecard_score == 7.5


def test_policy_parser_rejects_scorecard_keys_in_version_2_policy(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text("version: 2\nminimum_scorecard_score: 7.0\n", encoding="utf-8")

    with pytest.raises(PolicyError, match="version 2 does not support keys"):
        load_policy(path)


def test_build_policy_cli_only_scorecard_rule_upgrades_to_version_3() -> None:
    policy, policy_path = build_policy(fail_on="scorecard_below_threshold")

    assert policy_path is None
    assert policy is not None
    assert policy.version == 3
    assert policy.block_on == ("scorecard_below_threshold",)


def test_policy_evaluator_warns_when_scorecard_below_threshold() -> None:
    policy = PolicyConfig(
        version=3,
        warn_on=("scorecard_below_threshold",),
        minimum_scorecard_score=7.0,
    )
    component = _component_with_scorecard("requests", "2.32.0", score=5.5)

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[])

    assert evaluation.exit_code == 0
    assert len(evaluation.warning_violations) == 1
    assert evaluation.warning_violations[0].rule_id == "scorecard_below_threshold"
    assert "minimum_scorecard_score=7.0" in evaluation.warning_violations[0].message


def test_policy_evaluator_does_not_gate_scorecard_threshold_without_explicit_rule() -> None:
    policy = PolicyConfig(
        version=3,
        minimum_scorecard_score=7.0,
    )
    component = _component_with_scorecard("requests", "2.32.0", score=5.5)

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[])

    assert evaluation.exit_code == 0
    assert evaluation.blocking_violations == []
    assert evaluation.warning_violations == []


def _component_with_scorecard(name: str, version: str, *, score: float) -> Component:
    return Component(
        name=name,
        version=version,
        ecosystem="pypi",
        scorecard=ScorecardEvidence(
            provider="openssf-scorecard",
            requested=True,
            repository=RepositoryMapping(
                platform="github.com",
                owner="psf",
                repo=name,
                canonical_name=f"github.com/psf/{name}",
                repository_url=f"https://github.com/psf/{name}",
                source="component.source_url",
            ),
            statuses=(ScorecardStatus.SCORECARD_AVAILABLE,),
            score=score,
            date="2026-04-10T00:00:00Z",
            checks=(ScorecardCheck(name="Maintained", score=10),),
        ),
    )
