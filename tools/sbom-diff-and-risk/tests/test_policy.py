from __future__ import annotations

from pathlib import Path

import pytest

from sbom_diff_risk.errors import PolicyError
from sbom_diff_risk.models import Component, RiskBucket, RiskFinding
from sbom_diff_risk.policy_evaluator import evaluate_policy
from sbom_diff_risk.policy_models import PolicyConfig, PolicyLevel
from sbom_diff_risk.policy_parser import build_policy, load_policy


def test_policy_parser_accepts_minimal_policy() -> None:
    policy_path = _example_path("policy-minimal.yml")

    policy = load_policy(policy_path)

    assert policy.version == 1
    assert policy.block_on == ("unknown_license",)
    assert policy.warn_on == ("new_package",)


def test_policy_parser_rejects_unknown_rule_id(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text("version: 1\nblock_on: [made_up]\n", encoding="utf-8")

    with pytest.raises(PolicyError, match="Unknown rule id"):
        load_policy(path)


def test_policy_parser_rejects_unknown_key(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text("version: 1\nunknown_key: true\n", encoding="utf-8")

    with pytest.raises(PolicyError, match="unsupported keys"):
        load_policy(path)


def test_policy_parser_rejects_invalid_version(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text("version: 4\n", encoding="utf-8")

    with pytest.raises(PolicyError, match="versions 1, 2, and 3"):
        load_policy(path)


def test_build_policy_merges_cli_rules() -> None:
    policy_path = _example_path("policy-minimal.yml")

    policy, policy_path_str = build_policy(policy_path=policy_path, fail_on="suspicious_source", warn_on="new_package")

    assert policy_path_str is not None
    assert policy is not None
    assert "unknown_license" in policy.block_on
    assert "suspicious_source" in policy.block_on
    assert "new_package" in policy.warn_on


def test_build_policy_renders_path_relative_to_cwd(monkeypatch: pytest.MonkeyPatch) -> None:
    project_root = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(project_root)

    _, policy_path_str = build_policy(policy_path=project_root / "examples" / "policy-minimal.yml")

    assert policy_path_str == "examples/policy-minimal.yml"


def test_policy_evaluator_blocks_on_finding_bucket() -> None:
    policy = PolicyConfig(version=1, block_on=("unknown_license",))
    component = Component(name="requests", version="2.32.0", ecosystem="pypi")
    finding = RiskFinding(
        bucket=RiskBucket.UNKNOWN_LICENSE,
        component_key="purl:pkg:pypi/requests",
        component=component,
        rationale="License is missing",
    )

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[finding])

    assert evaluation.exit_code == 1
    assert len(evaluation.blocking_violations) == 1
    assert evaluation.blocking_violations[0].rule_id == "unknown_license"
    assert evaluation.blocking_violations[0].level is PolicyLevel.BLOCK


def test_policy_evaluator_warns_on_rule_when_configured() -> None:
    policy = PolicyConfig(version=1, warn_on=("new_package",))
    component = Component(name="urllib3", version="2.2.1", ecosystem="pypi")
    finding = RiskFinding(
        bucket=RiskBucket.NEW_PACKAGE,
        component_key="purl:pkg:pypi/urllib3",
        component=component,
        rationale="New package",
    )

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[finding])

    assert evaluation.exit_code == 0
    assert len(evaluation.warning_violations) == 1
    assert evaluation.warning_violations[0].rule_id == "new_package"


def test_policy_evaluator_max_added_packages_blocks() -> None:
    policy = PolicyConfig(version=1, max_added_packages=0)
    added = [
        Component(name="urllib3", version="2.2.1", ecosystem="pypi"),
    ]

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=added, changed=[], findings=[])

    assert evaluation.exit_code == 1
    assert any(violation.rule_id == "max_added_packages" for violation in evaluation.blocking_violations)


def test_policy_evaluator_allow_sources_blocks_unknown_hosts() -> None:
    policy = PolicyConfig(version=1, allow_sources=("pypi.org",))
    component = Component(
        name="internal-lib",
        version="1.0.0",
        ecosystem="pypi",
        source_url="https://example.com/internal-lib-1.0.0.tar.gz",
    )

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[])

    assert evaluation.exit_code == 1
    assert any(violation.rule_id == "allow_sources" for violation in evaluation.blocking_violations)


def test_policy_ignore_rules_suppresses_violations() -> None:
    policy = PolicyConfig(version=1, block_on=("unknown_license",), ignore_rules=("unknown_license",))
    component = Component(name="requests", version="2.32.0", ecosystem="pypi")
    finding = RiskFinding(
        bucket=RiskBucket.UNKNOWN_LICENSE,
        component_key="purl:pkg:pypi/requests",
        component=component,
        rationale="License missing",
    )

    evaluation = evaluate_policy(policy, policy_path="policy.yml", added=[component], changed=[], findings=[finding])

    assert evaluation.exit_code == 0
    assert evaluation.blocking_violations == []
    assert evaluation.ignored_checks == 1
    assert len(evaluation.suppressed_violations) == 1
    assert evaluation.suppressed_violations[0].suppression_reason == "ignored_by_policy"


def _example_path(name: str) -> Path:
    return Path(__file__).resolve().parents[1] / "examples" / name
