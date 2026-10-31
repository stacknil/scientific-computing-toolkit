"""Public YAML/CLI regressions for the documented fail-closed type boundary."""

import json

import pytest

from sbom_diff_risk import cli
from sbom_diff_risk.errors import PolicyError
from sbom_diff_risk.policy_parser import load_policy


@pytest.mark.parametrize(
    "text",
    [
        "version: true\n",
        "version: false\n",
        "version: 1\nmax_added_packages: true\n",
        "version: 1\nmax_added_packages: false\n",
        "version: 1\n0: unsupported\n",
        "version: 1\n0: unsupported\nunknown: unsupported\n",
    ],
    ids=[
        "boolean-version-true",
        "boolean-version-false",
        "boolean-threshold-true",
        "boolean-threshold-false",
        "numeric-key",
        "mixed-key-types",
    ],
)
def test_policy_invalid_integer_fields_and_keys_fail_closed(tmp_path, text):
    path = tmp_path / "policy.yml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(path)


@pytest.mark.parametrize("threshold", [0, 1])
def test_integer_zero_and_one_remain_valid_thresholds(tmp_path, threshold):
    path = tmp_path / "policy.yml"
    path.write_text(f"version: 1\nmax_added_packages: {threshold}\n", encoding="utf-8")
    policy = load_policy(path)
    assert type(policy.version) is int and policy.version == 1
    assert (
        type(policy.max_added_packages) is int
        and policy.max_added_packages == threshold
    )


@pytest.mark.parametrize(
    "policy_text",
    [
        "version: true\n",
        "version: 1\nmax_added_packages: true\n",
        "version: 1\nmax_added_packages: false\n",
        "version: 1\n0: unsupported\n",
    ],
)
def test_cli_invalid_policy_is_error_before_reports(tmp_path, monkeypatch, policy_text):
    monkeypatch.chdir(tmp_path)
    before = {"bomFormat": "CycloneDX", "components": []}
    after = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "name": "qualification-alpha",
                "version": "1.0.0",
                "purl": "pkg:pypi/qualification-alpha@1.0.0",
            }
        ],
    }
    for name, payload in [("before.json", before), ("after.json", after)]:
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "policy.yml").write_text(policy_text, encoding="utf-8")
    assert (
        cli.main(
            [
                "compare",
                "--before",
                "before.json",
                "--after",
                "after.json",
                "--policy",
                "policy.yml",
                "--out-json",
                "report.json",
                "--policy-json",
                "policy.json",
            ]
        )
        == 2
    )
    assert not (tmp_path / "report.json").exists()
    assert not (tmp_path / "policy.json").exists()
