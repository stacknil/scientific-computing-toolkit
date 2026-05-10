from __future__ import annotations

import json
from pathlib import Path

from sbom_diff_risk import cli


def test_cli_policy_json_writes_policy_only_file(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    policy_path = tmp_path / "policy.json"

    exit_code = cli.main(
        [
            "compare",
            "--before",
            str(project_root / "examples" / "cdx_before.json"),
            "--after",
            str(project_root / "examples" / "cdx_after.json"),
            "--policy",
            str(project_root / "examples" / "policy-strict.yml"),
            "--policy-json",
            str(policy_path),
        ]
    )

    payload = json.loads(policy_path.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert payload["summary"]["policy"] == {
        "status": "fail",
        "blocking": 3,
        "warning": 1,
        "suppressed": 0,
    }
    assert payload["policy_evaluation"]["applied"] is True
    assert payload["policy_evaluation"]["exit_code"] == 1
    assert len(payload["blocking_findings"]) == 3
    assert len(payload["warning_findings"]) == 1
    assert payload["blocking_findings"][0]["decision_reason"] == "added_package_count_exceeded_threshold"
    assert payload["blocking_findings"][0]["policy_rule"] == "max_added_packages"
    assert "components" not in payload
    assert "risks" not in payload
    assert policy_path.read_text(encoding="utf-8").endswith("\n")


def test_cli_policy_json_matches_full_report_policy_sections(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    report_path = tmp_path / "report.json"
    policy_path = tmp_path / "policy.json"

    exit_code = cli.main(
        [
            "compare",
            "--before",
            str(project_root / "examples" / "cdx_before.json"),
            "--after",
            str(project_root / "examples" / "cdx_after.json"),
            "--policy",
            str(project_root / "examples" / "policy-strict.yml"),
            "--out-json",
            str(report_path),
            "--policy-json",
            str(policy_path),
        ]
    )

    report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    policy_payload = json.loads(policy_path.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert policy_payload == _policy_sidecar_from_full_report(report_payload)


def test_cli_policy_json_without_policy_records_not_applied(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    policy_path = tmp_path / "policy.json"

    exit_code = cli.main(
        [
            "compare",
            "--before",
            str(project_root / "examples" / "cdx_before.json"),
            "--after",
            str(project_root / "examples" / "cdx_after.json"),
            "--policy-json",
            str(policy_path),
        ]
    )

    payload = json.loads(policy_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["policy_evaluation"]["applied"] is False
    assert payload["policy_evaluation"]["exit_code"] == 0
    assert "summary" not in payload
    assert payload["blocking_findings"] == []
    assert payload["warning_findings"] == []
    assert payload["suppressed_findings"] == []


def test_cli_policy_json_omitted_does_not_write_policy_file(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    report_path = tmp_path / "report.json"
    policy_path = tmp_path / "policy.json"

    exit_code = cli.main(
        [
            "compare",
            "--before",
            str(project_root / "examples" / "cdx_before.json"),
            "--after",
            str(project_root / "examples" / "cdx_after.json"),
            "--out-json",
            str(report_path),
        ]
    )

    assert exit_code == 0
    assert report_path.is_file()
    assert not policy_path.exists()


def _policy_sidecar_from_full_report(report_payload: dict[str, object]) -> dict[str, object]:
    policy_payload = {
        "policy_evaluation": report_payload["policy_evaluation"],
        "blocking_findings": report_payload["blocking_findings"],
        "warning_findings": report_payload["warning_findings"],
        "suppressed_findings": report_payload["suppressed_findings"],
        "rule_catalog": report_payload["rule_catalog"],
    }

    summary = report_payload["summary"]
    assert isinstance(summary, dict)
    if "policy" in summary:
        policy_payload["summary"] = {"policy": summary["policy"]}

    if "provenance_policy" in report_payload:
        policy_payload["provenance_policy"] = report_payload["provenance_policy"]
        policy_payload["provenance_policy_impact"] = report_payload["provenance_policy_impact"]

    return policy_payload
