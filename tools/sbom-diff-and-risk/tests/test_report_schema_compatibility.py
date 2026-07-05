from __future__ import annotations

import json
from pathlib import Path

import pytest

from sbom_diff_risk.schema_versions import POLICY_SCHEMA_V1, REPORT_SCHEMA_V1


_FULL_REPORT_FIXTURES = (
    "sample-report.json",
    "sample-policy-warn-report.json",
    "sample-policy-fail-report.json",
    "sample-requirements-report.json",
    "sample-provenance-report.json",
    "sample-scorecard-report.json",
)

_REQUIRED_REPORT_FIELDS = {
    "report_schema",
    "summary",
    "evidence_confidence",
    "components",
    "risks",
    "policy_evaluation",
    "blocking_findings",
    "warning_findings",
    "suppressed_findings",
    "rule_catalog",
    "metadata",
    "notes",
}

_REQUIRED_POLICY_DECISION_FIELDS = {
    "rule_id",
    "matched_rule_id",
    "decision_reason",
    "exact_evidence",
    "confidence_level",
}


@pytest.mark.parametrize("fixture_name", _FULL_REPORT_FIXTURES)
def test_full_report_fixtures_are_v1_compatible(fixture_name: str) -> None:
    payload = _read_json_fixture(fixture_name)

    assert payload["report_schema"] == REPORT_SCHEMA_V1
    assert set(payload) >= _REQUIRED_REPORT_FIELDS
    assert isinstance(payload["summary"], dict)
    assert isinstance(payload["components"], dict)
    assert isinstance(payload["risks"], list)
    assert isinstance(payload["metadata"], dict)
    assert isinstance(payload["notes"], list)

    for section in ("blocking_findings", "warning_findings", "suppressed_findings"):
        findings = payload[section]
        assert isinstance(findings, list)
        for finding in findings:
            assert set(finding) >= _REQUIRED_POLICY_DECISION_FIELDS
            assert finding["matched_rule_id"] == finding["rule_id"]
            assert set(finding["exact_evidence"]) == {
                "component_key",
                "finding_bucket",
                "matched_threshold",
                "observed_value",
            }
            assert finding["confidence_level"] in {
                "policy_matched",
                "provenance_recorded",
                "scorecard_recorded",
            }


def test_policy_sidecar_uses_v1_policy_schema() -> None:
    payload = _read_json_fixture("sample-policy.json")

    assert payload["policy_schema"] == POLICY_SCHEMA_V1
    assert payload["policy_evaluation"]["effective_policy"]["policy_schema"] == POLICY_SCHEMA_V1


def _read_json_fixture(name: str) -> dict[str, object]:
    path = Path(__file__).resolve().parents[1] / "examples" / name
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload
