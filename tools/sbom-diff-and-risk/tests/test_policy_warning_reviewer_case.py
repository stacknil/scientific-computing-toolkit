from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOC_PATH = PROJECT_ROOT / "docs" / "policy-warning-reviewer-case.md"
WARN_REPORT = PROJECT_ROOT / "examples" / "sample-policy-warn-report.json"


def test_policy_warning_reviewer_case_matches_warn_fixture() -> None:
    text = DOC_PATH.read_text(encoding="utf-8")
    payload = json.loads(WARN_REPORT.read_text(encoding="utf-8"))

    warning = payload["warning_findings"][0]

    assert payload["summary"]["policy"] == {
        "status": "warn",
        "blocking": 0,
        "warning": 1,
        "suppressed": 0,
    }
    assert payload["summary"]["evidence_confidence"] == "policy_matched"
    assert warning["policy_rule"] == "new_package"
    assert warning["component_name"] == "urllib3"
    assert warning["decision_reason"] == "risk_finding_matched_policy_rule"
    assert warning["severity_source"] == "warn_on"

    for expected in (
        "summary.policy.status",
        "policy_matched",
        "new_package",
        "urllib3",
        "risk_finding_matched_policy_rule",
        "warn_on",
        "not a package safety verdict",
        "any CVE result",
        "any malware verdict",
    ):
        assert expected in text
