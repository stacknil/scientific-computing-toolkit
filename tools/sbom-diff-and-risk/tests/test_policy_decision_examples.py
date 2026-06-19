from __future__ import annotations

import json
from pathlib import Path


EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples" / "policy-decisions"
DECISION_FILES = {
    "pass": "pass.json",
    "warn": "warn.json",
    "fail": "fail.json",
    "needs-review": "needs-review.json",
}
RUNTIME_POLICY_STATUSES = {"pass", "warn", "fail"}
COMMON_NON_CLAIMS = {
    "not a CVE result",
    "not a dependency safety verdict",
    "not a production PyPI release claim",
}


def test_policy_decision_examples_are_complete() -> None:
    expected_files = {"README.md", *DECISION_FILES.values()}
    actual_files = {path.name for path in EXAMPLES_DIR.iterdir() if path.is_file()}

    assert expected_files <= actual_files


def test_policy_decision_examples_have_expected_shape() -> None:
    for decision, filename in DECISION_FILES.items():
        payload = _read_example(filename)

        assert payload["example_type"] == "policy-decision-example"
        assert payload["review_decision"] == decision
        interpretation = payload["reviewer_interpretation"]
        assert interpretation["safe_statement"]
        assert interpretation["next_action"]
        assert COMMON_NON_CLAIMS <= set(interpretation["non_claims"])


def test_pass_warn_fail_examples_mirror_runtime_policy_statuses() -> None:
    for decision in sorted(RUNTIME_POLICY_STATUSES):
        payload = _read_example(DECISION_FILES[decision])
        policy_summary = payload["summary"]["policy"]

        assert payload["decision_source"] == "summary.policy"
        assert policy_summary["status"] == decision

        if decision == "pass":
            assert policy_summary == {
                "status": "pass",
                "blocking": 0,
                "warning": 0,
                "suppressed": 0,
            }
            assert payload["policy_findings"] == []
        elif decision == "warn":
            assert policy_summary["blocking"] == 0
            assert policy_summary["warning"] > 0
            assert all(finding["level"] == "warn" for finding in payload["policy_findings"])
        else:
            assert policy_summary["blocking"] > 0
            assert any(finding["level"] == "block" for finding in payload["policy_findings"])


def test_needs_review_is_consumer_interpretation_not_runtime_status() -> None:
    payload = _read_example("needs-review.json")

    assert payload["review_decision"] == "needs-review"
    assert payload["decision_source"] == "consumer_interpretation"
    assert "policy" not in payload["summary"]
    assert payload["review_decision"] not in RUNTIME_POLICY_STATUSES
    assert "not a runtime summary.policy.status value" in payload["reviewer_interpretation"]["non_claims"]


def _read_example(filename: str) -> dict[str, object]:
    return json.loads((EXAMPLES_DIR / filename).read_text(encoding="utf-8"))
