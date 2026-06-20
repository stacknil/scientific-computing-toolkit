from __future__ import annotations

from pathlib import Path

import yaml

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
POLICY_CONSUMER = EXAMPLES / "github-actions-policy-consumer.yml"


def test_only_minimal_github_actions_policy_consumer_is_checked_in() -> None:
    workflow_examples = sorted(
        path.name for path in EXAMPLES.glob("github-actions*consumer.yml")
    )

    assert workflow_examples == ["github-actions-policy-consumer.yml"]


def test_policy_consumer_uploads_policy_json_before_enforcing_exit_code() -> None:
    text = POLICY_CONSUMER.read_text(encoding="utf-8")
    payload = yaml.safe_load(text)

    assert payload["name"] == "Dependency policy review"

    steps = payload["jobs"]["dependency-policy"]["steps"]
    step_names = [step["name"] for step in steps]

    assert step_names == [
        "Check out consumer repository",
        "Set up Python",
        "Download sbom-diff-and-risk release wheel",
        "Install sbom-diff-risk",
        "Run dependency policy",
        "Upload policy JSON",
        "Pass or fail based on local policy",
    ]
    assert "--policy-json outputs/policy.json" in text
    assert "--summary-json" not in text
    assert "--out-json" not in text
    assert "--out-md" not in text
    assert "--out-sarif" not in text
    assert "tee " not in text

    run_index = step_names.index("Run dependency policy")
    upload_index = step_names.index("Upload policy JSON")
    enforce_index = step_names.index("Pass or fail based on local policy")

    assert run_index < upload_index < enforce_index
    assert steps[upload_index]["if"] == "always()"
    assert steps[upload_index]["with"]["path"] == "outputs/policy.json"
    assert steps[upload_index]["with"]["if-no-files-found"] == "error"
    assert steps[enforce_index]["run"] == 'exit "${{ steps.compare.outputs.exit_code }}"'
