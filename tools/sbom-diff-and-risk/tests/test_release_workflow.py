from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "sbom-diff-and-risk-ci.yml"
RELEASE_NOTES = REPO_ROOT / "tools" / "sbom-diff-and-risk" / "RELEASE_NOTES_v1.0-rc.1.md"


def test_release_workflow_marks_rc_tags_as_prereleases() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    publish_steps = workflow["jobs"]["publish-release-assets"]["steps"]
    publish_script = publish_steps[-1]["run"]

    assert RELEASE_NOTES.is_file()
    assert "RELEASE_NOTES_${RELEASE_TAG}.md" in publish_script
    assert '"${RELEASE_TAG}" == *"rc"*' in publish_script
    assert "create_args+=(--prerelease --latest=false)" in publish_script
    assert "edit_args+=(--prerelease)" in publish_script
    assert "notes_args=(--notes-file" in publish_script
    assert "edit_args+=(--notes-file" in publish_script
