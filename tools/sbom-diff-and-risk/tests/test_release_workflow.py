from __future__ import annotations

import json
from pathlib import Path
import tomllib

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "sbom-diff-and-risk-ci.yml"
RELEASE_NOTES = REPO_ROOT / "tools" / "sbom-diff-and-risk" / "RELEASE_NOTES_v1.0-rc.1.md"
FINAL_RELEASE_NOTES = REPO_ROOT / "tools" / "sbom-diff-and-risk" / "RELEASE_NOTES_v1.0.0.md"
V1_1_RELEASE_NOTES = REPO_ROOT / "tools" / "sbom-diff-and-risk" / "RELEASE_NOTES_v1.1.0.md"
PYPROJECT = REPO_ROOT / "tools" / "sbom-diff-and-risk" / "pyproject.toml"
PACKAGE_INIT = REPO_ROOT / "tools" / "sbom-diff-and-risk" / "src" / "sbom_diff_risk" / "__init__.py"
ROOT_README = REPO_ROOT / "README.md"
TOOL_README = REPO_ROOT / "tools" / "sbom-diff-and-risk" / "README.md"
EXAMPLES = REPO_ROOT / "tools" / "sbom-diff-and-risk" / "examples"


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


def test_release_workflow_marks_final_tags_as_latest() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    publish_steps = workflow["jobs"]["publish-release-assets"]["steps"]
    publish_script = publish_steps[-1]["run"]

    assert FINAL_RELEASE_NOTES.is_file()
    assert "else" in publish_script
    assert "create_args+=(--latest)" in publish_script
    assert "edit_args+=(--latest)" in publish_script


def test_release_workflow_normalizes_build_timestamps_before_checksums() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    epoch_index = text.index("SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)")
    build_index = text.index("python -m build", epoch_index)
    normalize_index = text.index("python scripts/normalize_sdist.py", build_index)
    checksum_index = text.index("Generate SHA256 checksum manifest", normalize_index)

    assert epoch_index < build_index < normalize_index < checksum_index


def test_main_release_metadata_and_v1_stable_status_are_aligned() -> None:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    package_init = PACKAGE_INIT.read_text(encoding="utf-8")
    root_readme = ROOT_README.read_text(encoding="utf-8")
    tool_readme = TOOL_README.read_text(encoding="utf-8")

    assert project["version"] == "1.1.0"
    assert "authors" not in project
    assert '__version__ = "1.1.0"' in package_init
    assert "Current stable flagship release: `sbom-diff-and-risk` `v1.1.0`" in root_readme
    assert "`v1.1.0` is the stable Policy Evidence GitHub release" in tool_readme
    assert "final candidate" not in root_readme
    assert "final candidate" not in tool_readme


def test_v1_release_notes_capture_rc_compatibility_boundary() -> None:
    text = FINAL_RELEASE_NOTES.read_text(encoding="utf-8")

    assert "v1.0-rc.1 to v1.0.0 compatibility" in text
    assert "CLI commands and flags are unchanged" in text
    assert "enrichment_recorded" in text
    assert "scorecard_recorded" in text
    assert "sdr.new_package" in text
    assert "Production PyPI publishing remains deferred" in text


def test_v1_1_release_notes_capture_identity_and_contract_boundaries() -> None:
    text = V1_1_RELEASE_NOTES.read_text(encoding="utf-8")

    assert "# sbom-diff-and-risk v1.1.0" in text
    assert "input and policy contract versioning" in text
    assert "policy decision explainability" in text
    assert "canonical component identity" in text
    assert "opaque local identifier" in text
    assert "Production PyPI publishing remains intentionally deferred" in text


def test_main_sarif_golden_fixtures_use_release_version() -> None:
    fixtures = sorted(EXAMPLES.glob("sample-*.sarif"))

    assert fixtures
    for fixture in fixtures:
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        driver = payload["runs"][0]["tool"]["driver"]
        assert driver["version"] == "1.1.0", fixture.name
        assert driver["semanticVersion"] == "1.1.0", fixture.name
