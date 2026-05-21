from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_regenerate_example_artifacts_check_mode_passes() -> None:
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            str(project_root / "scripts" / "regenerate-example-artifacts.py"),
            "--check",
        ],
        cwd=project_root,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "all checked example artifacts are up to date" in result.stdout


def test_regenerate_example_artifacts_can_list_artifact_sets() -> None:
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            str(project_root / "scripts" / "regenerate-example-artifacts.py"),
            "--list",
        ],
        cwd=project_root,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "cyclonedx:" in result.stdout
    assert "requirements:" in result.stdout
    assert "sarif:" in result.stdout


def test_regenerate_example_artifacts_can_check_one_artifact_set() -> None:
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            str(project_root / "scripts" / "regenerate-example-artifacts.py"),
            "--check",
            "--only",
            "requirements",
        ],
        cwd=project_root,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "generated: requirements" in result.stdout
    assert "generated: cyclonedx" not in result.stdout
