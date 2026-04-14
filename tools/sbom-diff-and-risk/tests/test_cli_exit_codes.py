from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_cli_exit_code_blocking_policy_stderr_summary(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    policy_path = project_root / "examples" / "policy-strict.yml"
    before = project_root / "examples" / "cdx_before.json"
    after = project_root / "examples" / "cdx_after.json"

    result = _run_compare(
        project_root,
        [
            "--before",
            str(before),
            "--after",
            str(after),
            "--policy",
            str(policy_path),
            "--out-json",
            str(tmp_path / "report.json"),
            "--out-md",
            str(tmp_path / "report.md"),
        ],
    )

    assert result.returncode == 1
    assert "blocking policy violations detected" in result.stderr
    assert "stale_package" in result.stderr
    assert "outputs were written" in result.stderr


def test_cli_exit_code_warn_only_policy(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    policy_path = project_root / "examples" / "policy-minimal.yml"
    before = project_root / "examples" / "cdx_before.json"
    after = project_root / "examples" / "cdx_after.json"

    result = _run_compare(
        project_root,
        [
            "--before",
            str(before),
            "--after",
            str(after),
            "--policy",
            str(policy_path),
            "--out-json",
            str(tmp_path / "report.json"),
            "--out-md",
            str(tmp_path / "report.md"),
        ],
    )

    assert result.returncode == 0
    assert "blocking policy violations detected" not in result.stderr


def test_cli_exit_code_invalid_policy_schema(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    before = project_root / "examples" / "cdx_before.json"
    after = project_root / "examples" / "cdx_after.json"
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text("version: 1\nunknown_key: true\n", encoding="utf-8")

    result = _run_compare(
        project_root,
        [
            "--before",
            str(before),
            "--after",
            str(after),
            "--policy",
            str(policy_path),
            "--out-json",
            str(tmp_path / "report.json"),
        ],
    )

    assert result.returncode == 2
    assert "Invalid policy schema" in result.stderr
    assert "exit code 2" in result.stderr


def test_cli_fail_on_flag_blocks(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    before = project_root / "examples" / "cdx_before.json"
    after = project_root / "examples" / "cdx_after.json"

    result = _run_compare(
        project_root,
        [
            "--before",
            str(before),
            "--after",
            str(after),
            "--fail-on",
            "new_package",
            "--warn-on",
            "major_upgrade",
            "--out-json",
            str(tmp_path / "report.json"),
        ],
    )

    assert result.returncode == 1
    assert "new_package" in result.stderr


def test_cli_compare_help_mentions_policy_flags_and_exit_codes() -> None:
    project_root = Path(__file__).resolve().parents[1]

    result = _run_compare(project_root, ["--help"])

    assert result.returncode == 0
    assert "--out-sarif" in result.stdout
    assert "--pyproject-group" in result.stdout
    assert "--policy" in result.stdout
    assert "--fail-on" in result.stdout
    assert "--warn-on" in result.stdout
    assert "--strict" in result.stdout
    assert "Exit codes: 0 = success/no blocking violations" in result.stdout


def test_cli_can_write_sarif_only(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    before = project_root / "examples" / "sarif_before.json"
    after = project_root / "examples" / "sarif_after.json"

    result = _run_compare(
        project_root,
        [
            "--before",
            str(before),
            "--after",
            str(after),
            "--policy",
            str(project_root / "examples" / "policy-strict.yml"),
            "--out-sarif",
            str(tmp_path / "report.sarif"),
        ],
    )

    assert result.returncode == 1
    assert (tmp_path / "report.sarif").is_file()


def test_cli_pyproject_group_selection_smoke(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    before = project_root / "examples" / "pyproject_groups_before.toml"
    after = project_root / "examples" / "pyproject_groups_after.toml"

    result = _run_compare(
        project_root,
        [
            "--before",
            str(before),
            "--after",
            str(after),
            "--format",
            "pyproject-toml",
            "--pyproject-group",
            "dev",
            "--out-json",
            str(tmp_path / "report.json"),
        ],
    )

    assert result.returncode == 0
    assert (tmp_path / "report.json").is_file()


def test_cli_pyproject_group_missing_fails_clearly(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    before = project_root / "examples" / "pyproject_groups_before.toml"
    after = project_root / "examples" / "pyproject_groups_after.toml"

    result = _run_compare(
        project_root,
        [
            "--before",
            str(before),
            "--after",
            str(after),
            "--format",
            "pyproject-toml",
            "--pyproject-group",
            "docs",
            "--out-json",
            str(tmp_path / "report.json"),
        ],
    )

    assert result.returncode == 2
    assert "Requested dependency group" in result.stderr
    assert "distinct from [project.optional-dependencies]" in result.stderr


def test_cli_pyproject_group_requires_pyproject_input(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    before = project_root / "examples" / "requirements_before.txt"
    after = project_root / "examples" / "requirements_after.txt"

    result = _run_compare(
        project_root,
        [
            "--before",
            str(before),
            "--after",
            str(after),
            "--pyproject-group",
            "dev",
            "--out-json",
            str(tmp_path / "report.json"),
        ],
    )

    assert result.returncode == 2
    assert "--pyproject-group requires at least one pyproject.toml input" in result.stderr


def _run_compare(project_root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    source_path = str(project_root / "src")
    env["PYTHONPATH"] = source_path if not env.get("PYTHONPATH") else f"{source_path}{os.pathsep}{env['PYTHONPATH']}"
    return subprocess.run(
        [sys.executable, "-m", "sbom_diff_risk.cli", "compare", *args],
        cwd=project_root,
        text=True,
        capture_output=True,
        env=env,
    )
