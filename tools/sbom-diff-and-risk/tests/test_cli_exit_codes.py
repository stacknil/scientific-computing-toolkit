from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_cli_exit_code_blocking_policy(tmp_path: Path) -> None:
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


def _run_compare(project_root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sbom_diff_risk.cli", "compare", *args],
        cwd=project_root,
        text=True,
        capture_output=True,
    )
