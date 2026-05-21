from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class ExampleArtifactSet:
    name: str
    base_args: tuple[str, ...]
    outputs: tuple[tuple[str, str], ...]
    expected_exit_codes: tuple[int, ...] = (0,)


ARTIFACT_SETS: tuple[ExampleArtifactSet, ...] = (
    ExampleArtifactSet(
        name="cyclonedx report, summary, and markdown",
        base_args=(
            "--before",
            "examples/cdx_before.json",
            "--after",
            "examples/cdx_after.json",
            "--format",
            "auto",
        ),
        outputs=(
            ("--out-json", "sample-report.json"),
            ("--summary-json", "sample-summary.json"),
            ("--out-md", "sample-report.md"),
        ),
    ),
    ExampleArtifactSet(
        name="warn-only policy report",
        base_args=(
            "--before",
            "examples/cdx_before.json",
            "--after",
            "examples/cdx_after.json",
            "--policy",
            "examples/policy-minimal.yml",
        ),
        outputs=(
            ("--out-json", "sample-policy-warn-report.json"),
            ("--out-md", "sample-policy-warn-report.md"),
        ),
    ),
    ExampleArtifactSet(
        name="blocking policy report and sidecar",
        base_args=(
            "--before",
            "examples/cdx_before.json",
            "--after",
            "examples/cdx_after.json",
            "--policy",
            "examples/policy-strict.yml",
        ),
        outputs=(
            ("--out-json", "sample-policy-fail-report.json"),
            ("--policy-json", "sample-policy.json"),
            ("--out-md", "sample-policy-fail-report.md"),
        ),
        expected_exit_codes=(1,),
    ),
    ExampleArtifactSet(
        name="requirements report",
        base_args=(
            "--before",
            "examples/requirements_before.txt",
            "--after",
            "examples/requirements_after.txt",
            "--format",
            "auto",
        ),
        outputs=(
            ("--out-json", "sample-requirements-report.json"),
            ("--out-md", "sample-requirements-report.md"),
        ),
    ),
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate checked-in no-network example report artifacts.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Generate artifacts into a temporary directory and fail if checked-in examples are stale.",
    )
    args = parser.parse_args(argv)

    project_root = Path(__file__).resolve().parents[1]
    if args.check:
        with tempfile.TemporaryDirectory(prefix="sbom-diff-risk-examples-") as temp_dir:
            return _check_artifacts(project_root, Path(temp_dir))
    return _write_artifacts(project_root, project_root / "examples")


def _write_artifacts(project_root: Path, output_root: Path) -> int:
    for artifact_set in ARTIFACT_SETS:
        _run_artifact_set(project_root, output_root, artifact_set)
        print(f"generated: {artifact_set.name}")
    return 0


def _check_artifacts(project_root: Path, output_root: Path) -> int:
    _write_artifacts(project_root, output_root)

    examples_dir = project_root / "examples"
    stale_files: list[str] = []
    for artifact_set in ARTIFACT_SETS:
        for _, output_name in artifact_set.outputs:
            expected = (examples_dir / output_name).read_text(encoding="utf-8")
            generated = (output_root / output_name).read_text(encoding="utf-8")
            if generated != expected:
                stale_files.append(output_name)

    if stale_files:
        print("stale example artifacts detected:", file=sys.stderr)
        for name in stale_files:
            print(f"  {name}", file=sys.stderr)
        print("run scripts/regenerate-example-artifacts.py and commit the updated files.", file=sys.stderr)
        return 1

    print("all checked example artifacts are up to date")
    return 0


def _run_artifact_set(project_root: Path, output_root: Path, artifact_set: ExampleArtifactSet) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "sbom_diff_risk.cli", "compare", *artifact_set.base_args]
    for flag, output_name in artifact_set.outputs:
        command.extend([flag, str(output_root / output_name)])

    env = dict(os.environ)
    src_path = str(project_root / "src")
    env["PYTHONPATH"] = src_path if not env.get("PYTHONPATH") else f"{src_path}{os.pathsep}{env['PYTHONPATH']}"

    result = subprocess.run(
        command,
        cwd=project_root,
        text=True,
        capture_output=True,
        env=env,
    )
    if result.returncode not in artifact_set.expected_exit_codes:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(
            f"{artifact_set.name} exited with {result.returncode}; "
            f"expected {artifact_set.expected_exit_codes}: {detail}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
