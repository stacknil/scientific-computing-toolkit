from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class ExampleArtifactSet:
    slug: str
    name: str
    base_args: tuple[str, ...]
    outputs: tuple[tuple[str, str], ...]
    expected_exit_codes: tuple[int, ...] = (0,)
    normalize_sarif_srcroot: bool = False


ARTIFACT_SETS: tuple[ExampleArtifactSet, ...] = (
    ExampleArtifactSet(
        slug="cyclonedx",
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
        slug="policy-warn",
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
        slug="policy-fail",
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
        slug="requirements",
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
    ExampleArtifactSet(
        slug="sarif",
        name="strict-policy SARIF report",
        base_args=(
            "--before",
            "examples/sarif_before.json",
            "--after",
            "examples/sarif_after.json",
            "--policy",
            "examples/policy-strict.yml",
        ),
        outputs=(
            ("--out-sarif", "sample-sarif.sarif"),
        ),
        expected_exit_codes=(1,),
        normalize_sarif_srcroot=True,
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
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available artifact set slugs and exit.",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="SLUG",
        help="Regenerate or check only one artifact set slug. Repeat to select multiple sets.",
    )
    args = parser.parse_args(argv)

    project_root = Path(__file__).resolve().parents[1]
    artifact_sets = _select_artifact_sets(args.only, parser)
    if args.list:
        _print_artifact_sets(artifact_sets)
        return 0
    if args.check:
        with tempfile.TemporaryDirectory(prefix="sbom-diff-risk-examples-") as temp_dir:
            return _check_artifacts(project_root, Path(temp_dir), artifact_sets)
    return _write_artifacts(project_root, project_root / "examples", artifact_sets)


def _select_artifact_sets(
    selected_slugs: Sequence[str],
    parser: argparse.ArgumentParser,
) -> tuple[ExampleArtifactSet, ...]:
    if not selected_slugs:
        return ARTIFACT_SETS

    by_slug = {artifact_set.slug: artifact_set for artifact_set in ARTIFACT_SETS}
    unknown = [slug for slug in selected_slugs if slug not in by_slug]
    if unknown:
        parser.error(f"unknown artifact set slug: {unknown[0]}")

    return tuple(by_slug[slug] for slug in selected_slugs)


def _print_artifact_sets(artifact_sets: Sequence[ExampleArtifactSet]) -> None:
    for artifact_set in artifact_sets:
        outputs = ", ".join(output_name for _, output_name in artifact_set.outputs)
        print(f"{artifact_set.slug}: {artifact_set.name} ({outputs})")


def _write_artifacts(
    project_root: Path,
    output_root: Path,
    artifact_sets: Sequence[ExampleArtifactSet],
) -> int:
    for artifact_set in artifact_sets:
        _run_artifact_set(project_root, output_root, artifact_set)
        print(f"generated: {artifact_set.slug}")
    return 0


def _check_artifacts(
    project_root: Path,
    output_root: Path,
    artifact_sets: Sequence[ExampleArtifactSet],
) -> int:
    _write_artifacts(project_root, output_root, artifact_sets)

    examples_dir = project_root / "examples"
    stale_files: list[str] = []
    for artifact_set in artifact_sets:
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
    if artifact_set.normalize_sarif_srcroot:
        _normalize_sarif_srcroot(output_root / artifact_set.outputs[0][1])


def _normalize_sarif_srcroot(path: Path) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]["uri"] = "file:///__PROJECT_ROOT__/"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
