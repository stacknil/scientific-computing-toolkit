from __future__ import annotations

from fnmatch import fnmatchcase
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote


REPO_ROOT = Path(__file__).resolve().parents[1]

DOCS_TO_VALIDATE = (
    Path("README.md"),
    Path("docs/reviewer-brief.md"),
    Path("docs/repo-scope-map.md"),
    Path("docs/why-scientific-computing-background-helps.md"),
    Path("docs/risk-model-boundary.md"),
    Path("tools/sbom-diff-and-risk/docs/report-schema.md"),
    Path("tools/sbom-diff-and-risk/docs/github-actions-consumer-example.md"),
    Path("tools/sbom-diff-and-risk/docs/reviewer-path.md"),
    Path("projects/precipitation-anomaly-diagnostics/docs/reviewer-path.md"),
    Path("projects/precipitation-anomaly-diagnostics-lab/docs/reviewer-path.md"),
    Path("projects/python-weather-diagnostics-toolkit/docs/reviewer-path.md"),
)

REVIEWER_SURFACE_ROOTS = (
    Path("README.md"),
    Path("docs"),
    Path("tools/sbom-diff-and-risk"),
    Path("projects"),
)

WORKFLOW_PATH = Path(".github/workflows/reviewer-route-contract-ci.yml")
WORKFLOW_EVENTS_WITH_PATH_FILTERS = ("push", "pull_request")
REQUIRED_WORKFLOW_PATH_FILTERS = (
    ".github/workflows/reviewer-route-contract-ci.yml",
    "README.md",
    "docs/**",
    "projects/**",
    "scripts/validate-reviewer-routes.py",
    "tools/sbom-diff-and-risk/*.md",
    "tools/sbom-diff-and-risk/docs/**",
    "tools/sbom-diff-and-risk/examples/**",
)

REQUIRED_LINK_TARGETS = {
    Path("README.md"): {
        "docs/reviewer-brief.md",
        "docs/repo-scope-map.md",
        "docs/why-scientific-computing-background-helps.md",
        "docs/risk-model-boundary.md",
        "tools/sbom-diff-and-risk/docs/reviewer-path.md",
        "tools/sbom-diff-and-risk/docs/reviewer-evidence-pack.md",
        "projects/precipitation-anomaly-diagnostics/docs/reviewer-path.md",
        "projects/precipitation-anomaly-diagnostics-lab/docs/reviewer-path.md",
        "projects/python-weather-diagnostics-toolkit/docs/reviewer-path.md",
    },
    Path("docs/reviewer-brief.md"): {
        "README.md",
        "docs/repo-scope-map.md",
        "docs/why-scientific-computing-background-helps.md",
        "docs/risk-model-boundary.md",
        "tools/sbom-diff-and-risk/docs/reviewer-path.md",
        "tools/sbom-diff-and-risk/docs/example-artifact-regeneration.md",
        "projects/precipitation-anomaly-diagnostics/docs/reviewer-path.md",
        "projects/precipitation-anomaly-diagnostics-lab/docs/reviewer-path.md",
        "projects/python-weather-diagnostics-toolkit/docs/reviewer-path.md",
    },
    Path("docs/repo-scope-map.md"): set(),
    Path("docs/why-scientific-computing-background-helps.md"): set(),
    Path("docs/risk-model-boundary.md"): {
        "tools/sbom-diff-and-risk/docs/dependency-risk-heuristics.md",
        "tools/sbom-diff-and-risk/src/sbom_diff_risk/diffing.py",
        "tools/sbom-diff-and-risk/src/sbom_diff_risk/models.py",
        "tools/sbom-diff-and-risk/src/sbom_diff_risk/risk.py",
    },
    Path("tools/sbom-diff-and-risk/docs/report-schema.md"): {
        "tools/sbom-diff-and-risk/docs/policy-decision-ci-cookbook.md",
        "tools/sbom-diff-and-risk/docs/policy-decision-explainability.md",
        "tools/sbom-diff-and-risk/docs/summary-json-ci-cookbook.md",
        "tools/sbom-diff-and-risk/examples/sample-report.json",
        "tools/sbom-diff-and-risk/examples/sample-summary.json",
    },
    Path("tools/sbom-diff-and-risk/docs/github-actions-consumer-example.md"): {
        "tools/sbom-diff-and-risk/docs/policy-decision-ci-cookbook.md",
        "tools/sbom-diff-and-risk/examples/github-actions-policy-consumer.yml",
    },
    Path("tools/sbom-diff-and-risk/docs/reviewer-path.md"): {
        ".github/workflows/reviewer-route-contract-ci.yml",
        "docs/risk-model-boundary.md",
        "scripts/validate-reviewer-routes.py",
        "tools/sbom-diff-and-risk/examples/github-actions-policy-consumer.yml",
        "tools/sbom-diff-and-risk/docs/reviewer-brief.md",
        "tools/sbom-diff-and-risk/docs/reviewer-evidence-pack.md",
        "tools/sbom-diff-and-risk/docs/verification.md",
        "tools/sbom-diff-and-risk/examples/policy-decisions/README.md",
        "tools/sbom-diff-and-risk/examples/sample-report.json",
        "tools/sbom-diff-and-risk/examples/sample-summary.json",
        "tools/sbom-diff-and-risk/examples/sample-policy.json",
        "tools/sbom-diff-and-risk/examples/sample-sarif.sarif",
    },
    Path("projects/precipitation-anomaly-diagnostics/docs/reviewer-path.md"): {
        "projects/precipitation-anomaly-diagnostics/README.md",
        "projects/precipitation-anomaly-diagnostics/docs/data-policy.md",
        "projects/precipitation-anomaly-diagnostics/docs/inference-framework.md",
        "projects/precipitation-anomaly-diagnostics/docs/methodology.md",
        "projects/precipitation-anomaly-diagnostics/examples/sample_metadata.json",
        "projects/precipitation-anomaly-diagnostics/PUBLICATION_BOUNDARIES.md",
        "projects/precipitation-anomaly-diagnostics/reports/example-report.md",
    },
    Path("projects/precipitation-anomaly-diagnostics-lab/docs/reviewer-path.md"): {
        "projects/precipitation-anomaly-diagnostics-lab/README.md",
        "projects/precipitation-anomaly-diagnostics-lab/docs/calculation-methods.md",
        "projects/precipitation-anomaly-diagnostics-lab/docs/data-policy.md",
        "projects/precipitation-anomaly-diagnostics-lab/docs/inference-analysis.md",
        "projects/precipitation-anomaly-diagnostics-lab/docs/methodology.md",
        "projects/precipitation-anomaly-diagnostics-lab/docs/reproducibility.md",
        "projects/precipitation-anomaly-diagnostics-lab/examples/synthetic-inference-report.md",
        "projects/precipitation-anomaly-diagnostics-lab/examples/generate_synthetic_demo_assets.py",
        "projects/precipitation-anomaly-diagnostics-lab/scripts/run_composite_circulation.py",
        "projects/precipitation-anomaly-diagnostics-lab/scripts/run_eof.py",
        "projects/precipitation-anomaly-diagnostics-lab/scripts/run_index_correlations.py",
        "projects/precipitation-anomaly-diagnostics-lab/scripts/run_lag_diagnostics.py",
        "projects/precipitation-anomaly-diagnostics-lab/scripts/run_mca.py",
        "projects/precipitation-anomaly-diagnostics-lab/scripts/run_precipitation_anomalies.py",
        "projects/precipitation-anomaly-diagnostics-lab/scripts/run_regression.py",
        "projects/precipitation-anomaly-diagnostics-lab/scripts/run_trend_diagnostics.py",
        "projects/precipitation-anomaly-diagnostics-lab/src/climate_diagnostics/config.py",
        "projects/precipitation-anomaly-diagnostics-lab/src/climate_diagnostics/grids.py",
        "projects/precipitation-anomaly-diagnostics-lab/src/climate_diagnostics/io.py",
        "projects/precipitation-anomaly-diagnostics-lab/src/climate_diagnostics/plotting.py",
        "projects/precipitation-anomaly-diagnostics-lab/src/climate_diagnostics/statistics.py",
        "projects/precipitation-anomaly-diagnostics-lab/SANITIZATION_REPORT.md",
    },
    Path("projects/python-weather-diagnostics-toolkit/docs/reviewer-path.md"): {
        "projects/python-weather-diagnostics-toolkit/README.md",
        "projects/python-weather-diagnostics-toolkit/docs/calculation-methods.md",
        "projects/python-weather-diagnostics-toolkit/docs/climate-statistical-diagnostics.md",
        "projects/python-weather-diagnostics-toolkit/docs/data-policy.md",
        "projects/python-weather-diagnostics-toolkit/docs/diagnostic-analysis.md",
        "projects/python-weather-diagnostics-toolkit/docs/focused-case-abstraction.md",
        "projects/python-weather-diagnostics-toolkit/docs/methodology.md",
        "projects/python-weather-diagnostics-toolkit/docs/source-to-public-mapping.md",
        "projects/python-weather-diagnostics-toolkit/docs/station-precipitation-workflows.md",
        "projects/python-weather-diagnostics-toolkit/examples/sample_metadata.json",
        "projects/python-weather-diagnostics-toolkit/examples/synthetic-weather-diagnostics-report.md",
        "projects/python-weather-diagnostics-toolkit/PUBLICATION_BOUNDARIES.md",
        "projects/python-weather-diagnostics-toolkit/SANITIZATION_REPORT.md",
    },
}

REQUIRED_TEXT = {
    Path("README.md"): (
        "current flagship tool",
        "not part of the `sbom-diff-and-risk` release surface",
        "why the scientific-computing background helps",
        "Production PyPI publishing: intentionally deferred",
    ),
    Path("docs/reviewer-brief.md"): (
        "The current flagship project is",
        "supporting diagnostics projects",
        "scientific-computing background note",
        "production PyPI publishing remains intentionally deferred",
    ),
    Path("docs/repo-scope-map.md"): (
        "Flagship",
        "sbom-diff-and-risk",
        "Supporting diagnostics",
        "precipitation-anomaly-diagnostics",
        "precipitation-anomaly-diagnostics-lab",
        "python-weather-diagnostics-toolkit",
        "What this repo does not claim",
        "not a climate portfolio",
        "not a vulnerability scanner",
        "not a CVE resolver",
        "not a production PyPI release claim",
    ),
    Path("docs/why-scientific-computing-background-helps.md"): (
        "Reproducibility",
        "Data Pipeline",
        "Uncertainty Boundary",
        "not a domain identity claim",
        "not a reason to expand repository scope",
        "checked-in fixtures instead of private source material",
        "Each stage should have a clear input and output.",
        "missing evidence should stay visible as missing evidence",
        "not a package safety verdict",
        "Do not use it as a reason to add unrelated project surfaces",
    ),
    Path("docs/risk-model-boundary.md"): (
        "Fields that affect risk classification",
        "Context-only fields",
        "Never inferred",
        "not a vulnerability scanner",
        "not a CVE resolver",
        "not a dependency safety verdict",
        "Not a CVE scanner",
        "Not a malware scanner",
        "Not a package safety verdict engine",
        "new_package",
        "major_upgrade",
        "version_change_unclassified",
        "unknown_license",
        "stale_package",
        "suspicious_source",
        "not_evaluated",
    ),
    Path("tools/sbom-diff-and-risk/docs/report-schema.md"): (
        "evidence_confidence",
        "local_manifest_only",
        "sbom_present",
        "policy_matched",
        "enrichment_recorded",
        "provenance_recorded",
        "not a package safety verdict",
        "not a CVE result",
    ),
    Path("tools/sbom-diff-and-risk/docs/github-actions-consumer-example.md"): (
        "minimal GitHub Actions consumer workflow",
        "outputs/policy.json",
        "Upload policy JSON",
        "Pass or fail based on local policy",
        "tool's own exit code",
        "not a CVE scanner",
        "not a dependency safety oracle",
    ),
    Path("tools/sbom-diff-and-risk/docs/reviewer-path.md"): (
        "Artifact evidence map",
        "Reviewer route contract",
        "Reviewer outcome statements",
        "What can I safely say in review?",
        "Your summary separates verified evidence from non-claims.",
        "Do not write:",
        "Markdown links across the reviewer surface resolve",
        "workflow path filters cover reviewer-surface changes",
        "every tracked reviewer-surface Markdown file is covered",
        "python scripts/validate-reviewer-routes.py",
        "No network",
        "summary.evidence_confidence",
        "runs the tool, uploads `policy.json`, and fails or passes from the policy exit code",
        "not current PyPI package truth",
        "not current repository reputation",
        "It does not decide whether a dependency is safe.",
    ),
    Path("projects/precipitation-anomaly-diagnostics/docs/reviewer-path.md"): (
        "supporting scientific-data project inside `scientific-computing-toolkit`",
        "not part of the `sbom-diff-and-risk` release surface",
        "not a separate meteorology portfolio",
        "This review does not require raw climate datasets.",
    ),
    Path("projects/precipitation-anomaly-diagnostics-lab/docs/reviewer-path.md"): (
        "supporting scientific-data project inside `scientific-computing-toolkit`",
        "not part of the `sbom-diff-and-risk` release surface",
        "not a separate meteorology portfolio",
        "without requiring raw climate datasets or private local materials",
        "does not claim causal attribution",
    ),
    Path("projects/python-weather-diagnostics-toolkit/docs/reviewer-path.md"): (
        "supporting atmospheric diagnostics module",
        "not part of the `sbom-diff-and-risk` release surface",
        "not a separate meteorology portfolio",
        "not a public redistribution of raw weather data or course material",
    ),
}

FORBIDDEN_TEXT = {
    Path("docs/why-scientific-computing-background-helps.md"): (
        "meteorology",
        "weather",
        "climate",
        "atmospheric",
        "precipitation",
    ),
}

REQUIRED_REVIEWER_PATHS = (
    Path("tools/sbom-diff-and-risk/docs/reviewer-path.md"),
    Path("projects/precipitation-anomaly-diagnostics/docs/reviewer-path.md"),
    Path("projects/precipitation-anomaly-diagnostics-lab/docs/reviewer-path.md"),
    Path("projects/python-weather-diagnostics-toolkit/docs/reviewer-path.md"),
)

SUPPORTING_PROJECT_BOUNDARIES = {
    Path("projects/precipitation-anomaly-diagnostics"): (
        "README.md",
        "PUBLICATION_BOUNDARIES.md",
        "SANITIZATION_REPORT.md",
        "docs/data-policy.md",
    ),
    Path("projects/precipitation-anomaly-diagnostics-lab"): (
        "README.md",
        "SANITIZATION_REPORT.md",
        "docs/data-policy.md",
    ),
    Path("projects/python-weather-diagnostics-toolkit"): (
        "README.md",
        "PUBLICATION_BOUNDARIES.md",
        "SANITIZATION_REPORT.md",
        "docs/data-policy.md",
        "docs/source-to-public-mapping.md",
    ),
}

INLINE_LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
REFERENCE_LINK_RE = re.compile(r"^\[[^\]]+\]:\s+(\S+)", re.MULTILINE)
URI_RE = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
WHITESPACE_RE = re.compile(r"\s+")
HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
HTML_TAG_RE = re.compile(r"<[^>]+>")
SLUG_PUNCTUATION_RE = re.compile(r"[^\w\s-]")


def repo_relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def read_markdown(path: Path) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def normalized_text(text: str) -> str:
    return WHITESPACE_RE.sub(" ", text)


def split_link_target(raw_target: str) -> tuple[str, str | None] | None:
    target = raw_target.strip()
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")]
    else:
        target = target.split()[0]

    target = unquote(target)
    if not target or URI_RE.match(target):
        return None

    path_part, separator, anchor = target.partition("#")
    return path_part, anchor if separator else None


def local_link_target(markdown_path: Path, raw_target: str) -> Path | None:
    parsed_target = split_link_target(raw_target)
    if parsed_target is None:
        return None

    path_part, _anchor = parsed_target
    if not path_part:
        return (REPO_ROOT / markdown_path).resolve()

    return (REPO_ROOT / markdown_path.parent / path_part).resolve()


def local_link_anchor(raw_target: str) -> str | None:
    parsed_target = split_link_target(raw_target)
    if parsed_target is None:
        return None

    _path_part, anchor = parsed_target
    return anchor


def heading_slug(heading: str) -> str:
    text = heading.strip().strip("#").strip()
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = HTML_TAG_RE.sub("", text)
    text = SLUG_PUNCTUATION_RE.sub("", text.lower())
    return WHITESPACE_RE.sub("-", text.strip())


def markdown_anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    anchors: set[str] = set()
    seen: dict[str, int] = {}

    for line in text.splitlines():
        match = HEADING_RE.match(line)
        if not match:
            continue

        slug = heading_slug(match.group(1))
        if not slug:
            continue

        count = seen.get(slug, 0)
        seen[slug] = count + 1
        anchors.add(slug if count == 0 else f"{slug}-{count}")

    return anchors


def iter_reviewer_surface_markdown(errors: list[str]) -> tuple[Path, ...]:
    markdown_paths: list[Path] = []
    seen: set[Path] = set()

    for root in REVIEWER_SURFACE_ROOTS:
        absolute_root = REPO_ROOT / root
        if not absolute_root.exists():
            errors.append(f"missing reviewer surface root: {root.as_posix()}")

    tracked_paths = subprocess.run(
        [
            "git",
            "-C",
            str(REPO_ROOT),
            "ls-files",
            "--",
            *(root.as_posix() for root in REVIEWER_SURFACE_ROOTS),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if tracked_paths.returncode != 0:
        errors.append(
            "failed to list tracked reviewer surface files: "
            f"{tracked_paths.stderr.strip()}"
        )
        return tuple()

    for raw_path in tracked_paths.stdout.splitlines():
        relative_path = Path(raw_path)
        if relative_path.suffix.lower() != ".md":
            continue

        if relative_path in seen:
            continue

        seen.add(relative_path)
        markdown_paths.append(relative_path)

    return tuple(markdown_paths)


def workflow_path_filters(workflow_path: Path, event_name: str, errors: list[str]) -> set[str]:
    absolute_path = REPO_ROOT / workflow_path
    if not absolute_path.is_file():
        errors.append(f"missing reviewer route workflow: {workflow_path.as_posix()}")
        return set()

    filters: set[str] = set()
    in_event = False
    in_paths = False

    for line in absolute_path.read_text(encoding="utf-8").splitlines():
        if not in_event:
            if line == f"  {event_name}:":
                in_event = True
            continue

        if line and not line.startswith(" "):
            break

        if line.startswith("  ") and not line.startswith("    "):
            break

        if line.strip() == "paths:":
            in_paths = True
            continue

        if not in_paths:
            continue

        if not line.startswith("      - "):
            if line.strip():
                in_paths = False
            continue

        raw_filter = line.split("- ", 1)[1].strip()
        filters.add(raw_filter.strip("\"'"))

    return filters


def path_filter_matches(path_filter: str, path: Path) -> bool:
    path_text = path.as_posix()
    filter_text = path_filter.strip("/")

    if filter_text.endswith("/**"):
        prefix = filter_text.removesuffix("/**")
        return path_text == prefix or path_text.startswith(f"{prefix}/")

    parent_filter, separator, name_filter = filter_text.rpartition("/")
    if separator and any(character in name_filter for character in "*?[]"):
        return path.parent.as_posix() == parent_filter and fnmatchcase(path.name, name_filter)

    return path_text == filter_text


def iter_local_links(markdown_path: Path) -> set[str]:
    text = read_markdown(markdown_path)
    raw_targets = INLINE_LINK_RE.findall(text)
    raw_targets.extend(REFERENCE_LINK_RE.findall(text))

    targets: set[str] = set()
    for raw_target in raw_targets:
        target = local_link_target(markdown_path, raw_target)
        if target is None:
            continue

        try:
            relative_target = repo_relative(target)
        except ValueError:
            targets.add(f"../{target}")
            continue

        targets.add(relative_target)

    return targets


def validate_existing_links(markdown_path: Path, errors: list[str]) -> None:
    text = read_markdown(markdown_path)
    raw_targets = INLINE_LINK_RE.findall(text)
    raw_targets.extend(REFERENCE_LINK_RE.findall(text))

    for raw_target in raw_targets:
        target = local_link_target(markdown_path, raw_target)
        if target is None:
            continue

        try:
            repo_relative(target)
        except ValueError:
            errors.append(f"{markdown_path}: link escapes repository: {raw_target}")
            continue

        if not target.exists():
            errors.append(f"{markdown_path}: missing local link target: {raw_target}")
            continue

        anchor = local_link_anchor(raw_target)
        if anchor is None:
            continue

        if target.suffix.lower() != ".md":
            continue

        expected_anchor = anchor.lower()
        if expected_anchor not in markdown_anchors(target):
            errors.append(
                f"{markdown_path}: missing markdown anchor in "
                f"{repo_relative(target)}: #{anchor}"
            )


def validate_required_links(markdown_path: Path, errors: list[str]) -> None:
    present_targets = iter_local_links(markdown_path)
    for required in sorted(REQUIRED_LINK_TARGETS[markdown_path]):
        if required not in present_targets:
            errors.append(f"{markdown_path}: missing required reviewer route to {required}")


def validate_required_text(markdown_path: Path, errors: list[str]) -> None:
    text = read_markdown(markdown_path)
    normalized = normalized_text(text)
    for phrase in REQUIRED_TEXT[markdown_path]:
        if phrase not in text and normalized_text(phrase) not in normalized:
            errors.append(f"{markdown_path}: missing reviewer contract phrase: {phrase!r}")


def validate_forbidden_text(markdown_path: Path, errors: list[str]) -> None:
    text = read_markdown(markdown_path).lower()
    for phrase in FORBIDDEN_TEXT.get(markdown_path, ()):
        if phrase.lower() in text:
            errors.append(f"{markdown_path}: forbidden scope phrase present: {phrase!r}")


def validate_required_paths(errors: list[str]) -> None:
    for path in REQUIRED_REVIEWER_PATHS:
        if not (REPO_ROOT / path).is_file():
            errors.append(f"missing reviewer path: {path.as_posix()}")

    for project_root, required_files in SUPPORTING_PROJECT_BOUNDARIES.items():
        for required_file in required_files:
            path = project_root / required_file
            if not (REPO_ROOT / path).is_file():
                errors.append(f"missing supporting-project boundary file: {path.as_posix()}")


def validate_workflow_path_filters(
    reviewer_surface_markdown: tuple[Path, ...], errors: list[str]
) -> None:
    for event_name in WORKFLOW_EVENTS_WITH_PATH_FILTERS:
        filters = workflow_path_filters(WORKFLOW_PATH, event_name, errors)
        if not filters:
            errors.append(f"{WORKFLOW_PATH}: missing path filters for {event_name}")
            continue

        for required_filter in REQUIRED_WORKFLOW_PATH_FILTERS:
            if required_filter not in filters:
                errors.append(
                    f"{WORKFLOW_PATH}: {event_name} is missing path filter "
                    f"{required_filter!r}"
                )

        for markdown_path in reviewer_surface_markdown:
            if not any(path_filter_matches(path_filter, markdown_path) for path_filter in filters):
                errors.append(
                    f"{WORKFLOW_PATH}: {event_name} path filters do not cover "
                    f"{markdown_path.as_posix()}"
                )


def main() -> int:
    errors: list[str] = []
    reviewer_surface_markdown = iter_reviewer_surface_markdown(errors)

    for markdown_path in reviewer_surface_markdown:
        validate_existing_links(markdown_path, errors)

    for markdown_path in DOCS_TO_VALIDATE:
        if not (REPO_ROOT / markdown_path).is_file():
            errors.append(f"missing reviewer document: {markdown_path.as_posix()}")
            continue

        validate_required_links(markdown_path, errors)
        validate_required_text(markdown_path, errors)
        validate_forbidden_text(markdown_path, errors)

    validate_required_paths(errors)
    validate_workflow_path_filters(reviewer_surface_markdown, errors)

    if errors:
        print("Reviewer route validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        "Reviewer route validation passed: "
        f"{len(DOCS_TO_VALIDATE)} documents and "
        f"{len(REQUIRED_REVIEWER_PATHS)} reviewer paths checked; "
        f"{len(reviewer_surface_markdown)} reviewer-surface markdown files "
        "link-checked; workflow path filters and coverage checked."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
