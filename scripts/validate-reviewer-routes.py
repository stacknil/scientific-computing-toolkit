from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


REPO_ROOT = Path(__file__).resolve().parents[1]

DOCS_TO_VALIDATE = (
    Path("README.md"),
    Path("docs/reviewer-brief.md"),
    Path("tools/sbom-diff-and-risk/docs/reviewer-path.md"),
)

REQUIRED_LINK_TARGETS = {
    Path("README.md"): {
        "docs/reviewer-brief.md",
        "tools/sbom-diff-and-risk/docs/reviewer-path.md",
        "tools/sbom-diff-and-risk/docs/reviewer-evidence-pack.md",
        "projects/python-weather-diagnostics-toolkit/docs/reviewer-path.md",
    },
    Path("docs/reviewer-brief.md"): {
        "README.md",
        "tools/sbom-diff-and-risk/docs/reviewer-path.md",
        "tools/sbom-diff-and-risk/docs/example-artifact-regeneration.md",
        "projects/python-weather-diagnostics-toolkit/docs/reviewer-path.md",
    },
    Path("tools/sbom-diff-and-risk/docs/reviewer-path.md"): {
        "tools/sbom-diff-and-risk/docs/reviewer-brief.md",
        "tools/sbom-diff-and-risk/docs/reviewer-evidence-pack.md",
        "tools/sbom-diff-and-risk/docs/verification.md",
        "tools/sbom-diff-and-risk/examples/sample-report.json",
        "tools/sbom-diff-and-risk/examples/sample-summary.json",
        "tools/sbom-diff-and-risk/examples/sample-policy.json",
        "tools/sbom-diff-and-risk/examples/sample-sarif.sarif",
    },
}

REQUIRED_TEXT = {
    Path("README.md"): (
        "current flagship tool",
        "not part of the `sbom-diff-and-risk` release surface",
        "Production PyPI publishing: intentionally deferred",
    ),
    Path("docs/reviewer-brief.md"): (
        "The current flagship project is",
        "supporting diagnostics projects",
        "production PyPI publishing remains intentionally deferred",
    ),
    Path("tools/sbom-diff-and-risk/docs/reviewer-path.md"): (
        "Artifact evidence map",
        "No network",
        "not current PyPI package truth",
        "not current repository reputation",
        "It does not decide whether a dependency is safe.",
    ),
}

REQUIRED_REVIEWER_PATHS = (
    Path("tools/sbom-diff-and-risk/docs/reviewer-path.md"),
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


def repo_relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def read_markdown(path: Path) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def normalized_text(text: str) -> str:
    return WHITESPACE_RE.sub(" ", text)


def local_link_target(markdown_path: Path, raw_target: str) -> Path | None:
    target = raw_target.strip()
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")]
    else:
        target = target.split()[0]

    target = unquote(target)
    if not target or target.startswith("#") or URI_RE.match(target):
        return None

    path_part = target.split("#", 1)[0]
    if not path_part:
        return None

    return (REPO_ROOT / markdown_path.parent / path_part).resolve()


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


def validate_required_paths(errors: list[str]) -> None:
    for path in REQUIRED_REVIEWER_PATHS:
        if not (REPO_ROOT / path).is_file():
            errors.append(f"missing reviewer path: {path.as_posix()}")

    for project_root, required_files in SUPPORTING_PROJECT_BOUNDARIES.items():
        for required_file in required_files:
            path = project_root / required_file
            if not (REPO_ROOT / path).is_file():
                errors.append(f"missing supporting-project boundary file: {path.as_posix()}")


def main() -> int:
    errors: list[str] = []

    for markdown_path in DOCS_TO_VALIDATE:
        if not (REPO_ROOT / markdown_path).is_file():
            errors.append(f"missing reviewer document: {markdown_path.as_posix()}")
            continue

        validate_existing_links(markdown_path, errors)
        validate_required_links(markdown_path, errors)
        validate_required_text(markdown_path, errors)

    validate_required_paths(errors)

    if errors:
        print("Reviewer route validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        "Reviewer route validation passed: "
        f"{len(DOCS_TO_VALIDATE)} documents and "
        f"{len(REQUIRED_REVIEWER_PATHS)} reviewer paths checked."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
