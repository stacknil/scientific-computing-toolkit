from __future__ import annotations

import re
from pathlib import Path

from ..errors import UnsupportedInputError

_UNSUPPORTED_DIRECTIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^(?:-r|--requirement)(?:\s|=|$)", re.IGNORECASE), "include directives (-r/--requirement)"),
    (re.compile(r"^(?:-c|--constraint)(?:\s|=|$)", re.IGNORECASE), "constraint directives (-c/--constraint)"),
    (re.compile(r"^(?:-e|--editable)(?:\s|=|$)", re.IGNORECASE), "editable installs (-e/--editable)"),
    (
        re.compile(r"^(?:-i|--index-url|--extra-index-url|--no-index|--find-links|--trusted-host)(?:\s|=|$)", re.IGNORECASE),
        "index and source options",
    ),
    (
        re.compile(r"^(?:--no-binary|--only-binary|--prefer-binary|--require-hashes|--hash|--pre|--all-releases|--only-final|--use-feature|--config-settings)(?:\s|=|$)", re.IGNORECASE),
        "pip-specific options",
    ),
)
_DIRECT_REFERENCE_MARKER_RE = re.compile(r"\s@\s")
_URL_PREFIX_RE = re.compile(r"^(?:https?|ftp|file|git\+|git|ssh)://", re.IGNORECASE)
_PLAIN_VCS_RE = re.compile(r"^(?:git|hg|svn|bzr)\+", re.IGNORECASE)
_LOCAL_PATH_RE = re.compile(r"^(?:\.{1,2}[\\/]|[\\/]|[A-Za-z]:[\\/])")
_ARCHIVE_SUFFIXES = (
    ".whl",
    ".zip",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tgz",
)


def reject_unsupported_requirement_syntax(raw_requirement: str, *, path: Path, line_number: int) -> None:
    stripped = raw_requirement.strip()

    for pattern, label in _UNSUPPORTED_DIRECTIVE_PATTERNS:
        if pattern.match(stripped):
            raise UnsupportedInputError(
                f"Unsupported requirements.txt syntax in {path} at line {line_number}: {label} are not supported "
                "in deterministic local mode."
            )

    if _DIRECT_REFERENCE_MARKER_RE.search(stripped):
        raise UnsupportedInputError(
            f"Unsupported requirements.txt syntax in {path} at line {line_number}: direct URL or path references "
            "using '@' are not supported in deterministic local mode."
        )

    if _URL_PREFIX_RE.match(stripped) or _PLAIN_VCS_RE.match(stripped):
        raise UnsupportedInputError(
            f"Unsupported requirements.txt syntax in {path} at line {line_number}: archive URLs and VCS references "
            "are not supported in deterministic local mode."
        )

    lowered = stripped.lower()
    if _LOCAL_PATH_RE.match(stripped) or lowered.endswith(_ARCHIVE_SUFFIXES):
        raise UnsupportedInputError(
            f"Unsupported requirements.txt syntax in {path} at line {line_number}: local paths and archive paths "
            "are not supported in deterministic local mode."
        )
