from __future__ import annotations

import re
from pathlib import Path

from ..errors import MalformedInputError, UnsupportedInputError
from ..models import Component
from .common import build_pypi_purl, extract_requirement_version, parse_requirement_text
from .requirements_rules import reject_unsupported_requirement_syntax


def parse(path: Path) -> list[Component]:
    normalized: list[Component] = []
    for start_line, raw_requirement in _iter_logical_requirements(path):
        reject_unsupported_requirement_syntax(raw_requirement, path=path, line_number=start_line)

        requirement = parse_requirement_text(raw_requirement, f"{path}:{start_line}")
        if requirement.url is not None:
            raise UnsupportedInputError(
                f"Unsupported requirements.txt syntax in {path} at line {start_line}: "
                "deterministic mode does not accept direct URL or VCS references."
            )
        version, exact_version = extract_requirement_version(requirement)
        normalized.append(
            Component(
                name=requirement.name,
                version=version,
                ecosystem="pypi",
                purl=build_pypi_purl(requirement.name, exact_version),
                license_id=None,
                supplier=None,
                source_url=requirement.url,
                bom_ref=None,
                raw_type="requirement",
                evidence={
                    "source_format": "requirements-txt",
                    "line_number": start_line,
                    "raw_requirement": raw_requirement,
                    "specifier": str(requirement.specifier) or None,
                    "marker": str(requirement.marker) if requirement.marker else None,
                    "extras": sorted(requirement.extras),
                    "url": None,
                },
            )
        )
    return normalized


def _iter_logical_requirements(path: Path) -> list[tuple[int, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    logical_lines: list[tuple[int, str]] = []
    buffer: list[str] = []
    start_line = 0

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line
        if line_number == 1:
            line = line.lstrip("\ufeff")

        uncommented = _strip_inline_comment(line).strip()
        if not buffer and not uncommented:
            continue

        continued = uncommented.endswith("\\")
        segment = uncommented[:-1].rstrip() if continued else uncommented

        if not buffer:
            start_line = line_number
        if segment:
            buffer.append(segment)

        if continued:
            continue

        logical = " ".join(buffer).strip()
        buffer = []
        if logical:
            logical_lines.append((start_line, logical))

    if buffer:
        raise MalformedInputError(
            f"Malformed requirements.txt in {path}: dangling line continuation starting at line {start_line}."
        )

    return logical_lines


def _strip_inline_comment(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    return re.split(r"\s+#", line, maxsplit=1)[0]
