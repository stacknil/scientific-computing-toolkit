from __future__ import annotations

from pathlib import Path

from ..errors import ParseError
from ..models import Component
from .common import build_pypi_purl, extract_requirement_version, load_toml_object, parse_requirement_text, require_mapping


def parse(path: Path) -> list[Component]:
    payload = load_toml_object(path, "pyproject")
    raw_project = payload.get("project")
    if raw_project is None:
        raise ParseError(
            f"Unsupported pyproject.toml layout in {path}: only PEP 621 [project] dependencies are supported."
        )
    project = require_mapping(raw_project, f"{path}: project")

    normalized: list[Component] = []
    normalized.extend(_parse_requirement_group(path, project.get("dependencies"), "dependencies", "project-dependency"))

    raw_optional = project.get("optional-dependencies", {})
    if raw_optional is None:
        raw_optional = {}
    optional_groups = require_mapping(raw_optional, f"{path}: project.optional-dependencies")
    for group_name, requirements in optional_groups.items():
        if not isinstance(group_name, str):
            raise ParseError(f"Malformed pyproject.toml in {path}: optional dependency group names must be strings.")
        normalized.extend(
            _parse_requirement_group(
                path,
                requirements,
                f"optional-dependencies.{group_name}",
                "optional-dependency",
            )
        )

    return normalized


def _parse_requirement_group(
    path: Path,
    raw_requirements: object,
    group_name: str,
    raw_type: str,
) -> list[Component]:
    if raw_requirements is None:
        return []
    if not isinstance(raw_requirements, list):
        raise ParseError(f"Malformed pyproject.toml in {path}: {group_name} must be an array of strings.")

    normalized: list[Component] = []
    for index, raw_requirement in enumerate(raw_requirements, start=1):
        if not isinstance(raw_requirement, str):
            raise ParseError(f"Malformed pyproject.toml in {path}: {group_name}[{index}] must be a string.")
        requirement = parse_requirement_text(raw_requirement, f"{path}:{group_name}[{index}]")
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
                raw_type=raw_type,
                evidence={
                    "source_format": "pyproject-toml",
                    "group": group_name,
                    "raw_requirement": raw_requirement,
                    "specifier": str(requirement.specifier) or None,
                    "marker": str(requirement.marker) if requirement.marker else None,
                    "extras": sorted(requirement.extras),
                    "url": requirement.url,
                },
            )
        )

    return normalized
