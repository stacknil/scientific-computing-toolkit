from __future__ import annotations

from pathlib import Path

from ..errors import InputSelectionError, MalformedInputError, UnsupportedInputError
from ..models import Component
from .common import build_pypi_purl, extract_requirement_version, load_toml_object, parse_requirement_text, require_mapping
from .pyproject_groups import normalize_dependency_groups, resolve_dependency_group


def parse(path: Path, *, dependency_group: str | None = None) -> list[Component]:
    payload = load_toml_object(path, "pyproject")
    if dependency_group is not None:
        return _parse_dependency_group(path, payload, dependency_group)

    raw_project = payload.get("project")
    if raw_project is None:
        if payload.get("dependency-groups") is not None:
            raise InputSelectionError(
                f"pyproject.toml in {path} defines [dependency-groups]; select one explicitly with --pyproject-group."
            )
        raise UnsupportedInputError(
            f"Unsupported pyproject.toml layout in {path}: only PEP 621 [project] dependencies are supported."
        )
    project = require_mapping(raw_project, f"{path}: project")

    normalized: list[Component] = []
    normalized.extend(
        _parse_requirement_group(
            path,
            project.get("dependencies"),
            group_name="dependencies",
            raw_type="project-dependency",
            selection_kind="project",
        )
    )

    raw_optional = project.get("optional-dependencies", {})
    if raw_optional is None:
        raw_optional = {}
    optional_groups = require_mapping(raw_optional, f"{path}: project.optional-dependencies")
    for group_name, requirements in optional_groups.items():
        if not isinstance(group_name, str):
            raise MalformedInputError(
                f"Malformed pyproject.toml in {path}: optional dependency group names must be strings."
            )
        normalized.extend(
            _parse_requirement_group(
                path,
                requirements,
                group_name=f"optional-dependencies.{group_name}",
                raw_type="optional-dependency",
                selection_kind="optional-dependency",
            )
        )

    return normalized


def _parse_dependency_group(path: Path, payload: dict[str, object], dependency_group: str) -> list[Component]:
    dependency_groups, original_names = normalize_dependency_groups(payload.get("dependency-groups"), f"{path}: dependency-groups")
    selected_group_name, resolved_requirements = resolve_dependency_group(
        dependency_groups,
        original_names,
        requested_group=dependency_group,
        context=str(path),
    )
    return _parse_requirement_group(
        path,
        resolved_requirements,
        group_name=f"dependency-groups.{selected_group_name}",
        raw_type="dependency-group-dependency",
        selection_kind="dependency-group",
    )


def _parse_requirement_group(
    path: Path,
    raw_requirements: object,
    *,
    group_name: str,
    raw_type: str,
    selection_kind: str,
) -> list[Component]:
    if raw_requirements is None:
        return []
    if not isinstance(raw_requirements, list):
        raise MalformedInputError(
            f"Malformed pyproject.toml in {path}: {group_name} must be an array of requirement strings."
        )

    normalized: list[Component] = []
    for index, raw_requirement in enumerate(raw_requirements, start=1):
        if not isinstance(raw_requirement, str):
            raise MalformedInputError(f"Malformed pyproject.toml in {path}: {group_name}[{index}] must be a string.")
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
                    "group_kind": selection_kind,
                    "raw_requirement": raw_requirement,
                    "specifier": str(requirement.specifier) or None,
                    "marker": str(requirement.marker) if requirement.marker else None,
                    "extras": sorted(requirement.extras),
                    "url": requirement.url,
                },
            )
        )

    return normalized
