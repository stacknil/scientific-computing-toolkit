from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from ..errors import InputSelectionError, MalformedInputError, UnsupportedInputError
from .common import require_list, require_mapping

_GROUP_NAME_NORMALIZE_RE = re.compile(r"[-_.]+")


def normalize_group_name(name: str) -> str:
    return _GROUP_NAME_NORMALIZE_RE.sub("-", name).lower()


def normalize_dependency_groups(raw_groups: object, context: str) -> tuple[dict[str, list[Any]], dict[str, str]]:
    if raw_groups is None:
        return {}, {}

    groups = require_mapping(raw_groups, context)
    normalized_groups: dict[str, list[Any]] = {}
    original_names: dict[str, str] = {}
    collisions: defaultdict[str, list[str]] = defaultdict(list)

    for group_name, raw_value in groups.items():
        if not isinstance(group_name, str):
            raise MalformedInputError(f"Malformed pyproject.toml in {context}: dependency group names must be strings.")
        normalized_name = normalize_group_name(group_name)
        collisions[normalized_name].append(group_name)
        normalized_groups[normalized_name] = require_list(raw_value, f"{context}.{group_name}")
        original_names[normalized_name] = group_name

    duplicates = [f"{normalized} ({', '.join(names)})" for normalized, names in collisions.items() if len(names) > 1]
    if duplicates:
        raise InputSelectionError(
            "Duplicate dependency group names after normalization: " + ", ".join(sorted(duplicates)) + "."
        )

    return normalized_groups, original_names


def resolve_dependency_group(
    dependency_groups: dict[str, list[Any]],
    original_names: dict[str, str],
    *,
    requested_group: str,
    context: str,
) -> tuple[str, list[str]]:
    normalized_requested_group = normalize_group_name(requested_group)
    if normalized_requested_group not in dependency_groups:
        raise InputSelectionError(
            f"Requested dependency group {requested_group!r} was not found in [dependency-groups] of {context}. "
            "Dependency groups are distinct from [project.optional-dependencies]."
        )

    resolved = _resolve_group(
        dependency_groups,
        original_names,
        group=normalized_requested_group,
        context=context,
        past_groups=(),
    )
    return original_names[normalized_requested_group], resolved


def _resolve_group(
    dependency_groups: dict[str, list[Any]],
    original_names: dict[str, str],
    *,
    group: str,
    context: str,
    past_groups: tuple[str, ...],
) -> list[str]:
    if group in past_groups:
        cycle = " -> ".join([*(original_names[item] for item in past_groups), original_names[group]])
        raise UnsupportedInputError(f"Cyclic dependency group include in {context}: {cycle}.")

    raw_group = dependency_groups[group]
    realized_group: list[str] = []
    for index, item in enumerate(raw_group, start=1):
        if isinstance(item, str):
            realized_group.append(item)
            continue

        if isinstance(item, dict):
            if tuple(item.keys()) != ("include-group",):
                raise UnsupportedInputError(
                    f"Unsupported dependency group item in {context}:{original_names[group]}[{index}]: {item!r}. "
                    "Only strings and {include-group = \"name\"} objects are supported."
                )

            include_name = item["include-group"]
            if not isinstance(include_name, str) or not include_name.strip():
                raise MalformedInputError(
                    f"Malformed dependency group include in {context}:{original_names[group]}[{index}]: "
                    "include-group must be a non-empty string."
                )
            normalized_include = normalize_group_name(include_name)
            if normalized_include not in dependency_groups:
                raise InputSelectionError(
                    f"Dependency group include {include_name!r} referenced by {original_names[group]!r} "
                    f"was not found in [dependency-groups] of {context}."
                )
            realized_group.extend(
                _resolve_group(
                    dependency_groups,
                    original_names,
                    group=normalized_include,
                    context=context,
                    past_groups=(*past_groups, group),
                )
            )
            continue

        raise MalformedInputError(
            f"Malformed dependency group item in {context}:{original_names[group]}[{index}]: "
            "items must be strings or include-group objects."
        )

    return realized_group
