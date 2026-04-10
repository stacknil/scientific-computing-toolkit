from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ..errors import ParseError


def load_json_object(path: Path, format_name: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ParseError(
            f"Malformed {format_name} JSON in {path} at line {exc.lineno}, column {exc.colno}: {exc.msg}."
        ) from exc

    if not isinstance(payload, dict):
        raise ParseError(f"Malformed {format_name} input in {path}: top-level JSON value must be an object.")
    return payload


def load_toml_object(path: Path, format_name: str) -> dict[str, Any]:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(f"Malformed {format_name} TOML in {path}: {exc}.") from exc

    if not isinstance(payload, dict):
        raise ParseError(f"Malformed {format_name} input in {path}: top-level TOML value must be a table.")
    return payload


def require_mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ParseError(f"Malformed input: expected object for {context}.")
    return value


def require_list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ParseError(f"Malformed input: expected array for {context}.")
    return value


def optional_str(value: Any, context: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ParseError(f"Malformed input: expected string for {context}.")
    stripped = value.strip()
    return stripped or None


def required_str(value: Any, context: str) -> str:
    parsed = optional_str(value, context)
    if parsed is None:
        raise ParseError(f"Malformed input: missing required string for {context}.")
    return parsed


def extract_ecosystem(purl: str | None, urls: list[str] | None = None) -> str:
    if purl and purl.startswith("pkg:"):
        body = purl[4:]
        ecosystem, _, _ = body.partition("/")
        ecosystem, _, _ = ecosystem.partition("?")
        if ecosystem:
            return ecosystem.lower()

    for url in urls or []:
        host = (urlparse(url).hostname or "").lower()
        if host in {"pypi.org", "files.pythonhosted.org"}:
            return "pypi"
        if host in {"registry.npmjs.org", "npmjs.org"}:
            return "npm"
        if host.endswith("maven.org") or host.endswith("mvnrepository.com"):
            return "maven"

    return "generic"


def build_pypi_purl(name: str, exact_version: str | None) -> str:
    normalized_name = quote(canonicalize_name(name), safe="")
    if exact_version:
        return f"pkg:pypi/{normalized_name}@{quote(exact_version, safe='')}"
    return f"pkg:pypi/{normalized_name}"


def parse_requirement_text(raw_requirement: str, source_description: str) -> Requirement:
    try:
        return Requirement(raw_requirement)
    except InvalidRequirement as exc:
        raise ParseError(f"Malformed requirement in {source_description}: {raw_requirement!r}. {exc}") from exc


def extract_requirement_version(requirement: Requirement) -> tuple[str | None, str | None]:
    specifier = str(requirement.specifier) or None
    exact_version: str | None = None
    specifiers = list(requirement.specifier)
    if specifier and len(specifiers) == 1:
        item = specifiers[0]
        if item.operator in {"==", "==="} and not item.version.endswith(".*"):
            exact_version = item.version
            return exact_version, exact_version
    return specifier, exact_version
