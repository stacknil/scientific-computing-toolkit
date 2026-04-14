from __future__ import annotations

import json
from pathlib import Path

from .errors import ParseError
from .models import Component
from .parsers import cyclonedx_json, pyproject_toml, requirements_txt, spdx_json

SUPPORTED_FORMATS = (
    "cyclonedx-json",
    "spdx-json",
    "requirements-txt",
    "pyproject-toml",
)

_FORMAT_PARSERS = {
    "cyclonedx-json": cyclonedx_json.parse,
    "spdx-json": spdx_json.parse,
    "requirements-txt": requirements_txt.parse,
    "pyproject-toml": pyproject_toml.parse,
}


def detect_format(path: Path) -> str:
    name = path.name.lower()
    if name == "requirements.txt" or (path.suffix.lower() == ".txt" and "requirements" in path.stem.lower()):
        return "requirements-txt"
    if name == "pyproject.toml" or (path.suffix.lower() == ".toml" and "pyproject" in path.stem.lower()):
        return "pyproject-toml"
    if path.suffix.lower() == ".json":
        try:
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ParseError(
                f"Malformed JSON while detecting input format in {path} at line {exc.lineno}, column {exc.colno}: "
                f"{exc.msg}."
            ) from exc
        if not isinstance(payload, dict):
            raise ParseError(f"Malformed JSON while detecting input format in {path}: top-level value must be an object.")
        if payload.get("bomFormat") == "CycloneDX":
            return "cyclonedx-json"
        if payload.get("spdxVersion") or "packages" in payload:
            return "spdx-json"
    raise ValueError(f"Could not auto-detect format for {path}.")


def normalize_input(path: Path, declared_format: str | None = None) -> tuple[str, list[Component], list[str]]:
    return normalize_input_with_options(path, declared_format=declared_format, pyproject_group=None)


def normalize_input_with_options(
    path: Path,
    *,
    declared_format: str | None = None,
    pyproject_group: str | None = None,
) -> tuple[str, list[Component], list[str]]:
    selected_format = declared_format or detect_format(path)
    if selected_format not in SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported input format {selected_format!r}. Supported formats: {', '.join(SUPPORTED_FORMATS)}."
        )

    if selected_format == "pyproject-toml":
        return selected_format, pyproject_toml.parse(path, dependency_group=pyproject_group), []

    parser = _FORMAT_PARSERS[selected_format]
    return selected_format, parser(path), []
