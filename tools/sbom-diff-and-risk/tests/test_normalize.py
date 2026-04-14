from __future__ import annotations

from pathlib import Path

import pytest

from sbom_diff_risk.errors import ParseError
from sbom_diff_risk.normalize import detect_format, normalize_input, normalize_input_with_options


def test_detect_format_from_scaffold_fixtures() -> None:
    fixtures = Path(__file__).parent / "fixtures"
    assert detect_format(fixtures / "cdx_before.json") == "cyclonedx-json"
    assert detect_format(fixtures / "spdx_before.json") == "spdx-json"
    assert detect_format(fixtures / "requirements_before.txt") == "requirements-txt"
    assert detect_format(fixtures / "pyproject_before.toml") == "pyproject-toml"


def test_detect_format_fails_clearly_for_malformed_json(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ParseError, match="Malformed JSON while detecting input format"):
        detect_format(broken)


def test_normalize_input_dispatches_to_parser() -> None:
    fixture = Path(__file__).parent / "fixtures" / "requirements_before.txt"

    selected_format, components, notes = normalize_input(fixture)

    assert selected_format == "requirements-txt"
    assert len(components) == 1
    assert components[0].name == "requests"
    assert notes == []


def test_normalize_input_with_pyproject_group_selects_dependency_group() -> None:
    fixture = Path(__file__).parent / "fixtures" / "pyproject_groups_after.toml"

    selected_format, components, notes = normalize_input_with_options(
        fixture,
        declared_format="pyproject-toml",
        pyproject_group="lint",
    )

    assert selected_format == "pyproject-toml"
    assert [component.name for component in components] == ["ruff"]
    assert components[0].version == "0.6.3"
    assert notes == []
