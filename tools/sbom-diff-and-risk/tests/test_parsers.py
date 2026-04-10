from __future__ import annotations

from pathlib import Path

import pytest

from sbom_diff_risk.errors import ParseError
from sbom_diff_risk.normalize import normalize_input
from sbom_diff_risk.parsers import cyclonedx_json, pyproject_toml, requirements_txt, spdx_json


def test_cyclonedx_parser_normalizes_component_fields() -> None:
    fixture = Path(__file__).parent / "fixtures" / "cdx_before.json"

    components = cyclonedx_json.parse(fixture)

    assert len(components) == 1
    component = components[0]
    assert component.name == "requests"
    assert component.version == "2.31.0"
    assert component.ecosystem == "pypi"
    assert component.purl == "pkg:pypi/requests@2.31.0"
    assert component.license_id == "Apache-2.0"
    assert component.supplier == "Python Software Foundation"
    assert component.source_url == "https://pypi.org/project/requests/"
    assert component.bom_ref == "pkg:pypi/requests@2.31.0"
    assert component.raw_type == "library"
    assert component.evidence["source_format"] == "cyclonedx-json"
    assert component.evidence["component"]["name"] == "requests"


def test_spdx_parser_normalizes_component_fields() -> None:
    fixture = Path(__file__).parent / "fixtures" / "spdx_before.json"

    components = spdx_json.parse(fixture)

    assert len(components) == 1
    component = components[0]
    assert component.name == "requests"
    assert component.version == "2.31.0"
    assert component.ecosystem == "pypi"
    assert component.purl == "pkg:pypi/requests@2.31.0"
    assert component.license_id == "Apache-2.0"
    assert component.supplier == "Organization: Python Software Foundation"
    assert component.source_url == "https://requests.readthedocs.io/"
    assert component.bom_ref == "SPDXRef-requests"
    assert component.raw_type == "LIBRARY"
    assert component.evidence["source_format"] == "spdx-json"
    assert component.evidence["package"]["name"] == "requests"


def test_requirements_parser_normalizes_exact_range_and_direct_url() -> None:
    fixture = Path(__file__).parent / "fixtures" / "requirements_parser.txt"

    components = requirements_txt.parse(fixture)

    assert [component.name for component in components] == ["requests", "urllib3", "internal-lib"]
    assert components[0].version == "2.31.0"
    assert components[0].purl == "pkg:pypi/requests@2.31.0"
    assert components[0].evidence["line_number"] == 2
    assert components[1].version == "<3.0,>=2.0"
    assert components[1].purl == "pkg:pypi/urllib3"
    assert components[2].version is None
    assert components[2].source_url == "https://example.com/packages/internal_lib-1.2.0-py3-none-any.whl"
    assert components[2].evidence["marker"] == 'python_version >= "3.11"'


def test_pyproject_parser_reads_project_and_optional_dependencies() -> None:
    fixture = Path(__file__).parent / "fixtures" / "pyproject_parser.toml"

    components = pyproject_toml.parse(fixture)

    assert [component.name for component in components] == ["requests", "urllib3", "pytest", "mkdocs"]
    assert components[0].raw_type == "project-dependency"
    assert components[2].evidence["group"] == "optional-dependencies.dev"
    assert components[3].source_url == "https://example.com/packages/mkdocs-1.6.0-py3-none-any.whl"


def test_normalize_input_dispatches_to_parser() -> None:
    fixture = Path(__file__).parent / "fixtures" / "requirements_before.txt"

    selected_format, components, notes = normalize_input(fixture)

    assert selected_format == "requirements-txt"
    assert len(components) == 1
    assert components[0].name == "requests"
    assert notes == []


def test_requirements_parser_fails_clearly_on_unsupported_directive(tmp_path: Path) -> None:
    broken = tmp_path / "requirements.txt"
    broken.write_text("-r base.txt\n", encoding="utf-8")

    with pytest.raises(ParseError, match="Unsupported requirements directive"):
        requirements_txt.parse(broken)


def test_pyproject_parser_fails_clearly_on_unsupported_layout(tmp_path: Path) -> None:
    broken = tmp_path / "pyproject.toml"
    broken.write_text("[tool.poetry]\nname = 'demo'\n", encoding="utf-8")

    with pytest.raises(ParseError, match="only PEP 621 \\[project\\] dependencies are supported"):
        pyproject_toml.parse(broken)


def test_cyclonedx_parser_fails_clearly_on_malformed_components(tmp_path: Path) -> None:
    broken = tmp_path / "broken-cdx.json"
    broken.write_text('{"bomFormat":"CycloneDX","components":{}}', encoding="utf-8")

    with pytest.raises(ParseError, match="expected array"):
        cyclonedx_json.parse(broken)


def test_spdx_parser_fails_clearly_on_missing_spdx_version(tmp_path: Path) -> None:
    broken = tmp_path / "broken-spdx.json"
    broken.write_text('{"packages":[]}', encoding="utf-8")

    with pytest.raises(ParseError, match="missing spdxVersion"):
        spdx_json.parse(broken)
