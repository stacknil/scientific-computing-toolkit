from __future__ import annotations

from pathlib import Path

import pytest

from sbom_diff_risk.errors import InputSelectionError, MalformedInputError, ParseError, UnsupportedInputError
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


def test_requirements_parser_normalizes_supported_pep508_subset() -> None:
    fixture = Path(__file__).parent / "fixtures" / "requirements_parser.txt"

    components = requirements_txt.parse(fixture)

    assert [component.name for component in components] == ["requests", "urllib3", "pytest"]
    assert components[0].version == "2.31.0"
    assert components[0].purl == "pkg:pypi/requests@2.31.0"
    assert components[0].evidence["line_number"] == 2
    assert components[1].version == "<3.0,>=2.0"
    assert components[1].evidence["marker"] == 'python_version >= "3.11"'
    assert components[2].version == ">=8.0"
    assert components[2].evidence["extras"] == ["testing"]
    assert components[2].source_url is None


def test_requirements_parser_supports_line_continuations(tmp_path: Path) -> None:
    continuation_file = tmp_path / "requirements.txt"
    continuation_file.write_text(
        "urllib3>=2.0,\\\n<3.0 ; python_version >= \"3.11\"\n",
        encoding="utf-8",
    )

    components = requirements_txt.parse(continuation_file)

    assert len(components) == 1
    assert components[0].name == "urllib3"
    assert components[0].version == "<3.0,>=2.0"
    assert components[0].evidence["marker"] == 'python_version >= "3.11"'


def test_pyproject_parser_reads_project_and_optional_dependencies() -> None:
    fixture = Path(__file__).parent / "fixtures" / "pyproject_parser.toml"

    components = pyproject_toml.parse(fixture)

    assert [component.name for component in components] == ["requests", "urllib3", "pytest", "mkdocs"]
    assert components[0].raw_type == "project-dependency"
    assert components[2].evidence["group"] == "optional-dependencies.dev"
    assert components[2].evidence["group_kind"] == "optional-dependency"
    assert components[3].source_url is None


def test_pyproject_parser_selects_dependency_group_with_includes() -> None:
    fixture = Path(__file__).parent / "fixtures" / "pyproject_groups_before.toml"

    components = pyproject_toml.parse(fixture, dependency_group="test")

    assert [component.name for component in components] == ["pytest-cov", "pytest", "ruff"]
    assert all(component.raw_type == "dependency-group-dependency" for component in components)
    assert all(component.evidence["group_kind"] == "dependency-group" for component in components)
    assert all(component.evidence["group"] == "dependency-groups.test" for component in components)


def test_pyproject_parser_normalizes_dependency_group_name_for_selection() -> None:
    fixture = Path(__file__).parent / "fixtures" / "pyproject_groups_before.toml"

    components = pyproject_toml.parse(fixture, dependency_group="DEV")

    assert [component.name for component in components] == ["pytest", "ruff"]


@pytest.mark.parametrize(
    ("line", "match"),
    [
        ("-r base.txt\n", "include directives"),
        ("-c constraints.txt\n", "constraint directives"),
        ("-e .\n", "editable installs"),
        ("package @ https://example.com/package.whl\n", "using '@'"),
        ("https://example.com/package.whl\n", "archive URLs and VCS references"),
        ("--index-url https://pypi.org/simple\n", "index and source options"),
    ],
)
def test_requirements_parser_rejects_unsupported_deterministic_mode_syntax(
    tmp_path: Path,
    line: str,
    match: str,
) -> None:
    broken = tmp_path / "requirements.txt"
    broken.write_text(line, encoding="utf-8")

    with pytest.raises(UnsupportedInputError, match=match):
        requirements_txt.parse(broken)


def test_requirements_parser_fails_on_malformed_continuation(tmp_path: Path) -> None:
    malformed = tmp_path / "requirements.txt"
    malformed.write_text("requests==2.31.0 \\\n", encoding="utf-8")

    with pytest.raises(MalformedInputError, match="dangling line continuation"):
        requirements_txt.parse(malformed)


def test_pyproject_parser_requires_group_selection_for_dependency_groups_only_layout(tmp_path: Path) -> None:
    broken = tmp_path / "pyproject.toml"
    broken.write_text(
        "[dependency-groups]\ndev = [\"pytest==8.2.0\"]\n",
        encoding="utf-8",
    )

    with pytest.raises(InputSelectionError, match="select one explicitly with --pyproject-group"):
        pyproject_toml.parse(broken)


def test_pyproject_parser_fails_when_requested_group_is_missing() -> None:
    fixture = Path(__file__).parent / "fixtures" / "pyproject_groups_before.toml"

    with pytest.raises(InputSelectionError, match="distinct from \\[project.optional-dependencies\\]"):
        pyproject_toml.parse(fixture, dependency_group="docs")


def test_pyproject_parser_fails_on_malformed_dependency_group_include(tmp_path: Path) -> None:
    broken = tmp_path / "pyproject.toml"
    broken.write_text(
        "[dependency-groups]\ndev = [{ include-group = 42 }]\n",
        encoding="utf-8",
    )

    with pytest.raises(MalformedInputError, match="include-group must be a non-empty string"):
        pyproject_toml.parse(broken, dependency_group="dev")


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
