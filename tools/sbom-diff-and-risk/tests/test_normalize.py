from __future__ import annotations

from pathlib import Path

import pytest

from sbom_diff_risk.errors import ParseError
from sbom_diff_risk.normalize import detect_format


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
