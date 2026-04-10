from __future__ import annotations

import pytest

from sbom_diff_risk.diffing import component_key, diff_components
from sbom_diff_risk.models import Component


def test_component_key_prefers_purl() -> None:
    component = Component(
        name="requests",
        version="2.31.0",
        ecosystem="pypi",
        purl="pkg:pypi/requests@2.31.0",
        bom_ref="requests-ref",
    )
    assert component_key(component) == "purl:pkg:pypi/requests"


def test_diff_components_empty_inputs() -> None:
    added, removed, changed = diff_components([], [])
    assert added == []
    assert removed == []
    assert changed == []


def test_diff_components_treats_purl_version_change_as_changed() -> None:
    before = [
        Component(
            name="requests",
            version="2.31.0",
            ecosystem="pypi",
            purl="pkg:pypi/requests@2.31.0",
        )
    ]
    after = [
        Component(
            name="requests",
            version="2.32.0",
            ecosystem="pypi",
            purl="pkg:pypi/requests@2.32.0",
        )
    ]

    added, removed, changed = diff_components(before, after)

    assert added == []
    assert removed == []
    assert len(changed) == 1
    assert changed[0].classification == "version_changed"


def test_diff_components_fails_on_duplicate_identity() -> None:
    duplicate_before = [
        Component(name="requests", version="2.31.0", ecosystem="pypi", purl="pkg:pypi/requests@2.31.0"),
        Component(name="requests", version="2.31.0", ecosystem="pypi", purl="pkg:pypi/requests@2.31.0"),
    ]

    with pytest.raises(ValueError, match="Duplicate component identity in before input"):
        diff_components(duplicate_before, [])
