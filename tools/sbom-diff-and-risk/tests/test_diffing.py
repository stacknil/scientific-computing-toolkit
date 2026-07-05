from __future__ import annotations

from pathlib import Path

import pytest

from sbom_diff_risk.diffing import component_key, diff_components
from sbom_diff_risk.errors import ComponentIdentityDiagnosticCode, ComponentIdentityError
from sbom_diff_risk.models import Component
from sbom_diff_risk.normalize import normalize_input


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


def test_diff_components_ignores_lexical_pypi_identity_variants() -> None:
    before = [
        Component(
            name="Requests_Test",
            version="1.0",
            ecosystem="PyPI",
            purl="pkg:pypi/Requests_Test@1.0",
        )
    ]
    after = [
        Component(
            name="requests-test",
            version="1.0",
            ecosystem="pypi",
            purl="pkg:pypi/requests-test@1.0",
        )
    ]

    added, removed, changed = diff_components(before, after)

    assert added == []
    assert removed == []
    assert changed == []


def test_diff_components_classifies_purl_only_version_change() -> None:
    before = [Component(name="requests", version=None, ecosystem="pypi", purl="pkg:pypi/requests@1.0")]
    after = [Component(name="requests", version=None, ecosystem="pypi", purl="pkg:pypi/requests@2.0")]

    _, _, changed = diff_components(before, after)

    assert len(changed) == 1
    assert changed[0].classification == "version_changed"


def test_diff_components_aligns_cyclonedx_and_spdx_by_canonical_purl() -> None:
    fixtures = Path(__file__).parent / "fixtures"
    _, before, _ = normalize_input(fixtures / "cdx_before.json")
    _, after, _ = normalize_input(fixtures / "spdx_after.json")

    added, removed, changed = diff_components(before, after)

    assert [component.name for component in added] == ["urllib3"]
    assert removed == []
    assert [change.key for change in changed] == ["purl:pkg:pypi/requests"]
    assert changed[0].classification == "version_changed"


def test_diff_components_fails_on_duplicate_identity() -> None:
    duplicate_before = [
        Component(name="requests", version="2.31.0", ecosystem="pypi", purl="pkg:pypi/requests@2.31.0"),
        Component(name="requests", version="2.31.0", ecosystem="pypi", purl="pkg:pypi/requests@2.31.0"),
    ]

    with pytest.raises(ComponentIdentityError, match="duplicate_component") as exc_info:
        diff_components(duplicate_before, [])

    assert exc_info.value.code is ComponentIdentityDiagnosticCode.DUPLICATE_COMPONENT
    assert exc_info.value.side == "before"
    assert exc_info.value.component_key == "purl:pkg:pypi/requests"


def test_diff_components_fails_on_conflicting_metadata_for_same_identity() -> None:
    conflicting_before = [
        Component(
            name="requests",
            version="2.31.0",
            ecosystem="pypi",
            purl="pkg:pypi/requests@2.31.0",
            supplier="Supplier A",
        ),
        Component(
            name="requests",
            version="2.31.0",
            ecosystem="pypi",
            purl="pkg:pypi/requests@2.31.0",
            supplier="Supplier B",
        ),
    ]

    with pytest.raises(ComponentIdentityError, match="conflicting_metadata") as exc_info:
        diff_components(conflicting_before, [])

    assert exc_info.value.code is ComponentIdentityDiagnosticCode.CONFLICTING_METADATA
    assert exc_info.value.side == "before"
    assert exc_info.value.component_key == "purl:pkg:pypi/requests"
