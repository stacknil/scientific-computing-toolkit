from __future__ import annotations

from pathlib import Path

import pytest

from sbom_diff_risk.component_identity import (
    CanonicalComponentIdentity,
    canonicalization_rule_for_ecosystem,
    canonicalization_rules,
    canonicalize_component_identity,
)
from sbom_diff_risk.errors import ComponentIdentityDiagnosticCode, ComponentIdentityError
from sbom_diff_risk.models import Component


def test_canonicalization_rules_expose_ecosystem_specific_matrix() -> None:
    rules = {rule.ecosystem: rule for rule in canonicalization_rules()}

    assert set(rules) == {"generic", "maven", "npm", "nuget", "pypi"}
    assert rules["pypi"].package_name_rule == "pep503"
    assert rules["maven"].package_name_rule == "preserve-observed"
    assert rules["npm"].package_name_rule == "packageurl-npm-name"
    assert rules["npm"].namespace_rule == "preserve-purl-namespace"
    assert rules["nuget"].version_rule == "preserve-observed"


def test_canonicalization_rules_are_documented() -> None:
    docs_path = Path(__file__).resolve().parents[1] / "docs" / "component-identity-canonicalization.md"
    docs_text = docs_path.read_text(encoding="utf-8")

    for rule in canonicalization_rules():
        assert f"`{rule.ecosystem}`" in docs_text
        assert f"`{rule.package_name_rule}`" in docs_text


def test_canonicalization_rule_for_unknown_ecosystem_preserves_observed_name() -> None:
    rule = canonicalization_rule_for_ecosystem("CustomEcosystem")

    assert rule.ecosystem == "customecosystem"
    assert rule.package_name_rule == "preserve-observed"
    assert rule.namespace_rule == "preserve-purl-namespace"


def test_canonicalize_component_identity_normalizes_pypi_coordinate() -> None:
    component = Component(
        name="Requests_Test",
        version=" 2.31.0 ",
        ecosystem=" PyPI ",
        purl="pkg:pypi/Requests_Test@2.31.0",
    )

    identity = canonicalize_component_identity(component)

    assert identity == CanonicalComponentIdentity(
        ecosystem="pypi",
        package_name="requests-test",
        version="2.31.0",
        purl="pkg:pypi/requests-test@2.31.0",
        component_key="purl:pkg:pypi/requests-test",
    )


def test_canonicalize_component_identity_uses_coordinate_without_purl() -> None:
    component = Component(
        name="Requests_Test",
        version=">=2.31",
        ecosystem="PyPI",
    )

    identity = canonicalize_component_identity(component)

    assert identity.component_key == "coord:pypi:requests-test"
    assert identity.version == ">=2.31"
    assert identity.purl is None


@pytest.mark.parametrize(
    ("component", "expected_package_name", "expected_purl", "expected_key"),
    [
        (
            Component(
                name="EnterpriseLibrary.Common",
                version="6.0.1304",
                ecosystem="nuget",
                purl="pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
            ),
            "EnterpriseLibrary.Common",
            "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
            "purl:pkg:nuget/EnterpriseLibrary.Common",
        ),
        (
            Component(
                name="CaseSensitiveArtifact",
                version="1.2.3",
                ecosystem="maven",
                purl="pkg:maven/Com.Example/CaseSensitiveArtifact@1.2.3",
            ),
            "CaseSensitiveArtifact",
            "pkg:maven/Com.Example/CaseSensitiveArtifact@1.2.3",
            "purl:pkg:maven/Com.Example/CaseSensitiveArtifact",
        ),
        (
            Component(
                name="LeftPad",
                version="1.3.0",
                ecosystem="npm",
                purl="pkg:npm/%40ExampleScope/LeftPad@1.3.0",
            ),
            "leftpad",
            "pkg:npm/%40ExampleScope/leftpad@1.3.0",
            "purl:pkg:npm/%40ExampleScope/leftpad",
        ),
        (
            Component(
                name="CaseSensitiveLib",
                version="2026.7",
                ecosystem="generic",
                purl="pkg:generic/Vendor/CaseSensitiveLib@2026.7",
            ),
            "CaseSensitiveLib",
            "pkg:generic/Vendor/CaseSensitiveLib@2026.7",
            "purl:pkg:generic/Vendor/CaseSensitiveLib",
        ),
    ],
    ids=["nuget", "maven", "npm-scope", "generic"],
)
def test_canonicalize_component_identity_uses_ecosystem_matrix_without_universal_lowercase(
    component: Component,
    expected_package_name: str,
    expected_purl: str,
    expected_key: str,
) -> None:
    identity = canonicalize_component_identity(component)

    assert identity.package_name == expected_package_name
    assert identity.purl == expected_purl
    assert identity.component_key == expected_key


def test_canonicalize_component_identity_preserves_unknown_ecosystem_coordinate_case() -> None:
    component = Component(
        name="CaseSensitiveLib",
        version="2026.7",
        ecosystem="Custom",
    )

    identity = canonicalize_component_identity(component)

    assert identity.ecosystem == "custom"
    assert identity.package_name == "CaseSensitiveLib"
    assert identity.component_key == "coord:custom:CaseSensitiveLib"


def test_canonicalize_component_identity_does_not_invent_purl_version() -> None:
    component = Component(
        name="requests",
        version="2.31.0",
        ecosystem="pypi",
        purl="pkg:pypi/requests",
    )

    identity = canonicalize_component_identity(component)

    assert identity.version == "2.31.0"
    assert identity.purl == "pkg:pypi/requests"


@pytest.mark.parametrize(
    "component",
    [
        Component(name="requests", version="2.31.0", ecosystem="npm", purl="pkg:pypi/requests@2.31.0"),
        Component(name="urllib3", version="2.31.0", ecosystem="pypi", purl="pkg:pypi/requests@2.31.0"),
        Component(name="requests", version="2.32.0", ecosystem="pypi", purl="pkg:pypi/requests@2.31.0"),
    ],
    ids=["ecosystem", "package-name", "version"],
)
def test_canonicalize_component_identity_rejects_conflicting_purl_metadata(component: Component) -> None:
    with pytest.raises(ComponentIdentityError, match="conflicting_metadata") as exc_info:
        canonicalize_component_identity(component)

    assert exc_info.value.code is ComponentIdentityDiagnosticCode.CONFLICTING_METADATA
