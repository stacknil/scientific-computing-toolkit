from __future__ import annotations

import pytest

from sbom_diff_risk.component_identity import CanonicalComponentIdentity, canonicalize_component_identity
from sbom_diff_risk.errors import ComponentIdentityDiagnosticCode, ComponentIdentityError
from sbom_diff_risk.models import Component


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


def test_canonicalize_component_identity_preserves_unregistered_name_case() -> None:
    component = Component(
        name="EnterpriseLibrary.Common",
        version="6.0.1304",
        ecosystem="nuget",
        purl="pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
    )

    identity = canonicalize_component_identity(component)

    assert identity.package_name == "EnterpriseLibrary.Common"
    assert identity.purl == "pkg:nuget/EnterpriseLibrary.Common@6.0.1304"
    assert identity.component_key == "purl:pkg:nuget/EnterpriseLibrary.Common"


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
