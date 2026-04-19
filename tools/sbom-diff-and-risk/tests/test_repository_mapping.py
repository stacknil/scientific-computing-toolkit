from __future__ import annotations

from sbom_diff_risk.models import Component
from sbom_diff_risk.repository_mapping import map_component_to_repository


def test_map_component_to_repository_accepts_direct_github_repository_url() -> None:
    component = Component(
        name="requests",
        version="2.32.0",
        ecosystem="pypi",
        source_url="https://github.com/psf/requests",
        evidence={"source_format": "cyclonedx-json"},
    )

    mapping = map_component_to_repository(component)

    assert mapping is not None
    assert mapping.canonical_name == "github.com/psf/requests"
    assert mapping.source == "component.source_url"


def test_map_component_to_repository_prefers_explicit_vcs_reference() -> None:
    component = Component(
        name="requests",
        version="2.32.0",
        ecosystem="pypi",
        source_url="https://pypi.org/project/requests/",
        evidence={
            "source_format": "cyclonedx-json",
            "component": {
                "externalReferences": [
                    {"type": "website", "url": "https://pypi.org/project/requests/"},
                    {"type": "vcs", "url": "https://github.com/psf/requests"},
                ]
            },
        },
    )

    mapping = map_component_to_repository(component)

    assert mapping is not None
    assert mapping.canonical_name == "github.com/psf/requests"
    assert mapping.source == "cyclonedx.externalReferences.vcs"


def test_map_component_to_repository_rejects_website_repository_hint_as_low_confidence() -> None:
    component = Component(
        name="requests",
        version="2.32.0",
        ecosystem="pypi",
        source_url="https://github.com/psf/requests",
        evidence={
            "source_format": "cyclonedx-json",
            "component": {
                "externalReferences": [
                    {"type": "website", "url": "https://github.com/psf/requests"},
                ]
            },
        },
    )

    assert map_component_to_repository(component) is None


def test_map_component_to_repository_rejects_registry_url_without_explicit_repo() -> None:
    component = Component(
        name="urllib3",
        version="2.2.1",
        ecosystem="pypi",
        source_url="https://pypi.org/project/urllib3/2.2.1/",
        evidence={"source_format": "requirements-txt"},
    )

    assert map_component_to_repository(component) is None


def test_map_component_to_repository_rejects_deep_repository_paths() -> None:
    component = Component(
        name="requests",
        version="2.32.0",
        ecosystem="pypi",
        source_url="https://github.com/psf/requests/tree/main",
        evidence={"source_format": "cyclonedx-json"},
    )

    assert map_component_to_repository(component) is None


def test_map_component_to_repository_rejects_ambiguous_explicit_repositories() -> None:
    component = Component(
        name="example",
        version="1.0.0",
        ecosystem="pypi",
        evidence={
            "source_format": "cyclonedx-json",
            "component": {
                "externalReferences": [
                    {"type": "vcs", "url": "https://github.com/example/one"},
                    {"type": "vcs", "url": "https://github.com/example/two"},
                ]
            },
        },
    )

    assert map_component_to_repository(component) is None


def test_map_component_to_repository_accepts_explicit_spdx_vcs_reference() -> None:
    component = Component(
        name="requests",
        version="2.32.0",
        ecosystem="pypi",
        evidence={
            "source_format": "spdx-json",
            "package": {
                "externalRefs": [
                    {
                        "referenceType": "vcs",
                        "referenceLocator": "https://github.com/psf/requests",
                    }
                ]
            },
        },
    )

    mapping = map_component_to_repository(component)

    assert mapping is not None
    assert mapping.canonical_name == "github.com/psf/requests"
    assert mapping.source == "spdx.externalRefs.vcs"


def test_map_component_to_repository_rejects_spdx_homepage_repository_hint_as_low_confidence() -> None:
    component = Component(
        name="requests",
        version="2.32.0",
        ecosystem="pypi",
        source_url="https://github.com/psf/requests",
        evidence={
            "source_format": "spdx-json",
            "package": {
                "homepage": "https://github.com/psf/requests",
            },
        },
    )

    assert map_component_to_repository(component) is None
