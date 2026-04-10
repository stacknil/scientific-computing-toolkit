from __future__ import annotations

from pathlib import Path

from ..errors import ParseError
from ..models import Component
from .common import extract_ecosystem, load_json_object, optional_str, require_list, require_mapping, required_str


def parse(path: Path) -> list[Component]:
    payload = load_json_object(path, "SPDX")
    spdx_version = optional_str(payload.get("spdxVersion"), f"{path}: spdxVersion")
    if spdx_version is None:
        raise ParseError(f"Unsupported SPDX input in {path}: missing spdxVersion.")

    raw_packages = payload.get("packages", [])
    if raw_packages is None:
        raw_packages = []
    packages = require_list(raw_packages, f"{path}: packages")

    normalized: list[Component] = []
    for index, raw_package in enumerate(packages, start=1):
        package = require_mapping(raw_package, f"{path}: packages[{index}]")
        purl = _extract_purl(package, path, index)
        source_candidates = _extract_source_urls(package, path, index)
        normalized.append(
            Component(
                name=required_str(package.get("name"), f"{path}: packages[{index}].name"),
                version=optional_str(package.get("versionInfo"), f"{path}: packages[{index}].versionInfo"),
                ecosystem=extract_ecosystem(purl, source_candidates),
                purl=purl,
                license_id=_extract_license_id(package, path, index),
                supplier=_extract_supplier(package, path, index),
                source_url=source_candidates[0] if source_candidates else None,
                bom_ref=optional_str(package.get("SPDXID"), f"{path}: packages[{index}].SPDXID"),
                raw_type=optional_str(
                    package.get("primaryPackagePurpose"),
                    f"{path}: packages[{index}].primaryPackagePurpose",
                ),
                evidence={
                    "source_format": "spdx-json",
                    "package": package,
                },
            )
        )

    return normalized


def _extract_purl(package: dict[str, object], path: Path, index: int) -> str | None:
    raw_external_refs = package.get("externalRefs", [])
    if raw_external_refs is None:
        return None
    external_refs = require_list(raw_external_refs, f"{path}: packages[{index}].externalRefs")
    for ref_index, raw_ref in enumerate(external_refs, start=1):
        reference = require_mapping(raw_ref, f"{path}: packages[{index}].externalRefs[{ref_index}]")
        reference_type = optional_str(reference.get("referenceType"), f"{path}: referenceType")
        locator = optional_str(reference.get("referenceLocator"), f"{path}: referenceLocator")
        if reference_type == "purl" and locator:
            return locator
    return None


def _extract_source_urls(package: dict[str, object], path: Path, index: int) -> list[str]:
    urls: list[str] = []
    homepage = optional_str(package.get("homepage"), f"{path}: packages[{index}].homepage")
    if homepage and homepage != "NOASSERTION":
        urls.append(homepage)
    download_location = optional_str(package.get("downloadLocation"), f"{path}: packages[{index}].downloadLocation")
    if download_location and download_location != "NOASSERTION":
        urls.append(download_location)

    raw_external_refs = package.get("externalRefs", [])
    if raw_external_refs is None:
        return urls
    external_refs = require_list(raw_external_refs, f"{path}: packages[{index}].externalRefs")
    for ref_index, raw_ref in enumerate(external_refs, start=1):
        reference = require_mapping(raw_ref, f"{path}: packages[{index}].externalRefs[{ref_index}]")
        locator = optional_str(reference.get("referenceLocator"), f"{path}: externalRefs[{ref_index}].referenceLocator")
        reference_type = optional_str(reference.get("referenceType"), f"{path}: externalRefs[{ref_index}].referenceType")
        if locator and reference_type != "purl":
            urls.append(locator)
    return urls


def _extract_license_id(package: dict[str, object], path: Path, index: int) -> str | None:
    for field in ("licenseConcluded", "licenseDeclared"):
        value = optional_str(package.get(field), f"{path}: packages[{index}].{field}")
        if value:
            return value
    return None


def _extract_supplier(package: dict[str, object], path: Path, index: int) -> str | None:
    supplier = optional_str(package.get("supplier"), f"{path}: packages[{index}].supplier")
    if supplier:
        return supplier
    return optional_str(package.get("originator"), f"{path}: packages[{index}].originator")
