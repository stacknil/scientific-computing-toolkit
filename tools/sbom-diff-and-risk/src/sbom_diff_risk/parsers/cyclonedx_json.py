from __future__ import annotations

from pathlib import Path

from ..errors import ParseError
from ..models import Component
from .common import extract_ecosystem, load_json_object, optional_str, require_list, require_mapping, required_str


def parse(path: Path) -> list[Component]:
    payload = load_json_object(path, "CycloneDX")
    bom_format = optional_str(payload.get("bomFormat"), f"{path}: bomFormat")
    if bom_format != "CycloneDX":
        raise ParseError(f"Unsupported CycloneDX input in {path}: bomFormat must be 'CycloneDX'.")

    raw_components = payload.get("components", [])
    if raw_components is None:
        raw_components = []
    components = require_list(raw_components, f"{path}: components")

    normalized: list[Component] = []
    for index, raw_component in enumerate(components, start=1):
        component = require_mapping(raw_component, f"{path}: components[{index}]")
        purl = optional_str(component.get("purl"), f"{path}: components[{index}].purl")
        bom_ref = optional_str(component.get("bom-ref"), f"{path}: components[{index}].bom-ref")
        source_urls = _extract_external_reference_urls(component, path, index)
        normalized.append(
            Component(
                name=required_str(component.get("name"), f"{path}: components[{index}].name"),
                version=optional_str(component.get("version"), f"{path}: components[{index}].version"),
                ecosystem=extract_ecosystem(purl, source_urls),
                purl=purl,
                license_id=_extract_license_id(component, path, index),
                supplier=_extract_supplier(component, path, index),
                source_url=source_urls[0] if source_urls else None,
                bom_ref=bom_ref,
                raw_type=optional_str(component.get("type"), f"{path}: components[{index}].type"),
                evidence={
                    "source_format": "cyclonedx-json",
                    "component": component,
                },
            )
        )

    return normalized


def _extract_external_reference_urls(component: dict[str, object], path: Path, index: int) -> list[str]:
    raw_refs = component.get("externalReferences", [])
    if raw_refs is None:
        return []
    references = require_list(raw_refs, f"{path}: components[{index}].externalReferences")

    urls: list[str] = []
    prioritized: list[str] = []
    for ref_index, raw_reference in enumerate(references, start=1):
        reference = require_mapping(raw_reference, f"{path}: components[{index}].externalReferences[{ref_index}]")
        url = optional_str(reference.get("url"), f"{path}: external reference url")
        if not url:
            continue
        urls.append(url)
        ref_type = optional_str(reference.get("type"), f"{path}: external reference type")
        if ref_type in {"vcs", "distribution", "website"}:
            prioritized.append(url)
    return prioritized or urls


def _extract_license_id(component: dict[str, object], path: Path, index: int) -> str | None:
    raw_licenses = component.get("licenses", [])
    if raw_licenses is None:
        return None
    licenses = require_list(raw_licenses, f"{path}: components[{index}].licenses")
    for license_index, raw_license in enumerate(licenses, start=1):
        entry = require_mapping(raw_license, f"{path}: components[{index}].licenses[{license_index}]")
        expression = optional_str(entry.get("expression"), f"{path}: license expression")
        if expression:
            return expression

        license_object = entry.get("license")
        if license_object is None:
            continue
        license_mapping = require_mapping(license_object, f"{path}: license object")
        license_id = optional_str(license_mapping.get("id"), f"{path}: license id")
        if license_id:
            return license_id
        license_name = optional_str(license_mapping.get("name"), f"{path}: license name")
        if license_name:
            return license_name
    return None


def _extract_supplier(component: dict[str, object], path: Path, index: int) -> str | None:
    raw_supplier = component.get("supplier")
    if raw_supplier is None:
        return optional_str(component.get("author"), f"{path}: components[{index}].author")
    if isinstance(raw_supplier, str):
        return optional_str(raw_supplier, f"{path}: components[{index}].supplier")
    supplier = require_mapping(raw_supplier, f"{path}: components[{index}].supplier")
    return optional_str(supplier.get("name"), f"{path}: components[{index}].supplier.name")
