from __future__ import annotations

from typing import Iterable

from .models import Component, ComponentChange


def component_key(component: Component) -> str:
    """Return a stable identity with purl -> bom_ref -> (ecosystem, name)."""
    if component.purl:
        return f"purl:{_purl_identity(component.purl)}"
    if component.bom_ref:
        return f"bom-ref:{component.bom_ref.strip().lower()}"
    ecosystem = component.ecosystem.strip().lower()
    name = component.name.strip().lower()
    return f"coord:{ecosystem}:{name}"


def _purl_identity(purl: str) -> str:
    candidate = purl.strip().lower()
    if not candidate.startswith("pkg:"):
        return candidate

    end = len(candidate)
    for separator in ("?", "#"):
        position = candidate.find(separator)
        if position != -1:
            end = min(end, position)

    base = candidate[:end]
    version_separator = base.rfind("@")
    name_separator = base.rfind("/")
    if version_separator != -1 and version_separator > name_separator:
        return base[:version_separator]

    return base


def _component_signature(component: Component) -> tuple[object, ...]:
    return (
        component.name,
        component.version,
        component.ecosystem,
        component.purl,
        component.license_id,
        component.supplier,
        component.source_url,
        component.bom_ref,
        component.raw_type,
    )


def diff_components(
    before: Iterable[Component],
    after: Iterable[Component],
) -> tuple[list[Component], list[Component], list[ComponentChange]]:
    before_map = _index_components(before, side="before")
    after_map = _index_components(after, side="after")

    added_keys = sorted(set(after_map) - set(before_map))
    removed_keys = sorted(set(before_map) - set(after_map))
    shared_keys = sorted(set(before_map) & set(after_map))

    added = [after_map[key] for key in added_keys]
    removed = [before_map[key] for key in removed_keys]
    changed: list[ComponentChange] = []

    for key in shared_keys:
        before_component = before_map[key]
        after_component = after_map[key]
        if _component_signature(before_component) == _component_signature(after_component):
            continue

        classification = "version_changed"
        if before_component.version == after_component.version:
            classification = "metadata_changed"

        changed.append(
            ComponentChange(
                key=key,
                before=before_component,
                after=after_component,
                classification=classification,
            )
        )

    return added, removed, changed


def _index_components(components: Iterable[Component], side: str) -> dict[str, Component]:
    indexed: dict[str, Component] = {}
    for component in components:
        key = component_key(component)
        if key in indexed:
            raise ValueError(f"Duplicate component identity in {side} input: {key}")
        indexed[key] = component
    return indexed
