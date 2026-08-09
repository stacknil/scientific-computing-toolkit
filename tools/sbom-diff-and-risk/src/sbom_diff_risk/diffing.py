from __future__ import annotations

from typing import Iterable

from .component_identity import canonicalize_component_identity
from .errors import ComponentIdentityDiagnosticCode, ComponentIdentityError
from .models import Component, ComponentChange


def component_key(component: Component) -> str:
    """Return a stable identity with purl -> bom_ref -> (ecosystem, name)."""
    return canonicalize_component_identity(component).component_key


def _component_signature(component: Component) -> tuple[object, ...]:
    identity = canonicalize_component_identity(component)
    return (
        identity,
        _normalized_metadata(component.license_id),
        _normalized_metadata(component.supplier),
        _normalized_metadata(component.source_url),
        _normalized_metadata(component.bom_ref),
        _normalized_metadata(component.raw_type, lower=True),
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

        before_identity = canonicalize_component_identity(before_component)
        after_identity = canonicalize_component_identity(after_component)
        classification = (
            "version_changed" if before_identity.version != after_identity.version else "metadata_changed"
        )

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
        try:
            key = component_key(component)
        except ComponentIdentityError as exc:
            raise ComponentIdentityError(
                exc.code,
                f"{exc.detail} in {side} input",
                side=side,
                component_key=exc.component_key,
            ) from exc
        if key in indexed:
            existing = indexed[key]
            if _component_signature(existing) == _component_signature(component):
                code = ComponentIdentityDiagnosticCode.DUPLICATE_COMPONENT
                label = "duplicate component"
            else:
                code = ComponentIdentityDiagnosticCode.CONFLICTING_METADATA
                label = "conflicting metadata"
            raise ComponentIdentityError(
                code,
                f"{label} in {side} input for {key}",
                side=side,
                component_key=key,
            )
        indexed[key] = component
    return indexed


def _normalized_metadata(value: str | None, *, lower: bool = False) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if lower:
        normalized = normalized.lower()
    return normalized or None
