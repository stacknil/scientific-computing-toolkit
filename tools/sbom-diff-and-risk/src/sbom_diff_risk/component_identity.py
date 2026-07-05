from __future__ import annotations

from dataclasses import dataclass

from packaging.utils import canonicalize_name
from packageurl import PackageURL

from .errors import ComponentIdentityDiagnosticCode, ComponentIdentityError
from .models import Component


@dataclass(slots=True, frozen=True)
class EcosystemCanonicalizationRule:
    ecosystem: str
    package_name_rule: str
    namespace_rule: str
    version_rule: str


@dataclass(slots=True, frozen=True)
class CanonicalComponentIdentity:
    ecosystem: str
    package_name: str
    version: str | None
    purl: str | None
    component_key: str


_REGISTERED_CANONICALIZATION_RULES: dict[str, EcosystemCanonicalizationRule] = {
    "generic": EcosystemCanonicalizationRule(
        ecosystem="generic",
        package_name_rule="preserve-observed",
        namespace_rule="preserve-purl-namespace",
        version_rule="preserve-observed",
    ),
    "maven": EcosystemCanonicalizationRule(
        ecosystem="maven",
        package_name_rule="preserve-observed",
        namespace_rule="preserve-purl-namespace",
        version_rule="preserve-observed",
    ),
    "npm": EcosystemCanonicalizationRule(
        ecosystem="npm",
        package_name_rule="packageurl-npm-name",
        namespace_rule="preserve-purl-namespace",
        version_rule="preserve-observed",
    ),
    "nuget": EcosystemCanonicalizationRule(
        ecosystem="nuget",
        package_name_rule="preserve-observed",
        namespace_rule="preserve-purl-namespace",
        version_rule="preserve-observed",
    ),
    "pypi": EcosystemCanonicalizationRule(
        ecosystem="pypi",
        package_name_rule="pep503",
        namespace_rule="preserve-purl-namespace",
        version_rule="preserve-observed",
    ),
}


def canonicalization_rules() -> tuple[EcosystemCanonicalizationRule, ...]:
    return tuple(_REGISTERED_CANONICALIZATION_RULES[name] for name in sorted(_REGISTERED_CANONICALIZATION_RULES))


def canonicalization_rule_for_ecosystem(ecosystem: str) -> EcosystemCanonicalizationRule:
    normalized_ecosystem = ecosystem.strip().lower()
    if normalized_ecosystem in _REGISTERED_CANONICALIZATION_RULES:
        return _REGISTERED_CANONICALIZATION_RULES[normalized_ecosystem]
    return EcosystemCanonicalizationRule(
        ecosystem=normalized_ecosystem,
        package_name_rule="preserve-observed",
        namespace_rule="preserve-purl-namespace",
        version_rule="preserve-observed",
    )


def canonicalize_component_identity(component: Component) -> CanonicalComponentIdentity:
    explicit_ecosystem = component.ecosystem.strip().lower()
    explicit_name = _canonical_package_name(explicit_ecosystem, component.name)
    explicit_version = _optional_str(component.version)

    if component.purl is None:
        if component.bom_ref:
            component_key = f"bom-ref:{component.bom_ref.strip().lower()}"
        else:
            component_key = f"coord:{explicit_ecosystem}:{explicit_name}"
        return CanonicalComponentIdentity(
            ecosystem=explicit_ecosystem,
            package_name=explicit_name,
            version=explicit_version,
            purl=None,
            component_key=component_key,
        )

    parsed = _parse_purl(component.purl)
    purl_ecosystem = parsed.type.strip().lower()
    purl_name = _canonical_package_name(purl_ecosystem, parsed.name)
    purl_version = _optional_str(parsed.version)

    conflicts: list[str] = []
    if explicit_ecosystem != purl_ecosystem:
        conflicts.append(f"ecosystem={explicit_ecosystem!r} disagrees with purl type={purl_ecosystem!r}")
    if explicit_name != purl_name:
        conflicts.append(f"package name={explicit_name!r} disagrees with purl name={purl_name!r}")
    if explicit_version is not None and purl_version is not None and explicit_version != purl_version:
        conflicts.append(f"version={explicit_version!r} disagrees with purl version={purl_version!r}")
    if conflicts:
        raise ComponentIdentityError(
            ComponentIdentityDiagnosticCode.CONFLICTING_METADATA,
            "; ".join(conflicts),
            component_key=_purl_component_key(parsed, purl_ecosystem, purl_name),
        )

    canonical_version = purl_version or explicit_version
    canonical_purl = _canonical_purl(parsed, purl_ecosystem, purl_name, purl_version)
    return CanonicalComponentIdentity(
        ecosystem=purl_ecosystem,
        package_name=purl_name,
        version=canonical_version,
        purl=canonical_purl,
        component_key=_purl_component_key(parsed, purl_ecosystem, purl_name),
    )


def _parse_purl(raw_purl: str) -> PackageURL:
    try:
        return PackageURL.from_string(raw_purl.strip())
    except ValueError as exc:
        raise ComponentIdentityError(
            ComponentIdentityDiagnosticCode.CONFLICTING_METADATA,
            f"purl is not valid: {exc}",
        ) from exc


def _canonical_purl(
    parsed: PackageURL,
    ecosystem: str,
    package_name: str,
    version: str | None,
) -> str:
    return PackageURL(
        type=ecosystem,
        namespace=parsed.namespace,
        name=package_name,
        version=version,
        qualifiers=parsed.qualifiers,
        subpath=parsed.subpath,
    ).to_string()


def _purl_component_key(parsed: PackageURL, ecosystem: str, package_name: str) -> str:
    identity_purl = PackageURL(
        type=ecosystem,
        namespace=parsed.namespace,
        name=package_name,
    ).to_string()
    return f"purl:{identity_purl}"


def _canonical_package_name(ecosystem: str, name: str) -> str:
    stripped = name.strip()
    rule = canonicalization_rule_for_ecosystem(ecosystem)
    if rule.package_name_rule == "pep503":
        return canonicalize_name(stripped)
    if rule.package_name_rule == "packageurl-npm-name":
        return stripped.lower()
    if rule.package_name_rule == "preserve-observed":
        return stripped
    raise AssertionError(f"unknown package name canonicalization rule: {rule.package_name_rule}")


def _optional_str(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None
