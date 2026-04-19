from __future__ import annotations

import math
from pathlib import Path
from typing import Iterable

import yaml

from .errors import PolicyError
from .policy_models import (
    PolicyConfig,
    SUPPORTED_POLICY_RULE_IDS,
    V1_SUPPORTED_POLICY_RULE_IDS,
    V2_PROVENANCE_POLICY_RULE_IDS,
    V3_SCORECARD_POLICY_RULE_IDS,
)

_V1_SUPPORTED_POLICY_KEYS = {
    "version",
    "block_on",
    "warn_on",
    "max_added_packages",
    "allow_sources",
    "ignore_rules",
}

_V2_ONLY_POLICY_KEYS = {
    "require_attestations_for_new_packages",
    "require_provenance_for_suspicious_sources",
    "allow_unattested_packages",
    "allow_provenance_publishers",
    "allow_unattested_publishers",
}

_V3_ONLY_POLICY_KEYS = {
    "minimum_scorecard_score",
}

_SUPPORTED_POLICY_KEYS = _V1_SUPPORTED_POLICY_KEYS | _V2_ONLY_POLICY_KEYS | _V3_ONLY_POLICY_KEYS


def load_policy(path: Path) -> PolicyConfig:
    if not path.is_file():
        raise FileNotFoundError(f"policy file does not exist: {path}")

    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"Malformed YAML policy in {path}: {exc}.") from exc

    if not isinstance(payload, dict):
        raise PolicyError(f"Invalid policy schema in {path}: top-level YAML value must be a mapping.")

    unknown_keys = sorted(set(payload) - _SUPPORTED_POLICY_KEYS)
    if unknown_keys:
        raise PolicyError(f"Invalid policy schema in {path}: unsupported keys: {', '.join(unknown_keys)}.")

    version = payload.get("version")
    if not isinstance(version, int):
        raise PolicyError(f"Invalid policy schema in {path}: version must be an integer.")
    if version not in {1, 2, 3}:
        raise PolicyError(f"Invalid policy schema in {path}: only versions 1, 2, and 3 are supported.")

    if version == 1:
        version_unknown_keys = sorted(set(payload) & (_V2_ONLY_POLICY_KEYS | _V3_ONLY_POLICY_KEYS))
        if version_unknown_keys:
            raise PolicyError(
                f"Invalid policy schema in {path}: version 1 does not support keys: {', '.join(version_unknown_keys)}."
            )
    if version == 2:
        version_unknown_keys = sorted(set(payload) & _V3_ONLY_POLICY_KEYS)
        if version_unknown_keys:
            raise PolicyError(
                f"Invalid policy schema in {path}: version 2 does not support keys: {', '.join(version_unknown_keys)}."
            )

    if "allow_provenance_publishers" in payload and "allow_unattested_publishers" in payload:
        raise PolicyError(
            f"Invalid policy schema in {path}: use either allow_provenance_publishers or "
            "allow_unattested_publishers, not both."
        )

    if version == 1:
        supported_rule_ids = V1_SUPPORTED_POLICY_RULE_IDS
    elif version == 2:
        supported_rule_ids = (*V1_SUPPORTED_POLICY_RULE_IDS, *V2_PROVENANCE_POLICY_RULE_IDS)
    else:
        supported_rule_ids = SUPPORTED_POLICY_RULE_IDS

    block_on = _parse_rule_list(payload.get("block_on", []), f"{path}: block_on", supported_rule_ids=supported_rule_ids)
    warn_on = _parse_rule_list(payload.get("warn_on", []), f"{path}: warn_on", supported_rule_ids=supported_rule_ids)
    ignore_rules = _parse_rule_list(
        payload.get("ignore_rules", []),
        f"{path}: ignore_rules",
        supported_rule_ids=supported_rule_ids,
    )

    max_added_packages = payload.get("max_added_packages")
    if max_added_packages is not None and (not isinstance(max_added_packages, int) or max_added_packages < 0):
        raise PolicyError(f"Invalid policy schema in {path}: max_added_packages must be a non-negative integer.")

    allow_sources = _parse_string_list(payload.get("allow_sources", []), f"{path}: allow_sources", lower=True)
    require_attestations_for_new_packages = _parse_bool(
        payload.get("require_attestations_for_new_packages", False),
        f"{path}: require_attestations_for_new_packages",
    )
    require_provenance_for_suspicious_sources = _parse_bool(
        payload.get("require_provenance_for_suspicious_sources", False),
        f"{path}: require_provenance_for_suspicious_sources",
    )
    allow_unattested_packages = _parse_string_list(
        payload.get("allow_unattested_packages", []),
        f"{path}: allow_unattested_packages",
        lower=True,
    )
    allow_provenance_publishers_value = payload.get("allow_provenance_publishers")
    if allow_provenance_publishers_value is None:
        allow_provenance_publishers_value = payload.get("allow_unattested_publishers", [])
        allow_provenance_publishers_context = f"{path}: allow_unattested_publishers"
    else:
        allow_provenance_publishers_context = f"{path}: allow_provenance_publishers"
    allow_provenance_publishers = _parse_string_list(
        allow_provenance_publishers_value,
        allow_provenance_publishers_context,
        lower=True,
    )
    minimum_scorecard_score = _parse_optional_score(
        payload.get("minimum_scorecard_score"),
        f"{path}: minimum_scorecard_score",
    )

    return normalize_policy(
        PolicyConfig(
            version=version,
            block_on=block_on,
            warn_on=warn_on,
            max_added_packages=max_added_packages,
            allow_sources=allow_sources,
            ignore_rules=ignore_rules,
            require_attestations_for_new_packages=require_attestations_for_new_packages,
            require_provenance_for_suspicious_sources=require_provenance_for_suspicious_sources,
            allow_unattested_packages=allow_unattested_packages,
            allow_provenance_publishers=allow_provenance_publishers,
            minimum_scorecard_score=minimum_scorecard_score,
        )
    )


def build_policy(
    *,
    policy_path: Path | None = None,
    fail_on: str | None = None,
    warn_on: str | None = None,
) -> tuple[PolicyConfig | None, str | None]:
    base_policy: PolicyConfig | None = None
    rendered_path: str | None = None
    if policy_path is not None:
        base_policy = load_policy(policy_path)
        rendered_path = _render_policy_path(policy_path)

    cli_block_on = parse_rule_csv(fail_on, "--fail-on")
    cli_warn_on = parse_rule_csv(warn_on, "--warn-on")
    if base_policy is None and not cli_block_on and not cli_warn_on:
        return None, None

    seed = base_policy or PolicyConfig(version=1)
    merged = PolicyConfig(
        version=seed.version,
        block_on=_merge_strings(seed.block_on, cli_block_on),
        warn_on=_merge_strings(seed.warn_on, cli_warn_on),
        max_added_packages=seed.max_added_packages,
        allow_sources=seed.allow_sources,
        ignore_rules=seed.ignore_rules,
        require_attestations_for_new_packages=seed.require_attestations_for_new_packages,
        require_provenance_for_suspicious_sources=seed.require_provenance_for_suspicious_sources,
        allow_unattested_packages=seed.allow_unattested_packages,
        allow_provenance_publishers=seed.allow_provenance_publishers,
        minimum_scorecard_score=seed.minimum_scorecard_score,
    )
    return normalize_policy(merged), rendered_path


def normalize_policy(policy: PolicyConfig) -> PolicyConfig:
    normalized_version = max(policy.version, _required_policy_version(policy))
    block_on = tuple(dict.fromkeys(policy.block_on))
    warn_on = tuple(rule for rule in dict.fromkeys(policy.warn_on) if rule not in block_on)
    ignore_rules = tuple(dict.fromkeys(policy.ignore_rules))
    return PolicyConfig(
        version=normalized_version,
        block_on=block_on,
        warn_on=warn_on,
        max_added_packages=policy.max_added_packages,
        allow_sources=tuple(dict.fromkeys(policy.allow_sources)),
        ignore_rules=ignore_rules,
        require_attestations_for_new_packages=policy.require_attestations_for_new_packages,
        require_provenance_for_suspicious_sources=policy.require_provenance_for_suspicious_sources,
        allow_unattested_packages=tuple(dict.fromkeys(policy.allow_unattested_packages)),
        allow_provenance_publishers=tuple(dict.fromkeys(policy.allow_provenance_publishers)),
        minimum_scorecard_score=policy.minimum_scorecard_score,
    )


def parse_rule_csv(value: str | None, source_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    entries = [entry.strip() for entry in value.split(",")]
    parsed = [entry for entry in entries if entry]
    if not parsed:
        raise PolicyError(f"{source_name} requires at least one rule id.")
    return _validate_rule_ids(parsed, source_name, supported_rule_ids=SUPPORTED_POLICY_RULE_IDS)


def _parse_rule_list(value: object, context: str, *, supported_rule_ids: Iterable[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise PolicyError(f"Invalid policy schema in {context}: expected a YAML list of rule ids.")
    if not all(isinstance(item, str) for item in value):
        raise PolicyError(f"Invalid policy schema in {context}: all rule ids must be strings.")
    return _validate_rule_ids(value, context, supported_rule_ids=supported_rule_ids)


def _parse_string_list(value: object, context: str, *, lower: bool = False) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise PolicyError(f"Invalid policy schema in {context}: expected a YAML list of strings.")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise PolicyError(f"Invalid policy schema in {context}: all values must be non-empty strings.")
        normalized = item.strip()
        if lower:
            normalized = normalized.lower()
        items.append(normalized)
    return tuple(dict.fromkeys(items))


def _parse_bool(value: object, context: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"Invalid policy schema in {context}: expected a boolean value.")
    return value


def _parse_optional_score(value: object, context: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyError(f"Invalid policy schema in {context}: expected a finite number between 0 and 10.")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0 or normalized > 10:
        raise PolicyError(f"Invalid policy schema in {context}: expected a finite number between 0 and 10.")
    return normalized


def _validate_rule_ids(rule_ids: Iterable[str], context: str, *, supported_rule_ids: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(rule_id.strip() for rule_id in rule_ids if rule_id.strip()))
    supported = set(supported_rule_ids)
    unknown = sorted(set(normalized) - supported)
    if unknown:
        raise PolicyError(
            f"Unknown rule id(s) in {context}: {', '.join(unknown)}. "
            f"Supported rule ids: {', '.join(sorted(supported))}."
        )
    return normalized


def _merge_strings(base: tuple[str, ...], extra: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys((*base, *extra)))


def _required_policy_version(policy: PolicyConfig) -> int:
    if any(rule in V3_SCORECARD_POLICY_RULE_IDS for rule in (*policy.block_on, *policy.warn_on, *policy.ignore_rules)):
        return 3
    if policy.minimum_scorecard_score is not None:
        return 3
    if any(rule in V2_PROVENANCE_POLICY_RULE_IDS for rule in (*policy.block_on, *policy.warn_on, *policy.ignore_rules)):
        return 2
    if policy.require_attestations_for_new_packages:
        return 2
    if policy.require_provenance_for_suspicious_sources:
        return 2
    if policy.allow_unattested_packages:
        return 2
    if policy.allow_provenance_publishers:
        return 2
    return 1


def _render_policy_path(policy_path: Path) -> str:
    resolved_policy_path = policy_path.resolve()
    try:
        return resolved_policy_path.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved_policy_path.as_posix()
