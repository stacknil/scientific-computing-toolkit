from __future__ import annotations

from pathlib import Path
from typing import Iterable

import yaml

from .errors import PolicyError
from .policy_models import PolicyConfig, SUPPORTED_POLICY_RULE_IDS

_SUPPORTED_POLICY_KEYS = {
    "version",
    "block_on",
    "warn_on",
    "max_added_packages",
    "allow_sources",
    "ignore_rules",
}


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
    if version != 1:
        raise PolicyError(f"Invalid policy schema in {path}: only version 1 is supported.")

    block_on = _parse_rule_list(payload.get("block_on", []), f"{path}: block_on")
    warn_on = _parse_rule_list(payload.get("warn_on", []), f"{path}: warn_on")
    ignore_rules = _parse_rule_list(payload.get("ignore_rules", []), f"{path}: ignore_rules")

    max_added_packages = payload.get("max_added_packages")
    if max_added_packages is not None and (not isinstance(max_added_packages, int) or max_added_packages < 0):
        raise PolicyError(f"Invalid policy schema in {path}: max_added_packages must be a non-negative integer.")

    allow_sources = _parse_string_list(payload.get("allow_sources", []), f"{path}: allow_sources", lower=True)

    return normalize_policy(
        PolicyConfig(
            version=version,
            block_on=block_on,
            warn_on=warn_on,
            max_added_packages=max_added_packages,
            allow_sources=allow_sources,
            ignore_rules=ignore_rules,
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
        rendered_path = str(policy_path)

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
    )
    return normalize_policy(merged), rendered_path


def normalize_policy(policy: PolicyConfig) -> PolicyConfig:
    block_on = tuple(dict.fromkeys(policy.block_on))
    warn_on = tuple(rule for rule in dict.fromkeys(policy.warn_on) if rule not in block_on)
    ignore_rules = tuple(dict.fromkeys(policy.ignore_rules))
    return PolicyConfig(
        version=policy.version,
        block_on=block_on,
        warn_on=warn_on,
        max_added_packages=policy.max_added_packages,
        allow_sources=tuple(dict.fromkeys(policy.allow_sources)),
        ignore_rules=ignore_rules,
    )


def parse_rule_csv(value: str | None, source_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    entries = [entry.strip() for entry in value.split(",")]
    parsed = [entry for entry in entries if entry]
    if not parsed:
        raise PolicyError(f"{source_name} requires at least one rule id.")
    return _validate_rule_ids(parsed, source_name)


def _parse_rule_list(value: object, context: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise PolicyError(f"Invalid policy schema in {context}: expected a YAML list of rule ids.")
    if not all(isinstance(item, str) for item in value):
        raise PolicyError(f"Invalid policy schema in {context}: all rule ids must be strings.")
    return _validate_rule_ids(value, context)


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


def _validate_rule_ids(rule_ids: Iterable[str], context: str) -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(rule_id.strip() for rule_id in rule_ids if rule_id.strip()))
    unknown = sorted(set(normalized) - set(SUPPORTED_POLICY_RULE_IDS))
    if unknown:
        raise PolicyError(
            f"Unknown rule id(s) in {context}: {', '.join(unknown)}. "
            f"Supported rule ids: {', '.join(SUPPORTED_POLICY_RULE_IDS)}."
        )
    return normalized


def _merge_strings(base: tuple[str, ...], extra: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys((*base, *extra)))
