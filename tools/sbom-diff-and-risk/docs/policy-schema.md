# Policy schema

`sbom-diff-and-risk` supports a YAML-only policy schema in v1.

The schema is intentionally conservative and fail-closed:

- unknown rule ids are rejected
- unknown top-level keys are rejected
- invalid types are rejected
- only schema version `1` is supported

## Fields

- `version: 1`
- `block_on: [rule_id, ...]`
- `warn_on: [rule_id, ...]`
- `max_added_packages: int`
- `allow_sources: [host, ...]`
- `ignore_rules: [rule_id, ...]`

## Supported rule ids

- `new_package`
- `major_upgrade`
- `version_change_unclassified`
- `unknown_license`
- `suspicious_source`
- `stale_package`
- `max_added_packages`
- `allow_sources`

## Semantics

- `block_on` turns matching rule ids into blocking violations.
- `warn_on` turns matching rule ids into warnings.
- If a rule is present in both `block_on` and `warn_on`, block wins.
- `max_added_packages` enforces a deterministic threshold on the added component count.
- `allow_sources` enforces exact host matches against `source_url` hosts for added and changed components.
- `ignore_rules` suppresses matching rule ids entirely.

## Example

```yaml
version: 1
block_on:
  - unknown_license
  - stale_package
warn_on:
  - new_package
max_added_packages: 2
allow_sources:
  - pypi.org
  - files.pythonhosted.org
ignore_rules:
  - major_upgrade
```
