# Policy schema

`sbom-diff-and-risk` supports YAML-only policy schemas in versions `1`, `2`, and `3` for the local, provenance-aware, and optional Scorecard-aware policy flows described here.

The schema is intentionally conservative and fail-closed:

- unknown rule ids are rejected
- unknown top-level keys are rejected
- invalid types are rejected
- version `1` remains the v0.2-compatible schema and existing v0.2 policies continue to work unchanged
- version `2` adds provenance-aware gating for explicit PyPI enrichment evidence
- version `3` adds optional Scorecard-aware gating for explicitly requested Scorecard enrichment

## Version 1 fields

- `version: 1`
- `block_on: [rule_id, ...]`
- `warn_on: [rule_id, ...]`
- `max_added_packages: int`
- `allow_sources: [host, ...]`
- `ignore_rules: [rule_id, ...]`

## Version 1 supported rule ids

- `new_package`
- `major_upgrade`
- `version_change_unclassified`
- `unknown_license`
- `suspicious_source`
- `stale_package`
- `max_added_packages`
- `allow_sources`

## Version 2 fields

Version `2` supports every version `1` field plus:

- `require_attestations_for_new_packages: bool`
- `require_provenance_for_suspicious_sources: bool`
- `allow_unattested_packages: [package_name, ...]`
- `allow_provenance_publishers: [publisher_kind, ...]`
- `allow_unattested_publishers: [publisher_kind, ...]` as an accepted compatibility alias for `allow_provenance_publishers`

`allow_provenance_publishers` is the canonical publisher override field. The parser also accepts `allow_unattested_publishers` as an alias when teams want a more explicit override-style name in review. Neither field treats missing attestations as trusted; they only constrain which attested publisher kinds count as verified provenance.

## Version 2 supported rule ids

Version `2` supports every version `1` rule id plus:

- `missing_attestation`
- `unverified_provenance`
- `provenance_unavailable`
- `provenance_required`

## Version 3 fields

Version `3` supports every version `1` and `2` field plus:

- `minimum_scorecard_score: float`

`minimum_scorecard_score` is advisory by itself. It only affects policy outcomes when you also opt into the `scorecard_below_threshold` rule through `block_on`, `warn_on`, or `ignore_rules`.

## Version 3 supported rule ids

Version `3` supports every version `1` and `2` rule id plus:

- `scorecard_below_threshold`

## Semantics

- `block_on` turns matching rule ids into blocking violations.
- `warn_on` turns matching rule ids into warnings.
- If a rule is present in both `block_on` and `warn_on`, block wins.
- `max_added_packages` enforces a deterministic threshold on the added component count.
- `allow_sources` enforces exact host matches against `source_url` hosts for added and changed components.
- `ignore_rules` suppresses matching rule ids entirely.
- `missing_attestation` means PyPI release metadata was fetched successfully but no attestations were present.
- `provenance_unavailable` means the run did not have usable provenance evidence for that package, for example because enrichment was disabled, unsupported, or failed.
- `unverified_provenance` means attestations were present, but the provenance could not be verified against publisher metadata.
- `provenance_required` is a policy-only rule emitted when an explicit provenance requirement was not satisfied.
- `require_attestations_for_new_packages` applies only to added PyPI packages.
- `require_provenance_for_suspicious_sources` applies only when the component also triggered `suspicious_source`.
- `allow_unattested_packages` is a narrow package-name override for explicit missing-attestation exceptions only.
- `allow_unattested_packages` does not waive `provenance_unavailable` or `unverified_provenance`; those remain separate, reviewable policy decisions.
- `allow_provenance_publishers` and `allow_unattested_publishers` apply only when attestations exist and publisher kinds are available to verify.
- when enrichment is disabled, deterministic local mode is unchanged unless a provenance-aware policy explicitly turns unavailable evidence into a warning or block.
- `minimum_scorecard_score` does not create alerts or blocks on its own; it only becomes enforceable when `scorecard_below_threshold` is configured explicitly.
- Scorecard evidence remains an auxiliary trust signal. A high score is not proof of safety, and missing Scorecard data is not proof of risk.

## Version 1 example

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

## Version 2 example

```yaml
version: 2
block_on:
  - provenance_required
  - provenance_unavailable
warn_on:
  - missing_attestation
require_attestations_for_new_packages: true
require_provenance_for_suspicious_sources: true
allow_unattested_packages:
  - pip
allow_unattested_publishers:
  - github actions
```

## Version 3 example

```yaml
version: 3
warn_on:
  - scorecard_below_threshold
minimum_scorecard_score: 7.0
```
