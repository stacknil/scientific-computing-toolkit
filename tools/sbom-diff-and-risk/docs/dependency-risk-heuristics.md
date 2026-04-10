# Dependency risk heuristics

`sbom-diff-and-risk` classifies change-related heuristics. It does not claim vulnerability truth.

## Implemented buckets

The current rules are intentionally conservative:

- `new_package`: a component appears only in the after input.
- `major_upgrade`: strict SemVer `x.y.z` major version increase.
- `version_change_unclassified`: version changed, but not a clear SemVer major bump.
- `unknown_license`: license metadata is missing or explicitly unknown.
- `suspicious_source`: provenance fields are missing or use suspicious schemes or hosts.
- `stale_package`: reserved for future enrichment work. When enrichment is disabled, the tool emits `not_evaluated` instead of guessing.

## Conservative rule notes

- `new_package` is a change signal, not a vulnerability claim.
- `major_upgrade` fires only when both versions look reliably parseable as strict SemVer.
- uncertain version changes fall back to `version_change_unclassified`.
- suspicious source is a provenance-quality heuristic, not a malware verdict.
- missing metadata is reported as unknown rather than silently treated as safe.
- `not_evaluated` means the stale-package question was intentionally left unanswered offline.

## Deferred work

- real `stale_package` evaluation behind explicit enrichment
- ecosystem-specific trust rules
- advisory and CVE enrichment
- configurable risk policy profiles
