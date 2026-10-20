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
- Eligibility follows the [SemVer 2.0.0 grammar](https://semver.org/spec/v2.0.0.html):
  ASCII `major.minor.patch`, optional prerelease identifiers and optional build
  metadata. Empty identifiers and leading zeroes in core or numeric prerelease
  identifiers are ineligible; numeric build identifiers may have leading zeroes.
  Outer whitespace and one lowercase `v` prefix remain supported tool extensions.
- Only the validated major integers are compared. Prerelease-to-final,
  final-to-prerelease, build-only changes and major decreases remain unclassified
  when the canonical strings differ. No package-manager precedence is inferred.
- uncertain version changes fall back to `version_change_unclassified`.
- Version comparison uses the same canonical identity as the diff: a PURL version
  is evidence even when the explicit version field is absent. Conflicting explicit
  and PURL versions still fail closed; original component fields remain unchanged.
- Both canonical versions must be known for a version risk bucket. Equal versions
  and missing-version transitions do not imply an upgrade. The SemVer check is a
  syntactic heuristic and does not infer package-manager ordering or compatibility.
- suspicious source is a provenance-quality heuristic, not a malware verdict.
- missing metadata is reported as unknown rather than silently treated as safe.
- `not_evaluated` means the stale-package question was intentionally left unanswered offline.

## Deferred work

- real `stale_package` evaluation behind explicit enrichment
- provenance-based policy gates over opt-in enrichment evidence
- ecosystem-specific trust rules
- advisory and CVE enrichment
- configurable risk policy profiles
