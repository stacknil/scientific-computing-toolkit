# sbom-diff-and-risk v1.1.0

`v1.1.0` is the stable v1.1 GitHub Release for `sbom-diff-and-risk`.

The Python package metadata version for this tag is `1.1.0`. The package
authors metadata is intentionally omitted; the public package identity remains
the repository and project name.

## Highlights

- Adds input and policy contract versioning while preserving readable v1.0
  policy and report fields.
- Adds policy decision explainability with stable rule, evidence, reason,
  and confidence fields.
- Adds typed canonical component identity with fail-closed duplicate and
  conflicting-metadata diagnostics.
- Adds an explicit ecosystem canonicalization matrix for PyPI, npm, Maven,
  NuGet, generic, and unknown ecosystems.
- Treats a no-purl `bom_ref` as an opaque local identifier: surrounding
  whitespace is trimmed, case is preserved, and local identifiers are not
  inferred to be aliases.
- Keeps the local CI consumer path, JSON/Markdown/SARIF report surfaces, and
  release artifact verification path available for reviewers.

## Compatibility

- CLI commands and flags remain unchanged.
- Existing v1.0 report fields remain readable for the lifetime of report
  schema v1.
- Legacy policy files remain readable while versioned policy schema identifiers
  are emitted and validated.
- Purl identity remains authoritative over `bom_ref`; a version change remains
  a change rather than an add/remove pair.
- Case-differing opaque bom-refs no longer collide. Exact duplicate identities
  and same-identity conflicting metadata still fail closed.

## Release policy

- `v1.1.0` is the stable GitHub Release contract and GitHub Latest.
- GitHub Release assets are the supported distribution surface for this
  version.
- Production PyPI publishing remains intentionally deferred.
- TestPyPI Trusted Publishing evidence remains evidence of the test publishing
  path only.

## Boundaries

- Default analysis remains local-file based and deterministic.
- Optional PyPI and OpenSSF Scorecard enrichment remains explicit opt-in
  network access.
- No CVE lookup, advisory resolution, malware scanning, or package safety
  verdict was added.
- Policy warnings and failures remain bounded local policy decisions, not
  third-party safety verdicts.

## Release evidence

The tag-gated GitHub Actions workflow builds the wheel and source distribution,
normalizes build timestamps from the tagged commit time, generates a SHA256
checksum manifest, records workflow artifact attestations, and publishes the
same built files as GitHub Release assets. Final tags are explicitly marked as
GitHub Latest; rc tags remain prereleases.

Expected assets:

- `sbom_diff_and_risk-1.1.0-py3-none-any.whl`
- `sbom_diff_and_risk-1.1.0.tar.gz`
- `sbom-diff-and-risk-SHA256SUMS.txt`

Use `docs/verification.md`, `docs/release-provenance.md`, and
`docs/self-provenance.md` for the correct verification path.
