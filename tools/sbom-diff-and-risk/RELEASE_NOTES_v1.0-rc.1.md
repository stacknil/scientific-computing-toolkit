# sbom-diff-and-risk v1.0-rc.1

`v1.0-rc.1` is the Policy Evidence release candidate.

The Python package metadata version for this tag is `1.0rc1`, which is the
PEP 440 form used in the wheel and source distribution filenames.

## Theme

Reviewer-stable policy evidence without expanding the tool's claims.

This release candidate turns the post-`v0.9.0` policy work into a tighter
review surface: fixed policy decision examples, explicit evidence-confidence
labels, a risk-model boundary, and a minimal CI consumer path.

## Highlights

- Added policy decision examples for `pass`, `warn`, `fail`, and
  consumer-side `needs-review`.
- Added `summary.evidence_confidence` and top-level `evidence_confidence`
  labels for `local_manifest_only`, `sbom_present`, `policy_matched`,
  `enrichment_recorded`, and `provenance_recorded`.
- Added a one-page policy warning reviewer case that traces an added
  dependency from diff input to local policy warning.
- Strengthened the risk-model boundary with explicit non-claims: not a CVE
  scanner, not a malware scanner, and not a package safety verdict engine.
- Added a minimal GitHub Actions consumer workflow that runs the tool, uploads
  `policy.json`, and fails or passes from the local policy result.
- Added repository scope and scientific-computing background notes to keep the
  repository from widening beyond the flagship SBOM release surface.

## Compatibility and boundaries

- This is a release candidate, not the final `v1.0.0`.
- Production PyPI publishing remains intentionally deferred.
- The GitHub Release assets are the expected distribution surface for this rc.
- Default analysis remains local-file based and deterministic.
- No default network enrichment was added.
- No CVE lookup, advisory resolution, malware scanning, or package safety
  verdict was added.
- Policy warnings and failures remain local policy decisions for review.

## Release evidence

The tag-gated GitHub Actions workflow builds the wheel and source distribution,
generates a SHA256 checksum manifest, records workflow artifact attestations,
and publishes the same built files as GitHub Release assets.

Expected assets:

- `sbom_diff_and_risk-1.0rc1-py3-none-any.whl`
- `sbom_diff_and_risk-1.0rc1.tar.gz`
- `sbom-diff-and-risk-SHA256SUMS.txt`

Use `docs/verification.md`, `docs/release-provenance.md`, and
`docs/self-provenance.md` for the correct verification path.
