# sbom-diff-and-risk v1.0.0

`v1.0.0` is the Policy Evidence release.

The Python package metadata version for this tag is `1.0.0`.

## Theme

A stable, bounded release surface for dependency diff and local policy evidence.

## Highlights

- Provides minimal policy decision examples for `pass`, `warn`, `fail`, and
  consumer-side `needs-review`.
- Stabilizes `evidence_confidence` as `local_manifest_only`, `sbom_present`,
  `policy_matched`, `provenance_recorded`, or `scorecard_recorded`.
- Fixes one reviewer case from dependency diff to `new_package` policy warning
  across JSON, Markdown, and SARIF artifacts.
- Records policy match metadata in direct SARIF risk results, including the
  local policy level and rule ID.
- Keeps the three supply-chain non-claims visible: not a CVE scanner, not a
  malware scanner, and not a package safety verdict engine.
- Keeps the minimal GitHub Actions consumer path for running policy, uploading
  `policy.json`, and enforcing the tool's exit code.

## Release policy

- `v1.0.0` is the stable GitHub Release contract.
- GitHub Release assets are the distribution surface for this release.
- Production PyPI publishing remains intentionally deferred.
- The TestPyPI Trusted Publishing dry-run remains evidence of the test
  publishing path only.

## Compatibility and boundaries

- Default analysis remains local-file based and deterministic.
- No default network enrichment was added.
- No CVE lookup, advisory resolution, malware scanning, or package safety
  verdict was added.
- Policy warnings and failures remain bounded local policy decisions.
- `enrichment_recorded` was an rc label and is replaced by the more specific
  `scorecard_recorded` label in the final contract.

## Release evidence

The tag-gated GitHub Actions workflow builds the wheel and source distribution,
generates a SHA256 checksum manifest, records workflow artifact attestations,
and publishes the same built files as GitHub Release assets. Final tags are
explicitly marked as GitHub Latest; rc tags remain prereleases.

Expected assets:

- `sbom_diff_and_risk-1.0.0-py3-none-any.whl`
- `sbom_diff_and_risk-1.0.0.tar.gz`
- `sbom-diff-and-risk-SHA256SUMS.txt`

Use `docs/verification.md`, `docs/release-provenance.md`, and
`docs/self-provenance.md` for the correct verification path.
