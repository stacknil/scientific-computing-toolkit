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

## v1.0-rc.1 to v1.0.0 compatibility

- The CLI commands and flags are unchanged from `v1.0-rc.1`.
- The package version moves from PEP 440 `1.0rc1` to `1.0.0`.
- JSON and Markdown report structure remains compatible, except that the rc
  evidence label `enrichment_recorded` is replaced by the more specific
  `scorecard_recorded` value. Consumers matching the old string must update.
- SARIF remains a conservative subset. The final release additively records
  `policy_matched`, `policy_level`, and `policy_rule_id` on direct mapped
  findings, and emits `sdr.new_package` only when `new_package` matched policy.
- Production PyPI publishing remains deferred; moving from rc to final changes
  the GitHub Release contract, not the PyPI publishing contract.

## Boundaries

- Default analysis remains local-file based and deterministic.
- No default network enrichment was added.
- No CVE lookup, advisory resolution, malware scanning, or package safety
  verdict was added.
- Policy warnings and failures remain bounded local policy decisions.

## Release evidence

The tag-gated GitHub Actions workflow builds the wheel and source distribution,
normalizes build timestamps from the tagged commit time, generates a SHA256
checksum manifest, records workflow artifact attestations, and publishes the
same built files as GitHub Release assets. Final tags are explicitly marked as
GitHub Latest; rc tags remain prereleases.

Expected assets:

- `sbom_diff_and_risk-1.0.0-py3-none-any.whl`
- `sbom_diff_and_risk-1.0.0.tar.gz`
- `sbom-diff-and-risk-SHA256SUMS.txt`

Use `docs/verification.md`, `docs/release-provenance.md`, and
`docs/self-provenance.md` for the correct verification path.
