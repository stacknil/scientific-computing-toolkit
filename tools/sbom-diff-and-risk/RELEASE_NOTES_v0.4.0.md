# v0.4.0

Theme: release/distribution provenance hardening

## Highlights

- Clarified the GitHub-hosted provenance story for `sbom-diff-and-risk` workflow-built artifacts and GitHub Release assets.
- Kept workflow artifact attestation and GitHub Release verification as explicit, separate consumer verification surfaces.
- Documented PyPI Trusted Publishing readiness and sequencing, while intentionally not enabling PyPI publishing yet.

## Verification story

- Workflow-built wheel and source distribution artifacts remain verifiable through `gh attestation verify`.
- Version-tag releases can publish those same built files as GitHub Release assets, with consumer guidance for `gh release verify` and `gh release verify-asset`.
- Verification docs now point users more directly to the right path depending on whether they want to verify the tool itself or analyze third-party dependency provenance with the tool.

## Packaging and release alignment

- Bumped the package version to `0.4.0`.
- Synced the README top-level version narrative with the `v0.4.0` release hardening theme.
- Updated example SARIF outputs and PyPI readiness notes to reference the `0.4.0` package line consistently.

## Not in this release

- No PyPI publishing is enabled yet.
- No new CLI analysis features were added.
- Default CLI behavior remains local and deterministic, with no hidden network access.
