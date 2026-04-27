# Release provenance and release asset verification

`sbom-diff-and-risk` now has two GitHub-hosted provenance surfaces for its packaged wheel and source distribution:

1. workflow-artifact attestations for the files built by `.github/workflows/sbom-diff-and-risk-ci.yml`
2. GitHub Release verification for version-tag releases that publish those same built files as release assets

This document is about the second surface: verifying a GitHub Release and a downloaded release asset.

This page is only about the `sbom-diff-and-risk` tool's own GitHub Releases. If you want the quick "which verification page do I need?" guide, start with [verification.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/verification.md).

## What the release workflow now does

For version tags matching `v*`, the `sbom-diff-and-risk-ci` workflow:

1. builds the wheel and source distribution in `build-and-attest`
2. uploads them as the workflow artifact `sbom-diff-and-risk-dist`
3. generates a workflow artifact attestation for those built files
4. downloads that same workflow artifact in `publish-release-assets`
5. publishes those exact `.whl` and `.tar.gz` files as GitHub Release assets for the matching tag

This intentionally reuses the same workflow-built bytes for both the workflow artifact and the release asset surfaces. It does not add PyPI publishing or a separate rebuild-only release pipeline.

## What release verification covers

GitHub Release verification is distinct from workflow artifact attestation:

- `gh attestation verify` checks a file against the workflow artifact attestation produced by `build-and-attest`
- `gh release verify` checks that a GitHub Release has a valid release attestation
- `gh release verify-asset` checks that a local file exactly matches an attested asset from that release

Release verification only works for immutable releases. Per GitHub's release integrity and immutable release documentation, immutable releases automatically generate a release attestation and protect release assets from modification after publication.

If immutable releases are not enabled for the repository, the release may still contain assets, but `gh release verify` and `gh release verify-asset` are not the source of truth. In that case, use the workflow-artifact attestation flow from [self-provenance.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/self-provenance.md).

## Manual verification for a release

Use this path after a successful version-tag run such as `v0.4.0`.

1. Open the repository's **Releases** page.
2. Open the release for the version tag you want to verify.
3. Check whether the release is immutable before relying on release verification:

```bash
gh release view v0.4.0 --repo stacknil/scientific-computing-toolkit --json isImmutable,assets,url
```

4. Confirm the release includes the packaged assets:
   - `sbom_diff_and_risk-<version>-py3-none-any.whl`
   - `sbom_diff_and_risk-<version>.tar.gz`
5. If the repository uses immutable releases, confirm GitHub shows `Immutable` on the release page.
6. Download one of the release assets locally.
7. Verify the release itself with GitHub CLI:

```bash
gh release verify v0.4.0 --repo stacknil/scientific-computing-toolkit
```

8. Verify the downloaded asset against the release attestation:

```bash
gh release verify-asset v0.4.0 path/to/sbom_diff_and_risk-0.4.0-py3-none-any.whl \
  --repo stacknil/scientific-computing-toolkit
```

If `isImmutable` is `false`, the release asset can still be downloaded, but the supported provenance path for this repository remains the workflow-artifact attestation flow from [self-provenance.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/self-provenance.md).

You can inspect structured output as JSON:

```bash
gh release verify v0.4.0 \
  --repo stacknil/scientific-computing-toolkit \
  --format json
```

```bash
gh release verify-asset v0.4.0 path/to/sbom_diff_and_risk-0.4.0.tar.gz \
  --repo stacknil/scientific-computing-toolkit \
  --format json
```

## Important boundary notes

- `gh release verify-asset` verifies a local file path against a release attestation. It does not verify a workflow artifact download directly unless that file is also a release asset.
- GitHub's generated source-code ZIP and tarball downloads are not covered by `gh release verify-asset`.
- A successful release verification does not replace the workflow-artifact attestation story; it complements it.
- This repository now has a separate TestPyPI Trusted Publishing readiness workflow, but production PyPI publishing remains deferred. For the production decision gate, publisher identity, future workflow shape, and provenance boundary, see [pypi-production-publishing-decision.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/pypi-production-publishing-decision.md).
