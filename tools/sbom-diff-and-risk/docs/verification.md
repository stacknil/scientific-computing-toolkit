# Verification guide

Use this page when you are trying to figure out which provenance or verification instructions apply to `sbom-diff-and-risk`.

## Choose the question you are trying to answer

### 1. "How do I verify `sbom-diff-and-risk` itself?"

Use the tool provenance docs:

- [self-provenance.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/self-provenance.md) if you want to verify the workflow-built wheel or source distribution with `gh attestation verify`
- [release-provenance.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/release-provenance.md) if you want to verify a GitHub Release or a downloaded release asset with `gh release verify` or `gh release verify-asset`
- [pypi-trusted-publishing-readiness.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/pypi-trusted-publishing-readiness.md) if you want to know whether this package is ready for PyPI Trusted Publishing

Current boundaries:

- the workflow name is `sbom-diff-and-risk-ci`
- the workflow artifact name is `sbom-diff-and-risk-dist`
- version-tag runs matching `v*` can publish the same built files as GitHub Release assets
- release verification depends on immutable releases being enabled for the repository
- this repository still does not publish to PyPI in this flow; see the readiness checklist before enabling that path

### 2. "How do I use `sbom-diff-and-risk` to analyze third-party dependency provenance?"

Use the dependency-analysis docs in the README:

- [Dependency provenance analysis](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/README.md#dependency-provenance-analysis-opt-in)
- [Dependency provenance reporting](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/README.md#dependency-provenance-reporting)
- [Enforcement mode](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/README.md#enforcement-mode)

Current boundaries:

- default CLI behavior remains local and deterministic
- no hidden network access occurs unless enrichment flags are set explicitly
- dependency provenance analysis is about third-party packages, not about verifying the `sbom-diff-and-risk` tool's own artifacts
- release verification and workflow artifact attestation do not change CLI analysis behavior

## One-line summary

- Verify the tool itself: use `self-provenance.md` or `release-provenance.md`
- Analyze dependencies with the tool: use the README's dependency provenance sections
