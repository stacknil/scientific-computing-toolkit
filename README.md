# scientific-computing-toolkit

This repository is a portfolio space for scientific-computing infrastructure, systems tooling, and supply-chain-security experiments that favor deterministic behavior, auditable outputs, and clear release evidence.

## Current Flagship Project

[`tools/sbom-diff-and-risk`](tools/sbom-diff-and-risk/README.md) is the current flagship tool. It compares SBOMs and dependency manifests, produces JSON, Markdown, and SARIF review artifacts, supports local policy checks, and can optionally record PyPI provenance and OpenSSF Scorecard evidence.

For a fast reviewer overview, start with the [`sbom-diff-and-risk` reviewer brief](tools/sbom-diff-and-risk/docs/reviewer-brief.md).

## Why This Repository Exists

Scientific and security-oriented engineering often needs small, inspectable tools that make evidence easier to review. This repository collects projects that emphasize:

- deterministic local analysis
- machine-readable security and review output
- conservative policy checks
- explicit provenance and release verification boundaries
- documentation that separates tool behavior from distribution evidence

## Project Map

| Project | Status | What to review |
| --- | --- | --- |
| [`sbom-diff-and-risk`](tools/sbom-diff-and-risk/README.md) | Released at `v0.5.0` | Deterministic SBOM/dependency diffing, JSON/Markdown/SARIF output, local policy checks, optional provenance and Scorecard evidence. |

Useful entry points:

- [`sbom-diff-and-risk` README](tools/sbom-diff-and-risk/README.md)
- [Reviewer brief](tools/sbom-diff-and-risk/docs/reviewer-brief.md)
- [v0.5.0 release notes](tools/sbom-diff-and-risk/RELEASE_NOTES_v0.5.0.md)
- [Examples](tools/sbom-diff-and-risk/examples/)

## Verification And Release Evidence

`sbom-diff-and-risk` has separate verification surfaces. They are related, but they do not prove the same thing.

| Evidence | Where to start |
| --- | --- |
| Tool verification guide | [`docs/verification.md`](tools/sbom-diff-and-risk/docs/verification.md) |
| GitHub Release asset verification | [`docs/release-provenance.md`](tools/sbom-diff-and-risk/docs/release-provenance.md) |
| TestPyPI Trusted Publishing dry-run | [`docs/pypi-trusted-publishing-readiness.md`](tools/sbom-diff-and-risk/docs/pypi-trusted-publishing-readiness.md) |
| Production PyPI decision gate | [`docs/pypi-production-publishing-decision.md`](tools/sbom-diff-and-risk/docs/pypi-production-publishing-decision.md) |

The TestPyPI Trusted Publishing dry-run has been validated. Production PyPI publishing is intentionally deferred.

## What This Repository Intentionally Does Not Claim

- It does not claim that `sbom-diff-and-risk` is a vulnerability scanner.
- It does not claim to resolve CVEs, advisories, exploitability, or package safety verdicts.
- It does not treat optional provenance or Scorecard evidence as proof that a dependency is safe.
- It does not imply that production PyPI publishing is enabled.
- It does not treat GitHub release verification, GitHub workflow artifact attestations, and PyPI Trusted Publishing provenance as interchangeable evidence.

## Reviewer Quick Path

1. Read the [`sbom-diff-and-risk` reviewer brief](tools/sbom-diff-and-risk/docs/reviewer-brief.md).
2. Skim the [`sbom-diff-and-risk` README](tools/sbom-diff-and-risk/README.md) for CLI scope and examples.
3. Check the [v0.5.0 release notes](tools/sbom-diff-and-risk/RELEASE_NOTES_v0.5.0.md).
4. Use the [verification guide](tools/sbom-diff-and-risk/docs/verification.md) to choose the right provenance check.
5. Inspect the [examples](tools/sbom-diff-and-risk/examples/) for sample reports and policy files.

## Status

- Current flagship release: `sbom-diff-and-risk` `v0.5.0`
- GitHub Release assets: available for `v0.5.0`
- TestPyPI Trusted Publishing dry-run: completed
- Production PyPI publishing: intentionally deferred

