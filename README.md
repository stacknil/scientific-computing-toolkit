# scientific-computing-toolkit

This repository is a portfolio space for scientific-computing infrastructure,
systems tooling, and supply-chain-security experiments that favor deterministic
behavior, auditable outputs, and clear release evidence.

## Current Flagship Tool

[`tools/sbom-diff-and-risk`](tools/sbom-diff-and-risk/README.md) is the
current flagship tool. It compares SBOMs and dependency manifests, produces
JSON, Markdown, and SARIF review artifacts, supports local policy checks, and
can optionally record PyPI provenance and OpenSSF Scorecard evidence.

For the clearest reviewer route, start with the
[`sbom-diff-and-risk` reviewer path](tools/sbom-diff-and-risk/docs/reviewer-path.md);
it separates orientation, artifact inspection, local reproduction, and release
evidence.

## Supporting Spatiotemporal Diagnostics Project

[`projects/precipitation-anomaly-diagnostics`](projects/precipitation-anomaly-diagnostics/README.md)
is a public-safe scientific-data diagnostics mini-lab. It demonstrates a
reproducible workflow for precipitation anomaly preprocessing, EOF analysis,
representative-period selection, composite analysis, and reviewer-friendly
scientific interpretation.

## Why This Repository Exists

Scientific and security-oriented engineering often needs small, inspectable
tools that make evidence easier to review. This repository collects projects
that emphasize:

- deterministic local analysis
- machine-readable security and review output
- conservative policy checks
- explicit provenance and release verification boundaries
- documentation that separates tool behavior from distribution evidence

## Project Map

Project:
[`sbom-diff-and-risk`](tools/sbom-diff-and-risk/README.md)

Status:
Released at `v0.9.0`.

What to review:
Deterministic SBOM/dependency diffing, JSON/Markdown/SARIF output, local policy
checks, policy decision explainability, optional provenance and Scorecard
evidence.

Useful entry points:

- [`sbom-diff-and-risk` README](tools/sbom-diff-and-risk/README.md)
- [Reviewer path](tools/sbom-diff-and-risk/docs/reviewer-path.md)
- [Reviewer brief](tools/sbom-diff-and-risk/docs/reviewer-brief.md)
- [Reviewer evidence pack](tools/sbom-diff-and-risk/docs/reviewer-evidence-pack.md)
- [v0.9.0 release notes][release-notes-v090]
- [Examples](tools/sbom-diff-and-risk/examples/)

Project:
[`precipitation-anomaly-diagnostics`](projects/precipitation-anomaly-diagnostics/README.md)

Status:
Public-safe mini-lab.

What to review:
Sanitized climate-diagnostics workflow, small derived example artifacts,
methodology notes, data policy, and synthetic-data tests.

This mini-lab is a supporting scientific-data project and is not part of the
`sbom-diff-and-risk` release surface.

Useful entry points:

- [`precipitation-anomaly-diagnostics` README](projects/precipitation-anomaly-diagnostics/README.md)
- [Data policy](projects/precipitation-anomaly-diagnostics/docs/data-policy.md)
- [Methodology](projects/precipitation-anomaly-diagnostics/docs/methodology.md)
- [Inference framework](projects/precipitation-anomaly-diagnostics/docs/inference-framework.md)
- [Example report](projects/precipitation-anomaly-diagnostics/reports/example-report.md)

## Verification and Release Evidence

`sbom-diff-and-risk` has separate verification surfaces. They are related, but
they do not prove the same thing.

- Tool verification guide:
  [`docs/verification.md`](tools/sbom-diff-and-risk/docs/verification.md)
- GitHub Release asset verification:
  [`docs/release-provenance.md`](tools/sbom-diff-and-risk/docs/release-provenance.md)
- TestPyPI Trusted Publishing dry-run:
  [`docs/pypi-trusted-publishing-readiness.md`](tools/sbom-diff-and-risk/docs/pypi-trusted-publishing-readiness.md)
- Production PyPI decision gate:
  [`docs/pypi-production-publishing-decision.md`](tools/sbom-diff-and-risk/docs/pypi-production-publishing-decision.md)

The TestPyPI Trusted Publishing dry-run has been validated. Production PyPI
publishing is intentionally deferred.

## What This Repository Does Not Claim

- It does not claim that `sbom-diff-and-risk` is a vulnerability scanner.
- It does not claim to resolve CVEs, advisories, exploitability, or package
  safety verdicts.
- It does not treat optional provenance or Scorecard evidence as proof that a dependency is safe.
- It does not imply that production PyPI publishing is enabled.
- It does not treat GitHub release verification, GitHub workflow artifact
  attestations, and PyPI Trusted Publishing provenance as interchangeable
  evidence.

## Reviewer Quick Path

For `sbom-diff-and-risk`, use the
[reviewer path](tools/sbom-diff-and-risk/docs/reviewer-path.md) and first choose
the review question:

1. 30 seconds:
   read the [reviewer brief](tools/sbom-diff-and-risk/docs/reviewer-brief.md).
2. 5 minutes:
   inspect [sample JSON, summary, policy, Markdown, and SARIF artifacts](tools/sbom-diff-and-risk/examples/).
3. 15 minutes:
   run the deterministic example check in
   [example artifact regeneration](tools/sbom-diff-and-risk/docs/example-artifact-regeneration.md).
4. Release evidence:
   use the [verification guide](tools/sbom-diff-and-risk/docs/verification.md)
   and [release provenance docs](tools/sbom-diff-and-risk/docs/release-provenance.md).

## Status

- Current flagship release: `sbom-diff-and-risk` `v0.9.0`
- GitHub Release assets: available for `v0.9.0`
- TestPyPI Trusted Publishing dry-run: completed
- Production PyPI publishing: intentionally deferred

[release-notes-v090]: tools/sbom-diff-and-risk/RELEASE_NOTES_v0.9.0.md

