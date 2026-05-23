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

## Supporting Diagnostics Projects

These projects are internal supporting material for reviewer depth. They are
not the repository's flagship release surface.

| Supporting project | Role | Review value |
| --- | --- | --- |
| [`precipitation-anomaly-diagnostics`](projects/precipitation-anomaly-diagnostics/README.md) | Compact case study | End-to-end spatiotemporal anomaly workflow |
| [`precipitation-anomaly-diagnostics-lab`](projects/precipitation-anomaly-diagnostics-lab/README.md) | Extended lab | More detailed climate diagnostics and synthetic reports |
| [`python-weather-diagnostics-toolkit`](projects/python-weather-diagnostics-toolkit/README.md) | Reusable toolkit | General weather-field calculation utilities |

## Scope Boundary

`sbom-diff-and-risk` remains the flagship release-facing tool in this repository.

The precipitation and weather diagnostics projects are supporting
scientific-data mini-labs. They demonstrate reproducible analysis workflows,
data-policy boundaries, and reviewer-friendly interpretation, but they are not
part of the `sbom-diff-and-risk` release surface and should not be read as a
separate meteorology portfolio.

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
Public-safe compact reviewer-facing mini-lab.

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

Project:
[`precipitation-anomaly-diagnostics-lab`](projects/precipitation-anomaly-diagnostics-lab/README.md)

Status:
Public-safe extended lab variant with configurable diagnostics utilities.

What to review:
Detailed calculation methods, inference boundaries, configurable analysis
scripts, synthetic chart generation, and a synthetic inference report.

This extended lab is a supporting scientific-data project and is not part of
the `sbom-diff-and-risk` release surface.

Useful entry points:

- [`precipitation-anomaly-diagnostics-lab` README](projects/precipitation-anomaly-diagnostics-lab/README.md)
- [Calculation methods](projects/precipitation-anomaly-diagnostics-lab/docs/calculation-methods.md)
- [Inference analysis](projects/precipitation-anomaly-diagnostics-lab/docs/inference-analysis.md)
- [Synthetic inference report](projects/precipitation-anomaly-diagnostics-lab/examples/synthetic-inference-report.md)

Project:
[`python-weather-diagnostics-toolkit`](projects/python-weather-diagnostics-toolkit/README.md)

Status:
Public-safe supporting atmospheric diagnostics module.

What to review:
Reusable Python weather-field diagnostics, synthetic examples, data-policy
boundaries, and deterministic tests for thermodynamic, dynamic, ensemble, and
baseline-model utilities.

This toolkit is a supporting scientific-data project and is not part of the
`sbom-diff-and-risk` release surface.

Useful entry points:

- [`python-weather-diagnostics-toolkit` README](projects/python-weather-diagnostics-toolkit/README.md)
- [Reviewer path](projects/python-weather-diagnostics-toolkit/docs/reviewer-path.md)
- [Calculation methods](projects/python-weather-diagnostics-toolkit/docs/calculation-methods.md)
- [Diagnostic analysis](projects/python-weather-diagnostics-toolkit/docs/diagnostic-analysis.md)
- [Source-to-public mapping](projects/python-weather-diagnostics-toolkit/docs/source-to-public-mapping.md)
- [Methodology](projects/python-weather-diagnostics-toolkit/docs/methodology.md)
- [Data policy](projects/python-weather-diagnostics-toolkit/docs/data-policy.md)
- [Synthetic report](projects/python-weather-diagnostics-toolkit/examples/synthetic-weather-diagnostics-report.md)

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

