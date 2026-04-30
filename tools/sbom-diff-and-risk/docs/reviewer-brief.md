# Reviewer brief

## Summary

`sbom-diff-and-risk` is a local CLI for comparing two SBOMs or dependency manifests and producing deterministic review artifacts: JSON, Markdown, and SARIF. It is built for conservative supply-chain review, not for vulnerability scanning or package reputation scoring.

## Why this project matters

Dependency review often needs evidence that is stable enough for code review, CI, and audit trails. This project turns dependency changes into repeatable findings, optional policy outcomes, and machine-readable security output while keeping default analysis offline and file-based.

## Capability map

| Area | What exists |
| --- | --- |
| Deterministic local analysis | Compares CycloneDX, SPDX, `requirements.txt`, and conservative `pyproject.toml` inputs without hidden network access by default. |
| Reviewer output | Produces JSON and Markdown reports for dependency diffs, heuristic risk buckets, and policy outcomes. |
| Security tooling output | Emits a conservative SARIF subset for selected high-signal findings and explicit policy violations. |
| Provenance-aware reporting | Optionally records PyPI provenance and integrity evidence when `--enrich-pypi` is enabled. |
| Scorecard signals | Optionally records OpenSSF Scorecard evidence when `--enrich-scorecard` is enabled and a repository mapping is explicit enough. |
| Policy support | Supports local YAML policies for thresholds, source allowlists, provenance requirements, and Scorecard thresholds. |

## Evidence map

| Question | Evidence path |
| --- | --- |
| What does the tool do? | `README.md`, examples, tests, and generated sample reports. |
| How can a reviewer reproduce the core evidence? | [reviewer-evidence-pack.md](reviewer-evidence-pack.md) for demo, release, TestPyPI, and SARIF verification paths. |
| What is the stable JSON shape? | [report-schema.md](report-schema.md) documents the machine-readable report structure and `summary` contract. |
| Are default runs offline? | CLI docs, tests for no-enrichment behavior, and explicit enrichment flags. |
| Can code scanning consume the output? | `docs/github-code-scanning.md` and `examples/sample-sarif.sarif`. |
| Can the tool's own artifacts be verified? | `docs/self-provenance.md` for workflow artifact attestations. |
| Can GitHub release assets be verified? | `docs/release-provenance.md` for release asset verification. |
| Did Trusted Publishing get exercised safely? | `docs/pypi-trusted-publishing-readiness.md` documents the completed TestPyPI dry-run. |
| Is production PyPI enabled? | `docs/pypi-production-publishing-decision.md` documents that production PyPI is intentionally deferred. |

## Quick verification path

1. Read this brief for the 30-second project shape.
2. Read [reviewer-evidence-pack.md](reviewer-evidence-pack.md) for reproducible commands and evidence paths.
3. Read `README.md` for CLI scope, supported inputs, and examples.
4. Read `docs/verification.md` to choose the right verification path.
5. Use `docs/self-provenance.md` when verifying workflow-built wheel or source distribution artifacts.
6. Use `docs/release-provenance.md` when verifying GitHub Release assets.
7. Use `docs/pypi-production-publishing-decision.md` before making any production PyPI publishing decision.

## What this project intentionally does not claim

- It does not claim to be a vulnerability scanner.
- It does not resolve CVEs, advisories, or exploitability.
- It does not score package reputation or declare packages safe.
- It does not perform hidden network enrichment.
- It does not treat TestPyPI success as production PyPI readiness.
- It does not currently publish to production PyPI.
- It does not treat PyPI Trusted Publishing provenance, GitHub workflow artifact attestations, and GitHub Release asset verification as interchangeable evidence.

## Resume / application wording

Built `sbom-diff-and-risk`, a deterministic SBOM and dependency diff CLI that produces JSON, Markdown, and SARIF review artifacts; supports local policy checks and optional provenance/Scorecard evidence; and documents a release verification story covering GitHub artifact attestations, GitHub Release assets, TestPyPI Trusted Publishing validation, and intentionally deferred production PyPI publishing.

