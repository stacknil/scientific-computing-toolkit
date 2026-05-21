# Reviewer brief

## Problem

Scientific and security-oriented review work often needs small deterministic tools, not vague platforms. Reviewers need evidence that inputs, outputs, and claims stay inspectable.

## What it does

`scientific-computing-toolkit` is a portfolio repository for scientific-computing infrastructure and supply-chain review work.

The current flagship project is `tools/sbom-diff-and-risk`, a local CLI for comparing two SBOMs or dependency manifests and producing deterministic JSON, Markdown, SARIF, and policy sidecar artifacts.

## Reviewer Evidence

- Reproducible command: `sbom-diff-risk compare --before examples/cdx_before.json --after examples/cdx_after.json --format auto --out-json outputs/report.json --summary-json outputs/summary.json --out-md outputs/report.md`
- Deterministic outputs: JSON reports, Markdown reports, summary sidecars, policy sidecars, SARIF, and checked-in example artifacts.
- Tests / CI: local pytest coverage and reviewer evidence docs for regenerating sample artifacts and verification paths.
- Release evidence: `sbom-diff-and-risk` release notes, GitHub release verification docs, TestPyPI Trusted Publishing dry-run notes, and intentionally deferred production PyPI decision docs.
- Non-goals: vulnerability scanning, CVE resolution, exploitability scoring, package safety verdicts, hidden enrichment, or production PyPI claims.

## Quick run

From the repository root:

```bash
cd tools/sbom-diff-and-risk
python -m pip install -e ".[dev]"
sbom-diff-risk compare --before examples/cdx_before.json --after examples/cdx_after.json --format auto --out-json outputs/report.json --summary-json outputs/summary.json --out-md outputs/report.md
```

## Sample output

The flagship tool can emit:

- `report.json`
- `summary.json`
- `policy.json`
- `report.md`
- `report.sarif`

The checked-in examples and docs cover deterministic local output, optional policy decisions, and opt-in provenance or Scorecard evidence when explicit enrichment flags are enabled.

## What this proves

- deterministic supply-chain review tooling
- reviewer-oriented artifact design instead of black-box scoring
- careful separation between local default behavior and opt-in enrichment
- the ability to package a broader repo around one clear flagship tool

## Safety / boundaries

- local-file analysis is the default
- no hidden network enrichment
- not a vulnerability scanner or package reputation oracle
- production PyPI publishing remains intentionally deferred

## Limitations

- the root repo is currently flagship-led rather than evenly balanced across multiple finished tools
- heuristic risk buckets do not resolve CVEs or exploitability
- provenance and Scorecard evidence are advisory, not proof that a dependency is safe

## Next milestone

Keep strengthening the flagship reviewer route while adding the next finished tool or mini-lab at the same documentation and evidence standard.
