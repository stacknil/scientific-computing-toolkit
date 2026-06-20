# Reviewer brief

## Problem

Scientific and security-oriented review work often needs small deterministic
tools, not vague platforms. Reviewers need evidence that inputs, outputs, and
claims stay inspectable.

## What it does

`scientific-computing-toolkit` is a portfolio repository for
scientific-computing infrastructure and supply-chain review work.

The current flagship project is
[`tools/sbom-diff-and-risk`](../tools/sbom-diff-and-risk/README.md), a local
CLI for comparing two SBOMs or dependency manifests and producing
deterministic JSON, Markdown, SARIF, and policy sidecar artifacts.

The precipitation and weather diagnostics projects are supporting
scientific-data projects. They demonstrate public-safe reproducible analysis
workflows, but they are not part of the `sbom-diff-and-risk` release surface.

## How to review this repository

| Review question | Start here | Stop when |
| --- | --- | --- |
| What is the repository shape? | This brief, the root [README](../README.md), and the [repository scope map](repo-scope-map.md). | You can distinguish the flagship SBOM tool from the supporting diagnostics projects. |
| What should I review for the SBOM tool? | The SBOM [reviewer path](../tools/sbom-diff-and-risk/docs/reviewer-path.md). | You have chosen the right 30-second, 5-minute, 15-minute, release, or deep-review route. |
| What does the SBOM risk model actually use? | The [risk model boundary](risk-model-boundary.md). | You can separate risk inputs from context-only fields and non-claims. |
| Can the SBOM examples be reproduced? | The SBOM [example artifact regeneration guide](../tools/sbom-diff-and-risk/docs/example-artifact-regeneration.md). | `python scripts/regenerate-example-artifacts.py --check` passes. |
| Can the released SBOM artifacts be verified? | The SBOM [verification guide](../tools/sbom-diff-and-risk/docs/verification.md). | You know whether to use checksums, release verification, or workflow artifact attestations. |
| Are the reviewer routes still valid? | The repository [reviewer route contract](../scripts/validate-reviewer-routes.py). | `python scripts/validate-reviewer-routes.py` passes. |
| What are the supporting diagnostics projects? | The supporting project entry points below and the root [README](../README.md). | You can state their data-policy boundaries and that they are separate from the SBOM release surface. |

## Supporting diagnostics entry points

| Project | Role | Start here |
| --- | --- | --- |
| `precipitation-anomaly-diagnostics` | Compact reviewer-facing mini-lab | [Reviewer path](../projects/precipitation-anomaly-diagnostics/docs/reviewer-path.md) |
| `precipitation-anomaly-diagnostics-lab` | Extended climate diagnostics lab | [Reviewer path](../projects/precipitation-anomaly-diagnostics-lab/docs/reviewer-path.md) |
| `python-weather-diagnostics-toolkit` | Reusable weather-field diagnostics toolkit | [Reviewer path](../projects/python-weather-diagnostics-toolkit/docs/reviewer-path.md) |

## Reviewer evidence

- Reproducible command path: install the SBOM tool, run the bundled CycloneDX
  example, and compare generated outputs with checked-in artifacts.
- Deterministic outputs: JSON reports, Markdown reports, summary sidecars,
  policy sidecars, SARIF, and checked-in example artifacts.
- Tests / CI: local pytest coverage, example-artifact regeneration checks, and
  reviewer evidence docs for verification paths.
- Release evidence: `sbom-diff-and-risk` release notes, GitHub release
  verification docs, TestPyPI Trusted Publishing dry-run notes, and
  intentionally deferred production PyPI decision docs.
- Scope map: `docs/repo-scope-map.md` keeps the flagship/supporting split and
  repository non-claims explicit.
- Risk model boundary: `docs/risk-model-boundary.md` states which fields affect
  risk classification, which fields are context only, and what the model never
  infers.
- Non-goals: vulnerability scanning, CVE resolution, exploitability scoring,
  package safety verdicts, hidden enrichment, or production PyPI claims.

## Quick run

From the repository root:

```bash
cd tools/sbom-diff-and-risk
python -m pip install -e ".[dev]"
sbom-diff-risk compare \
  --before examples/cdx_before.json \
  --after examples/cdx_after.json \
  --format auto \
  --out-json outputs/report.json \
  --summary-json outputs/summary.json \
  --out-md outputs/report.md
```

## Sample output

The flagship tool can emit:

- [`report.json`](../tools/sbom-diff-and-risk/examples/sample-report.json)
- [`summary.json`](../tools/sbom-diff-and-risk/examples/sample-summary.json)
- [`policy.json`](../tools/sbom-diff-and-risk/examples/sample-policy.json)
- [`report.md`](../tools/sbom-diff-and-risk/examples/sample-report.md)
- [`report.sarif`](../tools/sbom-diff-and-risk/examples/sample-sarif.sarif)

The checked-in examples and docs cover deterministic local output, optional
policy decisions, and opt-in provenance or Scorecard evidence when explicit
enrichment flags are enabled.

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
- supporting diagnostics projects use public-safe synthetic or derived example
  artifacts and are separate from the SBOM release surface

## Limitations

- the root repo is currently flagship-led rather than evenly balanced across
  multiple finished tools
- heuristic risk buckets do not resolve CVEs or exploitability
- provenance and Scorecard evidence are advisory, not proof that a dependency
  is safe

## Next milestone

Keep strengthening the flagship reviewer route while adding the next finished
tool or mini-lab at the same documentation and evidence standard.
