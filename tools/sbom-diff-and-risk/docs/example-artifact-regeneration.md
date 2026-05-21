# Example Artifact Regeneration

This page documents how to regenerate the checked-in no-network example
artifacts for `sbom-diff-and-risk`.

Use this when an example input changes, such as
`examples/requirements_before.txt` or `examples/requirements_after.txt`.
The generated sample reports are intentionally committed so reviewers can
compare deterministic output without running enrichment services.

## Regenerate

From `tools/sbom-diff-and-risk`:

```powershell
python scripts/regenerate-example-artifacts.py
```

The script regenerates these local, deterministic artifacts:

- `examples/sample-report.json`
- `examples/sample-summary.json`
- `examples/sample-report.md`
- `examples/sample-policy-warn-report.json`
- `examples/sample-policy-warn-report.md`
- `examples/sample-policy-fail-report.json`
- `examples/sample-policy.json`
- `examples/sample-policy-fail-report.md`
- `examples/sample-requirements-report.json`
- `examples/sample-requirements-report.md`

The strict-policy example intentionally exits with code `1` because it produces
blocking local policy findings. The script treats that as expected while still
capturing the generated reports.

## Check Mode

Use `--check` to verify that generated output matches the checked-in artifacts
without modifying the repository:

```powershell
python scripts/regenerate-example-artifacts.py --check
```

The test suite runs this check mode so stale local JSON, Markdown, summary, or
policy-sidecar examples fail predictably.

## Boundaries

The regeneration script covers no-network JSON, Markdown, summary, and policy
sidecar examples produced through the public CLI.

It does not perform PyPI or Scorecard enrichment, does not call external
services, and does not make dependency safety claims. Provenance-aware,
Scorecard-aware, and SARIF sample artifacts remain covered by their focused
golden tests because those examples include mocked evidence or normalized SARIF
metadata.
