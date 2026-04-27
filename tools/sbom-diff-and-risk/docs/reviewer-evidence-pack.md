# Reviewer evidence pack

This page is a reproducible evidence checklist for reviewing `sbom-diff-and-risk`. It focuses on what can be verified from the repository, examples, GitHub release assets, and TestPyPI dry-run documentation. It does not introduce new CLI behavior.

## Project Identity

`sbom-diff-and-risk` is a local-first deterministic CLI for comparing SBOMs and dependency manifests. It is designed to produce stable review evidence for dependency changes.

Core identity:

- local deterministic SBOM/dependency diffing
- JSON, Markdown, and SARIF output
- local policy checks over diff and risk findings
- optional provenance-aware reporting through explicit PyPI enrichment
- optional OpenSSF Scorecard evidence when repository mapping is explicit enough
- release and distribution documentation that separates tool behavior from artifact provenance

## Reproducible Demo Path

From `tools/sbom-diff-and-risk`, install the package in editable development mode:

```powershell
python -m pip install -e .[dev]
```

Generate the default CycloneDX example reports:

```powershell
sbom-diff-risk compare `
  --before examples/cdx_before.json `
  --after examples/cdx_after.json `
  --format auto `
  --out-json outputs/report.json `
  --out-md outputs/report.md
```

Expected output files:

- `outputs/report.json`
- `outputs/report.md`

Compare the outputs against the checked-in sample reports:

```powershell
Compare-Object (Get-Content examples/sample-report.json) (Get-Content outputs/report.json)
Compare-Object (Get-Content examples/sample-report.md) (Get-Content outputs/report.md)
```

No differences means the sample path reproduced the committed example output.

Generate the strict-policy SARIF sample:

```powershell
sbom-diff-risk compare `
  --before examples/sarif_before.json `
  --after examples/sarif_after.json `
  --policy examples/policy-strict.yml `
  --out-sarif outputs/report.sarif
```

Compare the SARIF output against the sample:

```powershell
Compare-Object (Get-Content examples/sample-sarif.sarif) (Get-Content outputs/report.sarif)
```

The SARIF sample is intentionally conservative. It covers selected high-signal findings and explicit policy violations, not every enrichment fact.

## Release Verification Path

Start with the GitHub Release for the version under review. For `v0.5.0`, inspect the release and assets:

```powershell
gh release view v0.5.0 --repo stacknil/scientific-computing-toolkit --json tagName,name,isDraft,isPrerelease,assets,url
```

Expected release assets:

- `sbom_diff_and_risk-0.5.0-py3-none-any.whl`
- `sbom_diff_and_risk-0.5.0.tar.gz`

For workflow-built artifacts downloaded from a trusted workflow run, verify artifact attestations with the signer workflow:

```powershell
gh attestation verify path/to/sbom_diff_and_risk-0.5.0-py3-none-any.whl `
  --repo stacknil/scientific-computing-toolkit `
  --signer-workflow stacknil/scientific-computing-toolkit/.github/workflows/sbom-diff-and-risk-ci.yml
```

```powershell
gh attestation verify path/to/sbom_diff_and_risk-0.5.0.tar.gz `
  --repo stacknil/scientific-computing-toolkit `
  --signer-workflow stacknil/scientific-computing-toolkit/.github/workflows/sbom-diff-and-risk-ci.yml
```

`gh release verify` and `gh release verify-asset` are conditional on immutable releases. Use them only when the repository release is immutable and GitHub has generated release attestations:

```powershell
gh release view v0.5.0 --repo stacknil/scientific-computing-toolkit --json isImmutable,assets,url
```

If `isImmutable` is true, release verification can check the release record and downloaded release assets:

```powershell
gh release verify v0.5.0 --repo stacknil/scientific-computing-toolkit
gh release verify-asset v0.5.0 path/to/sbom_diff_and_risk-0.5.0-py3-none-any.whl --repo stacknil/scientific-computing-toolkit
```

If `isImmutable` is false, use the workflow artifact attestation path as the primary artifact verification story.

## TestPyPI Evidence Path

The TestPyPI Trusted Publishing dry-run completed for `sbom-diff-and-risk`. See `pypi-trusted-publishing-readiness.md` for the exact workflow identity and setup notes.

What this proves:

- the package metadata can render on TestPyPI
- the TestPyPI upload path can use Trusted Publishing / OIDC
- the workflow separates build/check from upload
- TestPyPI upload was manually gated

What this does not prove:

- production PyPI publishing is ready
- production PyPI has a project, pending publisher, or trusted publisher
- future production distributions will be byte-identical to GitHub Release assets
- dependency analysis results are safety verdicts

Production PyPI is intentionally deferred. See `pypi-production-publishing-decision.md` before making any production publishing decision.

## Code Scanning / SARIF Evidence Path

The SARIF output is designed for GitHub code scanning consumption. Start with:

- `docs/github-code-scanning.md`
- `examples/sample-sarif.sarif`
- `examples/sample-provenance-report.sarif`
- `examples/sample-scorecard-report.sarif`

The SARIF renderer intentionally emits a conservative subset:

- selected heuristic findings such as suspicious source, unknown license, and major upgrade
- explicit blocking policy decisions
- selected provenance or Scorecard policy violations when policy turns them into findings

Avoid overclaiming:

- SARIF output is not a CVE scanner
- SARIF output is not a malware or reputation verdict
- missing provenance is an evidence gap, not proof of compromise
- Scorecard evidence is advisory unless policy explicitly gates it

## Non-Claims

- No hidden network access occurs by default.
- No production PyPI package exists yet.
- No dependency safety verdicts are produced.
- No CVE resolution is performed.
- No advisory database or exploitability analysis is performed.
- No production PyPI publishing workflow is enabled.
- TestPyPI validation is not production PyPI readiness.

## 30-Second Reviewer Checklist

- Can I identify what the tool does? Read `README.md` and `reviewer-brief.md`.
- Can I reproduce a deterministic demo? Run the CycloneDX example and compare `outputs/report.*` to `examples/sample-report.*`.
- Can I see machine-readable security output? Inspect or regenerate `examples/sample-sarif.sarif`.
- Can I verify release/distribution evidence? Read `verification.md`, `self-provenance.md`, and `release-provenance.md`.
- Can I distinguish TestPyPI from production PyPI? Read `pypi-trusted-publishing-readiness.md` and `pypi-production-publishing-decision.md`.
- Can I state the non-claims? No CVE scanner, no reputation oracle, no dependency safety verdicts, no production PyPI package yet.

