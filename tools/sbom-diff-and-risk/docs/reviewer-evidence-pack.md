# Reviewer evidence pack

This page is a reproducible evidence checklist for reviewing `sbom-diff-and-risk`. It focuses on what can be verified from the repository, examples, GitHub release assets, and TestPyPI dry-run documentation. It does not introduce new CLI behavior.

For the shortest ordered route through these materials, start with
[reviewer-path.md](reviewer-path.md).

For interpreting checked-in examples, use the
[artifact evidence map](reviewer-path.md#artifact-evidence-map). It separates
deterministic no-network examples, mocked enrichment snapshots, and consumer
workflow templates.

## Project Identity

`sbom-diff-and-risk` is a local-first deterministic CLI for comparing SBOMs and dependency manifests. It is designed to produce stable review evidence for dependency changes.

Current released version: `v1.0-rc.1` release candidate.

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
  --summary-json outputs/summary.json `
  --out-md outputs/report.md
```

Expected output files:

- `outputs/report.json`
- `outputs/summary.json`
- `outputs/report.md`

Compare the outputs against the checked-in sample reports:

```powershell
Compare-Object (Get-Content examples/sample-report.json) (Get-Content outputs/report.json)
Compare-Object (Get-Content examples/sample-summary.json) (Get-Content outputs/summary.json)
Compare-Object (Get-Content examples/sample-report.md) (Get-Content outputs/report.md)
```

No differences means the sample path reproduced the committed example output.

`examples/sample-summary.json` is the summary-only artifact for the same run
and is expected to match `examples/sample-report.json`'s `summary` object.

Maintainers can also verify checked-in no-network JSON, Markdown, summary,
policy sidecar, and SARIF examples in one pass:

```powershell
python scripts/regenerate-example-artifacts.py --check
```

For the exact regeneration scope, see
[example-artifact-regeneration.md](example-artifact-regeneration.md).

This check covers deterministic no-network examples only. Provenance-aware and
Scorecard-aware checked-in examples are focused rendering snapshots built by
golden tests with constructed evidence; they are not live PyPI or Scorecard
lookups.

Generate the strict-policy JSON sidecar:

```powershell
sbom-diff-risk compare `
  --before examples/cdx_before.json `
  --after examples/cdx_after.json `
  --policy examples/policy-strict.yml `
  --out-json outputs/policy-report.json `
  --policy-json outputs/policy.json
```

The strict policy example returns exit code `1` because it intentionally
produces blocking local policy findings. The JSON artifacts are still written.

Compare the sidecar output against the checked-in sample:

```powershell
Compare-Object (Get-Content examples/sample-policy.json) (Get-Content outputs/policy.json)
```

`examples/sample-policy.json` is expected to match the policy-related sections
from `outputs/policy-report.json`, including `summary.policy`, policy finding
lists, and `rule_catalog`. It intentionally omits full report `components` and
`risks`.

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

For consumers of the JSON output, see [report-schema.md](report-schema.md). It
documents the stable `summary` contract, including conditional
`summary.policy` and `summary.enrichment` fields.

For policy finding interpretation, see
[policy-decision-explainability.md](policy-decision-explainability.md). It
documents the policy decision metadata used to explain local blocks, warnings,
and suppressions.

For a fixed one-page policy warning case, see
[policy-warning-reviewer-case.md](policy-warning-reviewer-case.md). It traces
the checked-in CycloneDX example pair and `policy-minimal.yml` from added
dependency to `new_package` warning without turning the warning into a package
safety verdict.

For CI job-summary examples that consume policy decision metadata, see
[policy-decision-ci-cookbook.md](policy-decision-ci-cookbook.md).

For a copyable GitHub Actions example that captures `outputs/policy.json`, see
[../examples/github-actions-policy-consumer.yml](../examples/github-actions-policy-consumer.yml).

For CI dashboard, job-summary, and local-threshold examples that consume
`outputs/summary.json`, see
[summary-json-ci-cookbook.md](summary-json-ci-cookbook.md).

## Release Verification Path

Start with the GitHub Release for the version under review. For `v1.0-rc.1`,
inspect the release and assets:

```powershell
gh release view v1.0-rc.1 `
  --repo stacknil/scientific-computing-toolkit `
  --json tagName,name,isDraft,isPrerelease,assets,url
```

Expected release assets:

- `sbom_diff_and_risk-1.0rc1-py3-none-any.whl`
- `sbom_diff_and_risk-1.0rc1.tar.gz`
- `sbom-diff-and-risk-SHA256SUMS.txt`

For this rc, `isPrerelease` should be `true`.

The checksum manifest checks local downloaded distribution bytes before or alongside provenance verification:

```powershell
gh release download <tag> `
  --repo stacknil/scientific-computing-toolkit `
  --pattern 'sbom_diff_and_risk-*' `
  --pattern 'sbom-diff-and-risk-SHA256SUMS.txt' `
  --dir release-assets
Set-Location release-assets
Get-Content .\sbom-diff-and-risk-SHA256SUMS.txt | ForEach-Object {
  $expected, $file = $_ -split '\s+', 2
  $actual = ((Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash).ToLowerInvariant()
  if ($actual -ne $expected) {
    throw "Checksum mismatch for $file"
  }
  "$file OK"
}
```

Checksum verification confirms local byte integrity against the release
manifest; it does not replace workflow artifact attestations or
immutable-release verification. The attestation subject remains the built wheel
and source distribution.

For workflow-built artifacts downloaded from a trusted workflow run, verify
artifact attestations with the signer workflow:

```powershell
gh attestation verify path/to/sbom_diff_and_risk-1.0rc1-py3-none-any.whl `
  --repo stacknil/scientific-computing-toolkit `
  --signer-workflow stacknil/scientific-computing-toolkit/.github/workflows/sbom-diff-and-risk-ci.yml
```

```powershell
gh attestation verify path/to/sbom_diff_and_risk-1.0rc1.tar.gz `
  --repo stacknil/scientific-computing-toolkit `
  --signer-workflow stacknil/scientific-computing-toolkit/.github/workflows/sbom-diff-and-risk-ci.yml
```

`gh release verify` and `gh release verify-asset` are conditional on immutable
releases. Use them only when the repository release is immutable and GitHub has
generated release attestations:

```powershell
gh release view v1.0-rc.1 --repo stacknil/scientific-computing-toolkit --json isImmutable,assets,url
```

If `isImmutable` is true, release verification can check the release record and
downloaded release assets:

```powershell
gh release verify v1.0-rc.1 --repo stacknil/scientific-computing-toolkit
gh release verify-asset v1.0-rc.1 path/to/sbom_diff_and_risk-1.0rc1-py3-none-any.whl --repo stacknil/scientific-computing-toolkit
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
- Can I see machine-readable security output? Inspect or regenerate `examples/sample-sarif.sarif`, and read `report-schema.md` for JSON report shape.
- Can I verify release/distribution evidence? Read `verification.md`, `self-provenance.md`, and `release-provenance.md`.
- Can I distinguish TestPyPI from production PyPI? Read `pypi-trusted-publishing-readiness.md` and `pypi-production-publishing-decision.md`.
- Can I state the non-claims? No CVE scanner, no reputation oracle, no dependency safety verdicts, no production PyPI package yet.
