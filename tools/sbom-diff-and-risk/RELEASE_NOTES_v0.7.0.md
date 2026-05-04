# sbom-diff-and-risk v0.7.0

Draft release notes for `v0.7.0`.

Release notes file: `RELEASE_NOTES_v0.7.0.md`.

This PR only drafts release notes. It does not bump package version, create a
tag, publish a GitHub Release, or publish to PyPI/TestPyPI.

## Theme

Consumer integration usability.

`v0.7.0` focuses on consumer-facing examples and CI integration guidance for the
existing machine-readable summary output. It does not change the core dependency
diff model, CLI behavior, JSON report schema, Markdown output, SARIF output,
workflows, release tags, or publishing status.

## Highlights

- Added a summary JSON CI cookbook in
  [docs/summary-json-ci-cookbook.md](docs/summary-json-ci-cookbook.md).
- Added a checked-in summary-only example artifact at
  [examples/sample-summary.json](examples/sample-summary.json).
- Added a consumer-facing GitHub Actions example in
  [docs/github-actions-consumer-example.md](docs/github-actions-consumer-example.md).
- Documented explicit local thresholding with `summary.json`.
- Documented a GitHub Release wheel installation path for consumer workflows.
- Kept production PyPI intentionally deferred.

## Consumer integration examples

The summary JSON CI cookbook shows how to run:

```bash
sbom-diff-risk compare \
  --before examples/cdx_before.json \
  --after examples/cdx_after.json \
  --out-json outputs/report.json \
  --summary-json outputs/summary.json
```

It also shows Python and PowerShell consumers that read `outputs/summary.json`
and apply local thresholds chosen by the consuming repository.

The GitHub Actions consumer example shows how another repository can install
`sbom-diff-risk` from GitHub Release assets instead of production PyPI, run
`compare`, write JSON, Markdown, summary JSON, and SARIF outputs, and upload the
generated files as CI artifacts.

`summary.json` thresholding is a local consumer policy choice. It is not a
built-in dependency safety verdict.

## Compatibility and boundaries

- `report.json["summary"]` remains the stable compact summary object.
- `--summary-json PATH` writes the same object as `report.json["summary"]`.
- [examples/sample-summary.json](examples/sample-summary.json) remains a
  checked-in sample for the default CycloneDX example.
- `summary.policy` appears only when policy evaluation is applied.
- `summary.enrichment` appears only when PyPI or Scorecard enrichment is used.
- `unchanged` remains absent because unchanged components are not modeled.
- `sbom-diff-risk` is not a CVE scanner.
- `sbom-diff-risk` is not a dependency safety oracle.
- No hidden network behavior was added.
- No dependency analysis behavior changed.

## Distribution status

- The latest published GitHub Release before this draft is `v0.6.0`.
- This PR does not tag or publish `v0.7.0`.
- This PR does not publish to TestPyPI.
- This PR does not publish to production PyPI.
- Production PyPI publishing remains intentionally deferred.
- The GitHub Actions consumer example installs from GitHub Release assets, not
  production PyPI.

## Not in this release

- No CLI behavior changes.
- No JSON schema changes.
- No Markdown output behavior changes.
- No SARIF output behavior changes.
- No workflow changes.
- No package version bump.
- No release tag or GitHub Release creation in this PR.
- No PyPI/TestPyPI publishing.
- No production PyPI workflow.
- No CVE lookup or CVE resolution.
- No dependency safety verdicts.
