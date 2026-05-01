# sbom-diff-and-risk v0.6.0 draft release notes

These are draft release notes for the planned `v0.6.0` release. This PR does not tag or publish `v0.6.0`, does not create a GitHub Release, and does not publish to PyPI or TestPyPI.

## Theme

Machine-readable report consumption and summary-output usability.

`v0.6.0` focuses on making the existing JSON report easier to consume from automation without changing the core dependency diff model, Markdown output, SARIF output, workflows, package version, or publishing status.

## Highlights

- Added a stable, compact JSON `summary` contract for machine-readable report consumers.
- Documented the JSON report schema in [docs/report-schema.md](docs/report-schema.md).
- Added optional `--summary-json PATH` output for consumers that only need the stable summary object.
- Preserved the existing `--out-json` report shape and behavior.
- Kept production PyPI intentionally deferred.

## Machine-readable output changes

- `report.json["summary"]` is the stable compact entry point for automation.
- `--summary-json PATH` writes only the same stable object as `report.json["summary"]`.
- The base summary remains count-only:
  - `added`
  - `removed`
  - `changed`
  - `risk_counts`
- `summary.policy` appears only when policy is applied.
- `summary.enrichment` appears only when PyPI or Scorecard enrichment is used.
- `unchanged` remains absent because unchanged components are not modeled.
- Existing `--out-json` behavior is unchanged.

## JSON schema / compatibility notes

- JSON reports remain the primary machine-readable report format.
- The schema is conservative and additive where possible.
- Golden JSON samples and tests cover important output-shape expectations.
- Absence of `summary.policy` means policy was not applied, not that policy failed.
- Absence of `summary.enrichment` means PyPI and Scorecard enrichment were not used, not that enrichment failed.
- `--summary-json PATH` does not introduce a second summary schema; it reuses the same summary rendering path as the full JSON report.

## Verification and evidence surfaces

- JSON schema documentation: [docs/report-schema.md](docs/report-schema.md).
- Reviewer evidence pack: [docs/reviewer-evidence-pack.md](docs/reviewer-evidence-pack.md).
- Verification guide: [docs/verification.md](docs/verification.md).
- Release provenance guide: [docs/release-provenance.md](docs/release-provenance.md).
- TestPyPI Trusted Publishing readiness: [docs/pypi-trusted-publishing-readiness.md](docs/pypi-trusted-publishing-readiness.md).
- Production PyPI decision gate: [docs/pypi-production-publishing-decision.md](docs/pypi-production-publishing-decision.md).

These surfaces remain distinct: GitHub workflow artifact attestations, GitHub Release asset verification, TestPyPI Trusted Publishing validation, and future production PyPI Trusted Publishing provenance answer different trust questions.

## Distribution status

- Latest GitHub Release remains `v0.5.1` until a future release PR creates the `v0.6.0` tag and release.
- This PR does not tag or publish `v0.6.0`.
- This PR does not create a GitHub Release.
- This PR does not publish to TestPyPI.
- This PR does not publish to production PyPI.
- Production PyPI remains intentionally deferred.

## Not in this release

- No Markdown output behavior changed.
- No SARIF behavior changed.
- No workflow behavior changed.
- No package version bump is included in this draft-notes PR.
- No production PyPI workflow is added.
- No hidden network behavior was added.
- No CVE lookup or CVE resolution was added.
- No dependency safety verdicts were added.
- No dependency analysis behavior changed.
