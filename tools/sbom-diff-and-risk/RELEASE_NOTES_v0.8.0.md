# sbom-diff-and-risk v0.8.0

`v0.8.0` is the policy decision explainability release.

## Theme

Policy decision explainability for machine-readable JSON reports.

`v0.8.0` focuses on making local policy outcomes easier to inspect from JSON
reports and reviewer documentation. It keeps the dependency diff model,
existing CLI flags, Markdown output behavior, SARIF output behavior, workflows,
release tags, and publishing status unchanged.

## Highlights

- Added stable policy decision explanation fields to JSON policy findings.
- Documented those fields in
  [docs/report-schema.md](docs/report-schema.md).
- Added reviewer-facing interpretation guidance in
  [docs/policy-decision-explainability.md](docs/policy-decision-explainability.md).
- Kept `summary.policy` unchanged as the compact policy count/status surface.
- Kept production PyPI intentionally deferred.

## Machine-readable policy explainability

Policy findings in JSON reports can now include additive explanation fields:

- `decision_reason`
- `policy_rule`
- `severity_source`
- `matched_threshold`
- `observed_value`

These fields explain why a local policy rule produced a block, warning, or
suppression. They are policy-decision metadata only; they are not dependency
safety verdicts, CVE results, or proof that a package is safe or unsafe.

The fields appear only on policy finding objects, such as:

- `policy_evaluation.blocking_violations`
- `policy_evaluation.warning_violations`
- `policy_evaluation.suppressed_violations`
- `blocking_findings`
- `warning_findings`
- `suppressed_findings`
- provenance policy impact sections

Risk findings in `risks` remain local heuristic findings. They do not receive
policy-decision metadata unless policy evaluation maps them into policy
findings.

## JSON schema / compatibility notes

- The JSON report schema remains conservative and additive where possible.
- Existing `summary.policy` behavior is unchanged.
- Existing `--out-json` behavior remains the full JSON report output.
- Existing `--summary-json PATH` behavior remains summary-only output.
- Existing policy pass, warn, and fail behavior is unchanged.
- Existing CLI flags are unchanged.
- Consumers should treat unrecognized future fields as additive report data.

## Documentation and evidence surfaces

- JSON report schema:
  [docs/report-schema.md](docs/report-schema.md)
- Policy schema:
  [docs/policy-schema.md](docs/policy-schema.md)
- Policy decision explainability:
  [docs/policy-decision-explainability.md](docs/policy-decision-explainability.md)
- Reviewer evidence pack:
  [docs/reviewer-evidence-pack.md](docs/reviewer-evidence-pack.md)
- GitHub Actions consumer example:
  [docs/github-actions-consumer-example.md](docs/github-actions-consumer-example.md)
- Production PyPI decision gate:
  [docs/pypi-production-publishing-decision.md](docs/pypi-production-publishing-decision.md)

The v0.8 documentation keeps the release/distribution evidence surfaces
separate from tool behavior. GitHub workflow artifact attestations, GitHub
Release asset verification, TestPyPI Trusted Publishing validation, and future
production PyPI Trusted Publishing provenance answer different trust questions.

## Distribution status

- The `v0.8.0` GitHub Release is expected to be created from the tag-gated
  release workflow.
- Release assets are expected to include the wheel, source distribution, and
  `sbom-diff-and-risk-SHA256SUMS.txt`.
- This release does not publish to TestPyPI.
- This release does not publish to production PyPI.
- Production PyPI publishing remains intentionally deferred.
- No production PyPI workflow is added.

## Not in this release

- No new CLI flags.
- No Markdown output behavior changes.
- No SARIF output behavior changes.
- No workflow changes.
- No PyPI/TestPyPI publishing.
- No production PyPI workflow.
- No hidden network behavior.
- No CVE lookup or CVE resolution.
- No dependency safety verdicts.
