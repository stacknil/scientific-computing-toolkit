# sbom-diff-and-risk v0.9.0

`v0.9.0` is the policy JSON sidecar and consumer integration usability
release.

## Theme

Policy-focused machine-readable output for CI consumers.

`v0.9.0` focuses on making local policy outcomes easier to consume without
walking the full JSON report. It adds a policy-only JSON sidecar, checked-in
policy sidecar examples, and copyable GitHub Actions consumer guidance.

This release keeps the dependency diff model, existing full-report JSON shape,
Markdown output behavior, SARIF output behavior, release workflows, and
publishing status unchanged except for the new optional CLI output surface.

## Highlights

- Added optional `--policy-json PATH` support to `sbom-diff-risk compare`.
- Added a checked-in `examples/sample-policy.json` artifact for the policy
  sidecar shape.
- Added a GitHub Actions policy consumer example at
  `examples/github-actions-policy-consumer.yml`.
- Updated reviewer-facing evidence documentation for reproducing and consuming
  `outputs/policy.json`.
- Kept production PyPI intentionally deferred.

## Policy JSON sidecar

`--policy-json PATH` writes policy-related JSON sections from the same report
model used by `--out-json`. It does not introduce a second policy schema.

The sidecar includes:

- `policy_evaluation`
- `blocking_findings`
- `warning_findings`
- `suppressed_findings`
- `rule_catalog`
- `summary.policy` when policy evaluation is applied
- provenance policy sections when those sections are relevant

The sidecar intentionally omits full-report `components` and `risks`. Consumers
that need the complete dependency diff should continue to use `--out-json`.

When policy is not applied, the sidecar records
`policy_evaluation.applied` as `false` and omits `summary.policy`.

## Consumer integration examples

`examples/sample-policy.json` is generated from the existing CycloneDX example
pair with `examples/policy-strict.yml`. It is locked by tests and is expected to
match the policy-related sections in the corresponding full policy-fail JSON
report.

`examples/github-actions-policy-consumer.yml` shows how a consumer repository
can:

- install from the GitHub Release wheel, not production PyPI
- run `sbom-diff-risk compare` with `--policy-json`
- keep `outputs/policy.json` as a CI artifact
- upload evidence even when local policy fails
- fail the job from `summary.policy`

The example is documentation only. It is not a workflow for this repository and
does not change this repository's GitHub Actions configuration.

## Compatibility and boundaries

- Existing `--out-json` behavior remains the full JSON report output.
- Existing `--summary-json PATH` behavior remains summary-only output.
- Existing Markdown output behavior is unchanged.
- Existing SARIF output behavior is unchanged.
- Existing policy pass, warn, and fail behavior is unchanged.
- Existing exit codes are unchanged.
- No hidden network behavior was added.
- No CVE lookup or CVE resolution was added.
- Policy findings remain local policy decisions, not dependency safety
  verdicts.
- Consumers should treat unrecognized future fields as additive report data.

## Distribution status

- Production PyPI publishing remains intentionally deferred.
- This release is expected to be distributed through GitHub Release assets.
- The consumer examples install from GitHub Release assets or local checkout,
  not production PyPI.
- This release does not publish to TestPyPI.
- This release does not publish to production PyPI.
- No production PyPI workflow is added.

## Not in this release

- No package safety verdicts.
- No vulnerability scanning.
- No CVE resolution.
- No default network enrichment.
- No workflow changes for this repository.
- No TestPyPI publishing.
- No production PyPI publishing.
- No production PyPI workflow.

The v0.9.0 release is prepared for the tag-gated GitHub Release workflow. It
does not publish to PyPI/TestPyPI and keeps production PyPI intentionally
deferred.
