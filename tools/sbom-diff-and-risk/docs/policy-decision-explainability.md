# Policy decision explainability

This page explains the machine-readable policy decision metadata emitted in
JSON reports. It is intended for reviewers and CI consumers who need to
understand why a local policy rule produced a block, warning, or suppression.

The fields described here are explainability metadata for local policy
decisions. They are not dependency safety verdicts, CVE results, or proof that a
package is safe or unsafe.

## Where the fields appear

Policy decision explanation fields appear only on policy finding objects, such
as:

- `policy_evaluation.blocking_violations`
- `policy_evaluation.warning_violations`
- `policy_evaluation.suppressed_violations`
- `blocking_findings`
- `warning_findings`
- `suppressed_findings`
- provenance policy impact sections

Risk findings in `risks` remain the analyzer's local heuristic findings. They
do not receive policy-decision metadata unless policy evaluation maps them into
policy findings.

## Field contract

- `decision_reason`: Stable reason code for the policy decision.
- `policy_rule`: Policy rule id that produced the decision.
- `severity_source`: Source of the active severity, such as `block_on`,
  `warn_on`, `default_block`, or `default_warn`; `null` when there is no active
  severity.
- `matched_threshold`: Configured threshold or allowlist value involved in the
  decision, when applicable.
- `observed_value`: Observed local value that was compared to the policy rule,
  when applicable.

The full JSON report shape is documented in [report-schema.md](report-schema.md).
Policy configuration fields and supported rules are documented in
[policy-schema.md](policy-schema.md).

## Example interpretations

A policy finding with:

```json
{
  "decision_reason": "added_package_count_exceeded_threshold",
  "policy_rule": "max_added_packages",
  "severity_source": "block_on",
  "matched_threshold": 0,
  "observed_value": 1
}
```

means the local policy compared an observed added-package count of `1` against a
configured threshold of `0`, and the matching rule was active through
`block_on`.

A policy finding with:

```json
{
  "decision_reason": "risk_finding_matched_policy_rule",
  "policy_rule": "new_package",
  "severity_source": "warn_on",
  "matched_threshold": null,
  "observed_value": "new_package"
}
```

means a local heuristic risk finding matched the `new_package` policy rule, and
the matching rule was active through `warn_on`.

## CI and review usage

Consumers can use these fields to group policy findings by rule, explain why a
local gate failed, or build small job summaries. For example, a CI step can read
`blocking_findings`, print each `policy_rule` and `decision_reason`, and fail
only because the tool already returned a policy failure exit code.

Use `summary.policy` for compact counts and status. Use policy finding
explanation fields when a reviewer needs to inspect why the status was
`warn` or `fail`.

## Compatibility notes

- The fields are additive JSON metadata for policy findings.
- `summary.policy` is unchanged and remains the compact count/status surface.
- Absence of policy findings means policy evaluation did not produce findings
  for that section.
- Absence of policy explanation fields outside policy finding objects is
  expected.
- Consumers should treat unrecognized future fields as additive report data.

## Non-claims

- The fields do not resolve CVEs.
- The fields do not claim a package is safe or unsafe.
- The fields do not add network behavior.
- The fields do not replace human review of local policy choices.
