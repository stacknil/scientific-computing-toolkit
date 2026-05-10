# JSON report schema

This document describes the stable, reviewer-facing shape of
`sbom-diff-and-risk` JSON reports. The JSON format is intended for machine
consumption in CI, review tooling, and audit trails. Human-readable review
notes remain in the Markdown report.

The schema is conservative and additive where possible. Golden sample reports
in `examples/` lock important output shape for the default, policy, provenance,
and Scorecard paths.

## Top-level structure

JSON reports currently use this top-level structure:

| Field | Description |
| --- | --- |
| `summary` | Compact count-only run summary for deterministic machine consumption. |
| `components` | Added, removed, and changed component records. |
| `risks` | Heuristic risk findings generated from the diff. |
| `policy_evaluation` | Policy evaluation details when policy state is represented in the report. |
| `blocking_findings` | Policy findings that make the run fail. |
| `warning_findings` | Policy findings that are warnings only. |
| `suppressed_findings` | Policy findings suppressed by policy configuration. |
| `rule_catalog` | Policy rule metadata used to interpret policy findings. |
| `provenance_summary` | PyPI provenance evidence summary when available from report presentation. |
| `attestation_summary` | PyPI file attestation summary when available from report presentation. |
| `scorecard_summary` | OpenSSF Scorecard evidence summary when available from report presentation. |
| `enrichment_metadata` | Top-level enrichment metadata used by trust-signal report sections. |
| `trust_signal_notes` | Review notes for provenance and Scorecard trust signals. |
| `metadata` | Run metadata such as input formats, generation time, strict mode, policy state, and enrichment state. |
| `notes` | Additional report notes. |

When provenance policy fields are relevant, reports may also include
`provenance_policy` and `provenance_policy_impact`. Consumers should treat
unrecognized top-level fields as additive report data.

## Policy finding explanation fields

Policy findings in the following report sections include stable explainability
metadata:

- `policy_evaluation.blocking_violations`
- `policy_evaluation.warning_violations`
- `policy_evaluation.suppressed_violations`
- `blocking_findings`
- `warning_findings`
- `suppressed_findings`
- provenance policy impact sections

These fields describe why a local policy rule produced a block, warning, or
suppression. They are policy-decision metadata only; they are not dependency
safety verdicts, CVE results, or proof that a package is safe or unsafe.

- `decision_reason`: Stable reason code for the policy decision, such as
  `risk_finding_matched_policy_rule`,
  `added_package_count_exceeded_threshold`, or
  `scorecard_score_below_threshold`.
- `policy_rule`: Policy rule id that produced the decision. This mirrors
  `rule_id` for consumers that group explanation data separately.
- `severity_source`: Source of the active severity, such as `block_on`,
  `warn_on`, `default_block`, or `default_warn`; `null` when a policy finding
  has no active severity.
- `matched_threshold`: Configured threshold or allowlist value involved in the
  decision, when applicable.
- `observed_value`: Observed local value that was compared to the policy rule,
  when applicable.

Explanation fields appear only on policy finding objects. Risk findings in
`risks` remain the analyzer's local heuristic findings and do not receive
policy-decision metadata unless a policy evaluation maps them into policy
findings.

For reviewer-facing examples and interpretation guidance, see
[policy-decision-explainability.md](policy-decision-explainability.md). For CI
consumer snippets, see
[policy-decision-ci-cookbook.md](policy-decision-ci-cookbook.md).

The `--policy-json PATH` CLI option writes a policy-only JSON sidecar using the
same policy-related sections from the full JSON report:

- `policy_evaluation`
- `blocking_findings`
- `warning_findings`
- `suppressed_findings`
- `rule_catalog`
- `summary.policy` when policy evaluation is applied
- `provenance_policy` and `provenance_policy_impact` when provenance policy
  fields are relevant

The checked-in [sample-policy.json](../examples/sample-policy.json) artifact
locks the standalone policy sidecar shape for a strict policy example.

## Summary contract

`summary` is the stable, compact entry point for automation that needs counts
without walking the full report. The `--summary-json PATH` CLI option writes
only this stable `report.json["summary"]` object.

The checked-in [../examples/sample-summary.json](../examples/sample-summary.json)
artifact is the summary-only output for the default CycloneDX example and
matches the `summary` object in
[../examples/sample-report.json](../examples/sample-report.json). For CI
consumption examples, see
[summary-json-ci-cookbook.md](summary-json-ci-cookbook.md).

Base `summary` fields:

| Field | Meaning |
| --- | --- |
| `added` | Number of components present only in the after input. |
| `removed` | Number of components present only in the before input. |
| `changed` | Number of components present in both inputs with a detected change. |
| `risk_counts` | Map of risk bucket name to count. |

There is intentionally no `unchanged` field. The current diff model does not
track unchanged components, so reporting an unchanged count would imply a model
guarantee that does not exist.

`summary.policy` appears only when a policy is applied. Absence of
`summary.policy` means policy was not used, not that policy evaluation failed.

| Field | Meaning |
| --- | --- |
| `summary.policy.status` | `pass`, `warn`, or `fail`. |
| `summary.policy.blocking` | Count of blocking policy violations. |
| `summary.policy.warning` | Count of warning policy violations. |
| `summary.policy.suppressed` | Count of suppressed policy violations. |

`summary.enrichment` appears only when PyPI or Scorecard enrichment is used.
Absence of `summary.enrichment` means enrichment was not used, not that
enrichment failed.

| Field | Meaning |
| --- | --- |
| `summary.enrichment.status` | Currently `used` when enrichment ran. |
| `summary.enrichment.mode` | Enrichment mode recorded for the run. |
| `summary.enrichment.pypi.candidate_components` | Count of components considered for PyPI enrichment. |
| `summary.enrichment.pypi.supported_components` | Count of components supported by PyPI enrichment. |
| `summary.enrichment.pypi.status_counts` | Sorted map of PyPI enrichment status names to counts. |
| `summary.enrichment.scorecard.candidate_components` | Count of components considered for Scorecard enrichment. |
| `summary.enrichment.scorecard.supported_components` | Count of components supported by Scorecard enrichment. |
| `summary.enrichment.scorecard.status_counts` | Sorted map of Scorecard enrichment status names to counts. |

Provider-specific `pypi` and `scorecard` objects appear only for the providers
used in that run. Their `status_counts` maps are sorted by key to keep output
stable for tests and downstream consumers.

## Stability notes

- JSON reports are intended for machine consumption.
- Golden samples lock important output shape for stable reviewer and CI expectations.
- The schema is conservative and additive where possible.
- Missing `summary.policy` means policy was not applied.
- Missing `summary.enrichment` means PyPI and Scorecard enrichment were not used.
- Runtime details remain in the fuller report fields; `summary` stays count-only.

## Non-claims

- The report does not resolve CVEs.
- The report does not produce package safety verdicts.
- Default runs do not perform hidden network access.
- PyPI and Scorecard enrichment are opt-in.
- Missing provenance, attestation, or Scorecard evidence is an evidence gap, not proof of compromise.
