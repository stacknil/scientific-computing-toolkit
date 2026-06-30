# Policy warning reviewer case

This one-page case fixes a single reviewer question: how does a dependency diff
produce a local policy warning?

It uses the checked-in CycloneDX example pair and the minimal policy. No
network enrichment, CVE lookup, malware scan, or package safety verdict is
involved.

## Fixed input

Run from `tools/sbom-diff-and-risk`:

```powershell
sbom-diff-risk compare `
  --before examples/cdx_before.json `
  --after examples/cdx_after.json `
  --policy examples/policy-minimal.yml `
  --out-json outputs/policy-warn-report.json `
  --out-md outputs/policy-warn-report.md
```

Reference inputs and policy:

- [`examples/cdx_before.json`](../examples/cdx_before.json)
- [`examples/cdx_after.json`](../examples/cdx_after.json)
- [`examples/policy-minimal.yml`](../examples/policy-minimal.yml)

The minimal policy is intentionally small:

```yaml
version: 1
block_on:
  - unknown_license
warn_on:
  - new_package
```

## Fixed output

The checked-in reference outputs are:

- [`examples/sample-policy-warn-report.json`](../examples/sample-policy-warn-report.json)
- [`examples/sample-policy-warn-report.md`](../examples/sample-policy-warn-report.md)

The fixed JSON facts for this case are:

| Field | Value |
| --- | --- |
| `summary.added` | `1` |
| `summary.changed` | `1` |
| `summary.evidence_confidence` | `policy_matched` |
| `summary.policy.status` | `warn` |
| `summary.policy.blocking` | `0` |
| `summary.policy.warning` | `1` |
| `warning_findings[0].policy_rule` | `new_package` |
| `warning_findings[0].component_name` | `urllib3` |
| `warning_findings[0].decision_reason` | `risk_finding_matched_policy_rule` |
| `warning_findings[0].severity_source` | `warn_on` |
| `warning_findings[0].observed_value` | `new_package` |

## Explanation

The after input contains `urllib3` `2.2.1`, which is not present in the before
input. The local risk model classifies that component as `new_package`.

`examples/policy-minimal.yml` maps `new_package` to `warn_on`, so policy
evaluation adds one warning finding for `urllib3`. The tool exits successfully
because the warning does not become a blocking policy violation.

The `requests` version change is still visible in the report, but it is not the
source of this policy warning. It receives `version_change_unclassified` and
`not_evaluated` findings in offline mode, and the minimal policy does not warn
or block on either rule.

## Fixed boundary

This case proves that local policy matching can explain why a dependency diff
triggered a warning.

It does not prove:

- `urllib3` is unsafe
- `requests` is safe
- any CVE result
- any malware verdict
- not a package safety verdict
- current PyPI package truth
- current repository reputation

For field-level policy metadata, see
[policy-decision-explainability.md](policy-decision-explainability.md). For
the risk inputs and non-claims, see
[risk-model-boundary.md](../../../docs/risk-model-boundary.md).
