# Policy decision CI cookbook

This page shows how to consume policy decision explanation fields from the
`--policy-json PATH` sidecar in CI without changing the `sbom-diff-risk`
analysis model.

Use this when a repository wants a small job summary that explains local policy
blocks, warnings, or suppressions in machine-readable terms.

## Minimal command

```bash
sbom-diff-risk compare \
  --before examples/cdx_before.json \
  --after examples/cdx_after.json \
  --policy examples/policy-strict.yml \
  --out-json outputs/report.json \
  --policy-json outputs/policy.json
```

The strict example policy can make the command return a policy failure exit
code. In CI, keep the generated `outputs/policy.json` artifact so the policy
decision metadata remains available for review.

For a checked-in reference artifact generated from this path, see
[sample-policy.json](../examples/sample-policy.json).

For compact consumer examples that distinguish `pass`, `warn`, `fail`, and
`needs-review` review outcomes, see
[examples/policy-decisions](../examples/policy-decisions/README.md).

For a minimal GitHub Actions consumer workflow example that captures
`outputs/policy.json`, uploads it before the final pass/fail step, and then
uses the tool's exit code as the CI result, see
[github-actions-policy-consumer.yml](../examples/github-actions-policy-consumer.yml).

## Python consumer

This example reads the policy-only JSON sidecar, prints compact policy status,
and then prints the stable explanation fields for blocking and warning findings.

```python
import json
from pathlib import Path

report = json.loads(
    Path("outputs/policy.json").read_text(encoding="utf-8")
)

policy = report.get("summary", {}).get("policy")
if policy is None:
    print("policy=not-used")
    raise SystemExit(0)

print(
    "policy="
    f"{policy['status']} "
    f"blocking={policy['blocking']} "
    f"warning={policy['warning']} "
    f"suppressed={policy['suppressed']}"
)

findings = (
    report.get("blocking_findings", [])
    + report.get("warning_findings", [])
    + report.get("suppressed_findings", [])
)

for finding in findings:
    print(
        "policy-finding "
        f"level={finding.get('level')} "
        f"rule={finding.get('policy_rule')} "
        f"reason={finding.get('decision_reason')} "
        f"severity_source={finding.get('severity_source')} "
        f"observed={finding.get('observed_value')} "
        f"threshold={finding.get('matched_threshold')}"
    )

if policy["status"] == "fail":
    raise SystemExit("local policy failed")
```

The final failure is based on the local policy status already produced by the
tool. The snippet does not create a new package safety verdict.

## PowerShell consumer

This example uses `ConvertFrom-Json` to print the same policy status and
explanation fields from the policy-only sidecar.

```powershell
$report = Get-Content outputs/policy.json -Raw | ConvertFrom-Json
$policy = $report.summary.policy

if ($null -eq $policy) {
  Write-Output "policy=not-used"
  exit 0
}

Write-Output (
  "policy={0} blocking={1} warning={2} suppressed={3}" -f
  $policy.status,
  $policy.blocking,
  $policy.warning,
  $policy.suppressed
)

$findings = @()
$findings += @($report.blocking_findings)
$findings += @($report.warning_findings)
$findings += @($report.suppressed_findings)

foreach ($finding in $findings) {
  Write-Output (
    "policy-finding level={0} rule={1} reason={2} severity_source={3} observed={4} threshold={5}" -f
    $finding.level,
    $finding.policy_rule,
    $finding.decision_reason,
    $finding.severity_source,
    $finding.observed_value,
    $finding.matched_threshold
  )
}

if ($policy.status -eq "fail") {
  throw "local policy failed"
}
```

## Compatibility notes

- `summary.policy` appears only when policy evaluation is applied.
- Policy decision explanation fields appear only on policy finding objects.
- `risks` remains the local heuristic finding list; use policy finding sections
  when you need policy-decision metadata.
- Consumers should treat unrecognized future fields as additive report data.
- Use `summary.policy` for compact status and counts.
- Use policy finding explanation fields for reviewer-facing detail.

## Non-claims

- The policy decision fields are not CVE results.
- The policy decision fields are not dependency safety verdicts.
- The snippets do not add network behavior.
- The snippets do not replace human review of local policy choices.
- Production PyPI publishing remains intentionally deferred.
