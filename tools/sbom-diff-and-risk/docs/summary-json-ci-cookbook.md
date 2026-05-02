# Summary JSON CI cookbook

This page shows how to consume `--summary-json PATH` in CI without changing
the `sbom-diff-risk` analysis model.

`--summary-json` writes a compact machine-readable JSON object. It is the same
object as `report.json["summary"]`, and is useful for CI dashboards, job
summaries, and small local gates where a repository wants to set its own
thresholds.

## Minimal command

```bash
sbom-diff-risk compare \
  --before examples/cdx_before.json \
  --after examples/cdx_after.json \
  --out-json outputs/report.json \
  --summary-json outputs/summary.json
```

The full report remains available at `outputs/report.json`. The compact
summary-only object is written to `outputs/summary.json`.

## Python consumer

This example reads the summary and applies an explicit local threshold. The
threshold is chosen by the caller; it is not a built-in package safety verdict.

```python
import json
from pathlib import Path

summary = json.loads(Path("outputs/summary.json").read_text(encoding="utf-8"))

added = summary["added"]
removed = summary["removed"]
changed = summary["changed"]
risk_counts = summary["risk_counts"]

print(f"added={added} removed={removed} changed={changed}")
print(f"risk_counts={risk_counts}")

max_new_packages = 2
if risk_counts.get("new_package", 0) > max_new_packages:
    raise SystemExit(f"new_package count exceeds local threshold: {max_new_packages}")
```

## PowerShell consumer

This example uses `ConvertFrom-Json` and applies the same kind of explicit
local threshold.

```powershell
$summary = Get-Content outputs/summary.json -Raw | ConvertFrom-Json

$added = $summary.added
$removed = $summary.removed
$changed = $summary.changed
$newPackageCount = $summary.risk_counts.new_package

Write-Output "added=$added removed=$removed changed=$changed"
Write-Output "new_package=$newPackageCount"

$maxNewPackages = 2
if ($newPackageCount -gt $maxNewPackages) {
  throw "new_package count exceeds local threshold: $maxNewPackages"
}
```

## Compatibility notes

- `summary.policy` appears only when policy evaluation is applied.
- `summary.enrichment` appears only when PyPI or Scorecard enrichment is used.
- `unchanged` is absent because unchanged components are not modeled.
- Absence of `summary.policy` or `summary.enrichment` means the feature was
  not used, not that it failed.
- Consumers should treat new unrecognized fields as additive data.

## Non-claims

- `sbom-diff-risk` is not a CVE scanner.
- The summary is not a dependency safety oracle.
- Default runs do not perform hidden network access.
- Production PyPI publishing remains intentionally deferred.
