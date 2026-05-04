# GitHub Actions consumer example

This page shows how another repository could run `sbom-diff-risk` from GitHub
Actions and upload the generated review artifacts.

It is documentation only. It is not a workflow for this repository, and it does
not change the `sbom-diff-risk` CLI or publishing model.

Production PyPI publishing is intentionally deferred, so consumers should not
install `sbom-diff-and-risk` from production PyPI. Use a GitHub Release asset or
a local checkout instead.

## Example workflow

This example downloads the released wheel from the public GitHub Release, runs a
local comparison, writes JSON, Markdown, summary JSON, and SARIF outputs, applies
an explicit local threshold to `summary.json`, and uploads the outputs as CI
artifacts.

Replace the placeholder input paths with files from the consumer repository.
The same workflow is also checked in as
[../examples/github-actions-consumer.yml](../examples/github-actions-consumer.yml)
for copying into consumer repositories.

```yaml
name: Dependency diff review

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  dependency-diff:
    runs-on: ubuntu-latest

    steps:
      - name: Check out consumer repository
        uses: actions/checkout@v6

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: "3.x"

      - name: Download sbom-diff-and-risk release wheel
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          mkdir -p .tooling/sbom-diff-risk
          gh release download v0.6.0 \
            --repo stacknil/scientific-computing-toolkit \
            --pattern "sbom_diff_and_risk-0.6.0-py3-none-any.whl" \
            --dir .tooling/sbom-diff-risk

      - name: Install sbom-diff-risk
        run: |
          python -m pip install \
            .tooling/sbom-diff-risk/sbom_diff_and_risk-0.6.0-py3-none-any.whl

      - name: Compare dependency evidence
        run: |
          mkdir -p outputs
          sbom-diff-risk compare \
            --before path/to/before-sbom.json \
            --after path/to/after-sbom.json \
            --format auto \
            --out-json outputs/report.json \
            --out-md outputs/report.md \
            --summary-json outputs/summary.json \
            --out-sarif outputs/report.sarif

      - name: Apply local summary threshold
        run: |
          python - <<'PY'
          import json
          from pathlib import Path

          summary = json.loads(
              Path("outputs/summary.json").read_text(encoding="utf-8")
          )
          risk_counts = summary["risk_counts"]

          max_new_packages = 2
          new_package_count = risk_counts.get("new_package", 0)
          print(f"new_package={new_package_count}")

          if new_package_count > max_new_packages:
              raise SystemExit(
                  f"new_package count exceeds local threshold: {max_new_packages}"
              )
          PY

      - name: Upload dependency diff outputs
        uses: actions/upload-artifact@v7
        with:
          name: dependency-diff-outputs
          path: |
            outputs/report.json
            outputs/report.md
            outputs/summary.json
            outputs/report.sarif
```

## Local checkout variant

If the consumer repository vendors or checks out this toolkit repository, install
from that local checkout instead of downloading a release wheel:

```yaml
- name: Install sbom-diff-risk from local checkout
  run: |
    python -m pip install \
      path/to/scientific-computing-toolkit/tools/sbom-diff-and-risk
```

## What the example proves

- The consumer workflow runs deterministic local diff analysis over files the
  consumer repository provides.
- `outputs/report.json` contains the full machine-readable report.
- `outputs/report.md` contains the human-readable review report.
- `outputs/summary.json` contains the same object as `report.json["summary"]`.
- `outputs/report.sarif` can be uploaded or inspected by consumers that want
  SARIF output.
- The threshold step is a local consumer policy choice, not a built-in security
  verdict.

## Boundaries

- The example does not use production PyPI.
- Production PyPI publishing remains intentionally deferred.
- The example does not require secrets.
- Default `sbom-diff-risk` runs do not perform hidden network access.
- Downloading the GitHub Release wheel is explicit network access by the
  workflow.
- `sbom-diff-risk` is not a CVE scanner.
- The output is not a dependency safety oracle.
- Replace all placeholder input paths with non-private paths from the consumer
  repository.

For compact summary consumption patterns, see
[summary-json-ci-cookbook.md](summary-json-ci-cookbook.md).
