# GitHub Actions policy consumer demo

This page documents the minimal GitHub Actions consumer workflow for
`sbom-diff-risk`. The workflow runs the tool with a local policy, uploads
`outputs/policy.json`, and then passes or fails based on the tool's policy exit
code.

It is documentation only. It is not a workflow for this repository, and it does
not change the `sbom-diff-risk` CLI or publishing model.

Production PyPI publishing is intentionally deferred, so consumers should not
install `sbom-diff-and-risk` from production PyPI. Use a GitHub Release asset or
a local checkout instead.

## Minimal policy workflow

Replace the placeholder input and policy paths with files from the consumer
repository. The same workflow is checked in as
[../examples/github-actions-policy-consumer.yml](../examples/github-actions-policy-consumer.yml)
for copying into consumer repositories.

```yaml
name: Dependency policy review

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  dependency-policy:
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
          gh release download v1.0-rc.1 \
            --repo stacknil/scientific-computing-toolkit \
            --pattern "sbom_diff_and_risk-1.0rc1-py3-none-any.whl" \
            --dir .tooling/sbom-diff-risk

      - name: Install sbom-diff-risk
        run: |
          python -m pip install \
            .tooling/sbom-diff-risk/sbom_diff_and_risk-1.0rc1-py3-none-any.whl

      - name: Run dependency policy
        id: compare
        shell: bash
        run: |
          mkdir -p outputs
          set +e
          sbom-diff-risk compare \
            --before path/to/before-sbom.json \
            --after path/to/after-sbom.json \
            --format auto \
            --policy path/to/policy.yml \
            --policy-json outputs/policy.json
          status=$?
          set -e
          echo "exit_code=$status" >> "$GITHUB_OUTPUT"

      - name: Upload policy JSON
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: dependency-policy-json
          path: outputs/policy.json
          if-no-files-found: error

      - name: Pass or fail based on local policy
        run: exit "${{ steps.compare.outputs.exit_code }}"
```

The upload step runs before the final pass/fail step, so reviewers can inspect
`outputs/policy.json` even when the local policy blocks the job. The final step
uses the tool's own exit code:

- `0`: report written and local policy passed
- `1`: report written and local policy produced blocking findings
- `2`: usage, parse, or runtime error before a successful policy decision

## Local checkout variant

If the consumer repository vendors or checks out this toolkit repository, install
from that local checkout instead of downloading a release wheel:

```yaml
- name: Install sbom-diff-risk from local checkout
  run: |
    python -m pip install \
      path/to/scientific-computing-toolkit/tools/sbom-diff-and-risk
```

## What the demo proves

- The consumer workflow runs deterministic local policy analysis over files the
  consumer repository provides.
- `outputs/policy.json` contains policy status, blocking/warning/suppressed
  findings, and rule metadata.
- CI pass/fail is based on the `sbom-diff-risk compare` exit code.
- The workflow does not invent a second policy decision after the tool runs.

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

For policy sidecar consumption patterns, see
[policy-decision-ci-cookbook.md](policy-decision-ci-cookbook.md).
