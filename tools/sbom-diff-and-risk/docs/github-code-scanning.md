# GitHub Code Scanning Integration

`sbom-diff-and-risk` can export a GitHub-compatible SARIF 2.1.0 subset and upload it with `github/codeql-action/upload-sarif`.

This project remains local, deterministic, and conservative by default. The GitHub integration is only a transport path for selected high-signal findings.

## What the example workflow does

The example workflow in `.github/workflows/sbom-diff-and-risk-code-scanning.yml`:

- checks out the repository
- installs Python and the local tool
- runs `sbom-diff-risk compare ... --out-sarif`
- uploads the generated SARIF file as the workflow artifact `sbom-diff-and-risk-sarif`
- uploads the generated SARIF file with `github/codeql-action/upload-sarif`

The example intentionally uses local example inputs and does not depend on secrets or network enrichment.
It also keeps the compare step at exit code `0` for readability. If you intentionally enforce blocking policy rules during CI and still want SARIF uploaded, add `continue-on-error: true` to the compare step and gate the upload step with `if: always()`.

## Required permissions

At minimum, the upload job needs:

- `security-events: write`

For private repositories, GitHub also documents `contents: read`. If your workflow needs to inspect other workflow artifacts, `actions: read` may also be required.

## SARIF guardrails

GitHub documents both SARIF file-size limits and object-count limits for code scanning uploads. In particular:

- gzip-compressed SARIF uploads over 10 MB are rejected
- a run may contain up to 25,000 results, but GitHub only includes the top 5,000 results for display, prioritized by severity

To keep uploads reviewable and GitHub-oriented, `sbom-diff-risk` applies a deterministic SARIF result cap of 5,000 results. When truncation happens:

- results are prioritized as `error`, then `warning`, then `note`
- direct mapped findings are kept ahead of policy-only checks
- stable tie-breakers are applied by rule ID and component identity
- truncation is recorded in SARIF run metadata
- the CLI emits a warning to stderr

This does not guarantee every huge SARIF file will fit under GitHub's documented upload-size limits, but it prevents silent overproduction of low-priority results.

## When to use a SARIF category

Set a SARIF category when you upload more than one analysis for the same commit and tool. Common cases include:

- one upload per manifest type
- one upload per monorepo slice
- separate policy modes or rule packs

If you upload multiple SARIF files for the same tool and commit without distinct categories, later uploads replace earlier ones. In GitHub Actions, set the `category:` input on `github/codeql-action/upload-sarif`. Outside Actions, use `runAutomationDetails.id` in the SARIF file.

## Manual verification for one workflow run

After merging a change that touches `tools/sbom-diff-and-risk` or the workflow file itself:

1. Open the repository's **Actions** tab.
2. Open a successful `sbom-diff-and-risk-code-scanning` run for the pull request, or trigger it manually with `workflow_dispatch`.
   - the visible run name starts with `sbom-diff-and-risk code scanning / <event> / <ref>`
3. Confirm that the `upload-sarif` job completed successfully.
4. Download the `sbom-diff-and-risk-sarif` artifact and confirm it contains `report.sarif`.
5. Open the repository's **Security** tab, then **Code scanning**.
6. Confirm the uploaded analysis appears under the category `sbom-diff-risk/example`.

## What this integration does not cover

- It does not add CVE lookup or advisory enrichment.
- It does not make exact line mappings for manifests that do not expose stable locations.
- It does not automatically handle every possible multi-workflow or monorepo routing strategy.
- It does not package `sbom-diff-risk` as a GitHub Marketplace Action.
- It does not bypass GitHub's documented SARIF ingestion limits.
