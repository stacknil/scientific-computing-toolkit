# Self-provenance and artifact attestations

`sbom-diff-and-risk` analyzes third-party dependency changes, but consumers should also be able to verify where the tool itself came from. This repository generates GitHub artifact attestations for the packaged build outputs produced by the `sbom-diff-and-risk-ci` workflow.

## What is attested in this repository

The attested subjects are the exact Python distributables built from `tools/sbom-diff-and-risk` via `python -m build`:

- the wheel: `dist/sbom_diff_and_risk-<version>-py3-none-any.whl`
- the source distribution: `dist/sbom_diff_and_risk-<version>.tar.gz`

Those two files are uploaded together as the workflow artifact named `sbom-diff-and-risk-dist`. The attestation applies to the built files themselves, not just to the artifact bundle name shown in the Actions UI.

This repository does not currently publish PyPI Trusted Publishing provenance or immutable GitHub release attestations as part of this workflow. The current self-provenance coverage is limited to the workflow-produced wheel and source distribution files.

## Workflow and permissions

The attestation is generated in `.github/workflows/sbom-diff-and-risk-ci.yml` by the `build-and-attest` job in the `sbom-diff-and-risk-ci` workflow.

That job runs only for trusted non-PR events in this repository:

- `push`
- `workflow_dispatch`

Pull request runs still execute the `test` job, but they do not publish artifact attestations.

The `build-and-attest` job uses the minimum explicit permissions required for GitHub-hosted build provenance:

- `contents: read` for repository checkout
- `id-token: write` for GitHub's signing identity
- `attestations: write` to publish the attestation

## Where provenance evidence appears in GitHub

After a successful non-PR run of `sbom-diff-and-risk-ci`, consumers can find the evidence in two useful places:

1. On the workflow run page:
   - the uploaded artifact appears as `sbom-diff-and-risk-dist`
   - this is the run consumers should use to confirm the workflow name, job name, and downloaded artifact bundle before verification
2. In the repository-wide attestations view:
   - open **Actions**
   - in the left sidebar, under **Management**, open **Attestations**
   - search for `sbom_diff_and_risk-` or filter by recent creation date

On the **Attestations** page, the relevant subjects are the wheel and sdist filenames, not the workflow artifact bundle name. On the workflow run page, the main visible bundle name is still `sbom-diff-and-risk-dist`.

## Manual verification for one workflow run

Use this path after a merge to the default branch or an intentional `workflow_dispatch` run.

1. Open the repository's **Actions** tab.
2. Open a successful `sbom-diff-and-risk-ci` run triggered by `push` or `workflow_dispatch`.
3. Confirm that the `build-and-attest` job ran successfully.
4. Download the `sbom-diff-and-risk-dist` artifact from that run.
5. Confirm the downloaded archive contains exactly the expected build outputs for that version:
   - `sbom_diff_and_risk-<version>-py3-none-any.whl`
   - `sbom_diff_and_risk-<version>.tar.gz`
6. Verify one of the files with the GitHub CLI:

```bash
gh attestation verify path/to/sbom_diff_and_risk-<version>-py3-none-any.whl \
  --repo OWNER/scientific-computing-toolkit \
  --signer-workflow OWNER/scientific-computing-toolkit/.github/workflows/sbom-diff-and-risk-ci.yml
```

You can verify the source distribution the same way:

```bash
gh attestation verify path/to/sbom_diff_and_risk-<version>.tar.gz \
  --repo OWNER/scientific-computing-toolkit \
  --signer-workflow OWNER/scientific-computing-toolkit/.github/workflows/sbom-diff-and-risk-ci.yml
```

If you want more inspection detail during review, ask the CLI for structured output:

```bash
gh attestation verify path/to/sbom_diff_and_risk-<version>-py3-none-any.whl \
  --repo OWNER/scientific-computing-toolkit \
  --signer-workflow OWNER/scientific-computing-toolkit/.github/workflows/sbom-diff-and-risk-ci.yml \
  --format json
```

A successful verification confirms that:

- the downloaded file matches an attested subject
- the attestation was linked to `OWNER/scientific-computing-toolkit`
- the attestation was signed by `.github/workflows/sbom-diff-and-risk-ci.yml`

## Release-consumer note

If these same wheel or source distribution bytes are later attached to a GitHub release, consumers should verify the downloaded release asset file itself with the same `gh attestation verify` flow. In the current setup, the provenance source of truth is still the workflow-produced build artifact and its attestation, not a separate release-attestation workflow.

## How this complements the tool's own analysis

Self-provenance and dependency analysis solve different problems:

- artifact attestations help consumers verify where `sbom-diff-and-risk` itself was built
- `sbom-diff-and-risk` helps users review and gate third-party dependency changes in their own projects

These attestations strengthen trust in the tool's own distributable artifacts, but they do not replace the tool's analysis of external SBOM inputs, policy decisions, or trust-signal reporting for third-party packages.
