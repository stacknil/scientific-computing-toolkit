# Self-provenance and artifact attestations

`sbom-diff-and-risk` analyzes third-party dependency changes, but consumers should also be able to verify where the tool itself came from. This repository generates GitHub artifact attestations for the packaged build outputs produced by the `sbom-diff-and-risk-ci` workflow.

This page is only about verifying the `sbom-diff-and-risk` tool's own build artifacts. If you want the top-level decision guide, start with [verification.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/verification.md). If you want to analyze third-party dependency provenance with the CLI, go back to the README's dependency provenance sections instead of this page.

## What is attested in this repository

The attested subjects are the exact Python distributables built from `tools/sbom-diff-and-risk` via `python -m build`:

- the wheel: `dist/sbom_diff_and_risk-<version>-py3-none-any.whl`
- the source distribution: `dist/sbom_diff_and_risk-<version>.tar.gz`

Those two files are uploaded together as the workflow artifact named `sbom-diff-and-risk-dist`. The attestation applies to the built files themselves, not just to the artifact bundle name shown in the Actions UI.

On version tags matching `v*`, the same workflow also publishes those exact wheel and sdist files as GitHub Release assets for the matching tag. The workflow-artifact attestation story remains the build-provenance source of truth for the files themselves; release verification is an additional GitHub-hosted surface layered on top of those same bytes.

This repository does not currently publish production PyPI Trusted Publishing provenance. The separate TestPyPI readiness workflow is a pre-production validation path and is documented in [pypi-trusted-publishing-readiness.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/pypi-trusted-publishing-readiness.md). The production PyPI decision gate is documented in [pypi-production-publishing-decision.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/pypi-production-publishing-decision.md). Release verification is separate from workflow-artifact attestations and depends on GitHub immutable releases being enabled for the repository. When immutable releases are enabled, GitHub automatically generates a release attestation covering the published release record and its attached assets.

## Workflow and permissions

The attestation is generated in `.github/workflows/sbom-diff-and-risk-ci.yml` by the `build-and-attest` job in the `sbom-diff-and-risk-ci` workflow.

That job runs only for trusted non-PR events in this repository:

- `push`
- `workflow_dispatch`

Pull request runs still execute the `test` job, but they do not publish artifact attestations.

On version tags matching `v*`, the same workflow also runs `publish-release-assets`, which downloads the already-built `sbom-diff-and-risk-dist` artifact from the workflow run and uploads those same files to the GitHub Release for that tag.

The `build-and-attest` job uses the minimum explicit permissions required for GitHub-hosted build provenance:

- `contents: read` for repository checkout
- `id-token: write` for GitHub's signing identity
- `attestations: write` to publish the attestation

Regular branch pushes remain path-filtered to the `sbom-diff-and-risk` workflow file and tool directory. The workflow also accepts version tags matching `v*`, which gives the repository a minimal release-oriented build path that now covers workflow artifact attestation plus GitHub Release asset publication, without adding production PyPI publishing.

## Where provenance evidence appears in GitHub

After a successful non-PR run of `sbom-diff-and-risk-ci`, consumers can find the evidence in two useful places:

1. On the workflow run page:
   - the run name starts with `sbom-diff-and-risk ci / <event> / <ref>`
   - the uploaded artifact appears as `sbom-diff-and-risk-dist`
   - this is the run consumers should use to confirm the workflow name, job name, and downloaded artifact bundle before verification
2. In the repository-wide attestations view:
   - open **Actions**
   - in the left sidebar, under **Management**, open **Attestations**
   - search for `sbom_diff_and_risk-` or filter by recent creation date

On the **Attestations** page, the relevant subjects are the wheel and sdist filenames, not the workflow artifact bundle name. On the workflow run page, the main visible bundle name is still `sbom-diff-and-risk-dist`.

## Manual verification for one workflow run

Use this path after a merge to the default branch, a version-tag push such as `v0.4.0`, or an intentional `workflow_dispatch` run.

1. Open the repository's **Actions** tab.
2. Open a successful `sbom-diff-and-risk-ci` run triggered by `push` or `workflow_dispatch`.
   - for a release-oriented check, prefer a run whose visible name looks like `sbom-diff-and-risk ci / push / v0.4.0`
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

If these same wheel or source distribution bytes are attached to a GitHub release, consumers now have two related but distinct verification surfaces:

- use `gh attestation verify` when you want to verify the workflow-built file against the workflow artifact attestation
- use `gh release verify` and `gh release verify-asset` when you want to verify the GitHub Release record and a downloaded release asset from an immutable release

These flows complement each other. The workflow-artifact attestation answers "were these bytes built by this workflow?", while immutable release verification answers "does this published release and local release asset exactly match GitHub's release attestation?" See [release-provenance.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/release-provenance.md) for the release-specific consumer flow.

Future production PyPI Trusted Publishing provenance will be a third, separate surface. It will answer whether a PyPI distribution was uploaded through the configured GitHub publisher identity, not whether the file is byte-identical to a GitHub workflow artifact or release asset. See [pypi-production-publishing-decision.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/pypi-production-publishing-decision.md) for that boundary.

## How this complements the tool's own analysis

Self-provenance and dependency analysis solve different problems:

- artifact attestations help consumers verify where `sbom-diff-and-risk` itself was built
- `sbom-diff-and-risk` helps users review and gate third-party dependency changes in their own projects

These attestations strengthen trust in the tool's own distributable artifacts, but they do not replace the tool's analysis of external SBOM inputs, policy decisions, or trust-signal reporting for third-party packages.
