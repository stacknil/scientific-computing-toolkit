# PyPI Trusted Publishing readiness

This page documents the PR 4 TestPyPI / Trusted Publishing dry-run path for `sbom-diff-and-risk`.

The repository now has a safe GitHub Actions path that always builds and checks the Python distributions, and can publish those already-checked distributions to TestPyPI only when a maintainer explicitly enables the manual upload input. It does not publish to production PyPI.

Official references:

- [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/)
- [Adding a Trusted Publisher to an existing PyPI project](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
- [Creating a PyPI project with a Trusted Publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
- [Publishing with a Trusted Publisher](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
- [Configuring OpenID Connect in PyPI](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-pypi)
- [PyPA gh-action-pypi-publish](https://github.com/pypa/gh-action-pypi-publish)

## PR 4 decision

Use a TestPyPI-first readiness workflow, but do not claim that a TestPyPI dry-run is complete until the external TestPyPI publisher is configured and a maintainer runs the manual upload.

Current outcome for this PR:

- **Trusted Publishing readiness only** by default
- **TestPyPI dry-run blocked by external configuration** until TestPyPI has the matching pending publisher or trusted publisher
- **No production PyPI publishing**

The workflow file is `.github/workflows/sbom-diff-and-risk-testpypi.yml`.

It has two separate jobs:

- `build-and-check` builds the wheel and source distribution, runs `twine check`, and uploads the checked files as a workflow artifact
- `publish-testpypi` downloads that artifact and publishes to TestPyPI with OIDC only when `workflow_dispatch` input `publish_to_testpypi` is set to `true`

The upload job does not rebuild the package.

## Current package and project status

As checked on April 25, 2026:

- `https://pypi.org/pypi/sbom-diff-and-risk/json` returned `404`
- `https://test.pypi.org/pypi/sbom-diff-and-risk/json` returned `404`

That means neither the production PyPI project nor the TestPyPI project currently exists under `sbom-diff-and-risk`.

Because the TestPyPI project does not exist yet, the first upload must use a **pending publisher** on TestPyPI, unless a maintainer creates the TestPyPI project some other way first. For production PyPI, defer all configuration and upload work to PR 5.

## Workflow identity

Configure the TestPyPI publisher to match this GitHub workflow identity exactly:

| Field | Value |
| --- | --- |
| Package/project name | `sbom-diff-and-risk` |
| GitHub owner | `stacknil` |
| GitHub repository | `scientific-computing-toolkit` |
| Workflow file in repository | `.github/workflows/sbom-diff-and-risk-testpypi.yml` |
| Trusted Publisher workflow name field | `sbom-diff-and-risk-testpypi.yml` |
| GitHub environment | `testpypi` |

The workflow uses `environment: testpypi` for the upload job, so the TestPyPI publisher must also include `testpypi` as the environment name. If the publisher is configured without an environment, the OIDC identity will not match this workflow.

## What this PR validates

Locally and in GitHub Actions, this PR validates:

- package metadata still points at `PYPI_DESCRIPTION.md` as the PyPI-facing long description
- the package can build a wheel and source distribution
- the built distributions pass `twine check`
- the GitHub workflow separates build/check from upload
- the TestPyPI upload job uses OIDC-compatible permissions with `id-token: write`
- no PyPI token secret is required or documented
- production PyPI upload is absent

This PR does not validate:

- that TestPyPI has the pending publisher configured
- that TestPyPI accepts the first upload
- that production PyPI has a project, pending publisher, or trusted publisher
- that production PyPI publishing should happen for version `0.4.1`

## TestPyPI setup required before upload

Do these steps only after this workflow is merged.

1. In GitHub, create or verify the repository environment named `testpypi`.
2. In TestPyPI, create a pending publisher for the new `sbom-diff-and-risk` project.
3. Use the identity values from [Workflow identity](#workflow-identity).
4. Do not add a PyPI API token or GitHub secret for publishing.
5. Run the workflow manually and set `publish_to_testpypi` to `true`.

If the pending publisher is missing or any identity field differs, the upload job should fail instead of silently falling back to a token or pretending the dry-run succeeded.

## Local validation

From `tools/sbom-diff-and-risk`:

```powershell
python -m pip install --upgrade build twine
python -m build
$files = (Get-ChildItem dist -File).FullName
python -m twine check $files
```

What this proves:

- the local package can be built
- the built distributions have valid metadata and long-description rendering according to Twine

What this does not prove:

- the GitHub OIDC identity matches TestPyPI
- the TestPyPI pending publisher exists
- the upload job can mint a TestPyPI publishing token

## GitHub Actions validation

Without uploading anything:

1. Open **Actions**.
2. Run **sbom-diff-and-risk-testpypi** with `publish_to_testpypi` left as `false`.
3. Confirm `build-and-check` succeeds.
4. Confirm the run uploads `sbom-diff-and-risk-testpypi-dist`.
5. Confirm `publish-testpypi` is skipped.

With TestPyPI pending publisher configured:

1. Open **Actions**.
2. Run **sbom-diff-and-risk-testpypi** with `publish_to_testpypi` set to `true`.
3. Confirm `build-and-check` succeeds before upload.
4. Confirm `publish-testpypi` downloads `sbom-diff-and-risk-testpypi-dist`.
5. Confirm `publish-testpypi` uses OIDC and publishes to `https://test.pypi.org/legacy/`.
6. Open `https://test.pypi.org/project/sbom-diff-and-risk/` and confirm the uploaded version appears.

Only after those steps pass can maintainers describe the result as **TestPyPI dry-run completed**.

## Production PyPI boundary

Production PyPI remains intentionally out of scope for PR 4.

Do not add a production PyPI publish job here. Do not configure production PyPI Trusted Publishing as part of this PR unless it is documented as future preparation only and no upload path is enabled.

PR 5 should decide:

- the first production PyPI version
- whether to use a pending publisher or an existing-project trusted publisher
- the production workflow file identity
- the GitHub environment name for production, if any
- how PyPI distribution provenance should be documented alongside GitHub artifact and release verification

## Current decision

PR 4 stops at a clean readiness state unless a maintainer performs the explicit TestPyPI setup and manual upload after merge.

Until that happens, the correct status is **Trusted Publishing readiness only; TestPyPI upload blocked by external configuration**.
