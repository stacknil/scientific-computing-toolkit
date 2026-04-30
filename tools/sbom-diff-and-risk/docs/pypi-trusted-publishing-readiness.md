# PyPI Trusted Publishing readiness

This page documents the PR 4 TestPyPI / Trusted Publishing dry-run path for `sbom-diff-and-risk`.

The PR 5 production PyPI decision gate is documented separately in [pypi-production-publishing-decision.md](pypi-production-publishing-decision.md).

The repository now has a safe GitHub Actions path that always builds and checks the Python distributions, and can publish those already-checked distributions to TestPyPI only when a maintainer explicitly enables the manual upload input. It does not publish to production PyPI.

Official references:

- [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/)
- [Adding a Trusted Publisher to an existing PyPI project](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
- [Creating a PyPI project with a Trusted Publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
- [Publishing with a Trusted Publisher](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
- [Configuring OpenID Connect in PyPI](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-pypi)
- [PyPA gh-action-pypi-publish](https://github.com/pypa/gh-action-pypi-publish)

## PR 4 decision

Use a TestPyPI-first readiness workflow, but do not treat TestPyPI success as automatic production PyPI readiness.

Current outcome for this PR:

- **Trusted Publishing readiness and TestPyPI dry-run completed** after the external TestPyPI publisher was configured and a maintainer manually enabled upload
- **No production PyPI publishing**
- **Production PyPI deferred** to the decision gate in [pypi-production-publishing-decision.md](pypi-production-publishing-decision.md)

The workflow file is `.github/workflows/sbom-diff-and-risk-testpypi.yml`.

It has two separate jobs:

- `build-and-check` builds the wheel and source distribution, runs `twine check`, and uploads the checked files as a workflow artifact
- `publish-testpypi` downloads that artifact and publishes to TestPyPI with OIDC only when `workflow_dispatch` input `publish_to_testpypi` is set to `true`

The upload job does not rebuild the package.

## Current package and project status

As checked on April 26, 2026:

- `https://pypi.org/pypi/sbom-diff-and-risk/json` returned `404`
- `https://test.pypi.org/pypi/sbom-diff-and-risk/json` returned `200`
- TestPyPI reports `sbom-diff-and-risk` version `0.4.1`

That means the production PyPI project is not currently visible under `sbom-diff-and-risk`, while the TestPyPI dry-run project exists. For production PyPI, use the PR 5 decision gate before adding any production workflow or publisher configuration.

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

- that production PyPI has a project, pending publisher, or trusted publisher
- that production PyPI publishing should happen for version `0.4.1`
- that a TestPyPI upload is sufficient proof of production PyPI readiness

## TestPyPI setup used for upload

The completed TestPyPI dry-run required these external steps. Use them again only if the TestPyPI publisher must be recreated.

1. In GitHub, create or verify the repository environment named `testpypi`.
2. In TestPyPI, create a pending publisher for the new `sbom-diff-and-risk` project.
3. Use the identity values from [Workflow identity](#workflow-identity).
4. Do not add a PyPI API token or GitHub secret for publishing.
5. Run the workflow manually and set `publish_to_testpypi` to `true`.

If the pending publisher or trusted publisher is missing, or any identity field differs, the upload job should fail instead of silently falling back to a token or pretending the dry-run succeeded.

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

After those steps pass, maintainers can describe the result as **TestPyPI dry-run completed**.

## Production PyPI boundary

Production PyPI remains intentionally separate from the TestPyPI dry-run.

Do not add a production PyPI publish job to the TestPyPI workflow. Do not configure production PyPI Trusted Publishing from the TestPyPI readiness process.

PR 5 decides:

- the first production PyPI version
- whether to use a pending publisher or an existing-project trusted publisher
- the production workflow file identity
- the GitHub environment name for production, if any
- how PyPI distribution provenance should be documented alongside GitHub artifact and release verification

See [pypi-production-publishing-decision.md](pypi-production-publishing-decision.md) for the current production gate.

## Current decision

PR 4 established the TestPyPI readiness workflow and the manual dry-run path. After the external TestPyPI publisher was configured and a maintainer ran the manual upload, the dry-run completed for version `0.4.1`.

Production PyPI remains deferred behind the PR 5 gate.
