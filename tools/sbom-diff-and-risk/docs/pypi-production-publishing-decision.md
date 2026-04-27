# Production PyPI publishing decision

This page records the PR 5 production PyPI gate for `sbom-diff-and-risk`.

## PR 5 decision

Production PyPI publishing is **deferred, but conditionally allowed after the prerequisites below are complete**. In short: production PyPI is currently deferred.

PR 5 does not add an enabled production publishing workflow and does not publish to production PyPI. The successful TestPyPI Trusted Publishing dry-run proves that the package metadata can render on TestPyPI and that the TestPyPI OIDC path can work, but it is not automatic proof that production PyPI publishing is ready.

The production gate is intentionally conservative because:

- the production PyPI project does not currently exist under the intended name
- the package metadata still declares version `0.4.1`
- the first production upload should be a deliberate release version, not an old dry-run version
- the production PyPI pending publisher or trusted publisher has not been configured
- the production GitHub environment has not yet been confirmed

## Package name and external state

The production package name should be `sbom-diff-and-risk`.

As checked on April 26, 2026:

- `https://pypi.org/pypi/sbom-diff-and-risk/json` returned `404`
- `https://test.pypi.org/pypi/sbom-diff-and-risk/json` returned `200`
- TestPyPI reports `sbom-diff-and-risk` version `0.4.1`

This means the intended production project name is not currently visible on production PyPI, while the TestPyPI dry-run project exists. Treat the production name as available for this decision, but re-check immediately before configuration because PyPI can reserve, prohibit, or receive new projects at any time. The first production upload should use a production PyPI pending publisher unless the project is created by a maintainer before the publishing workflow is enabled.

## First production version

Do not publish `0.4.1` to production PyPI casually.

The first production PyPI version should be `0.5.0` only if v0.5 is approved as the first production package release. Otherwise, defer to a later GitHub release tag.

For the first production upload:

- the GitHub tag should be `v<version>`
- `tools/sbom-diff-and-risk/pyproject.toml` should declare the matching `<version>`
- the GitHub release and release assets should be available for the same tag
- the production PyPI workflow should run from the matching tag ref
- the production PyPI upload should use the checked distributions from that workflow run

## Production publisher identity

Configure the production PyPI publisher to match this identity exactly:

| Field | Value |
| --- | --- |
| PyPI project name | `sbom-diff-and-risk` |
| GitHub owner | `stacknil` |
| GitHub repository | `scientific-computing-toolkit` |
| Future workflow file path | `.github/workflows/sbom-diff-and-risk-pypi.yml` |
| Trusted Publisher workflow name field | `sbom-diff-and-risk-pypi.yml` |
| GitHub environment | `pypi` |

If production PyPI still has no project for this name, configure a pending publisher for a new project. If the project exists by the time production publishing is implemented, add the trusted publisher to the existing project instead.

Do not create or document a PyPI API token for this workflow. Production upload should use Trusted Publishing / OIDC only.

PyPI-side setup should use these paths:

- for a new production project, create a pending publisher on production PyPI for project `sbom-diff-and-risk` with the owner, repository, workflow, and environment values above
- for an existing production project, open that project on production PyPI and add a trusted publisher with the same owner, repository, workflow, and environment values
- leave the environment field as `pypi`; if the PyPI publisher omits the environment, it will not match the future publish job identity
- do not add a PyPI API token, PyPI password, or GitHub publishing secret as a fallback

## Prerequisites before enabling production publishing

Before adding `.github/workflows/sbom-diff-and-risk-pypi.yml`, maintainers should complete all of these checks:

- confirm the intended production package name still resolves as expected on production PyPI
- choose the first production version, likely `0.5.0` or a later release tag
- update `pyproject.toml` to that version
- create or verify the matching GitHub tag and release assets
- create the GitHub environment named `pypi`
- configure required reviewers or equivalent repository controls on the `pypi` environment
- create the PyPI pending publisher or existing-project trusted publisher with the exact identity above
- run the future workflow in no-publish mode first and confirm the publish job is skipped
- verify the checked distributions with `python -m twine check dist/*`

## Future workflow shape

PR 5 intentionally documents the future workflow shape without enabling it.

The future production workflow should:

- use `workflow_dispatch` only for the initial production publishing process
- require an explicit boolean input such as `publish_to_pypi`
- require a confirmation string such as `publish sbom-diff-and-risk to production PyPI`
- require an expected version input and assert that it matches `pyproject.toml`
- require the run ref to be a version tag such as `refs/tags/v0.5.0`
- build the wheel and source distribution once
- run `python -m twine check dist/*`
- upload the checked distributions as a workflow artifact
- publish only from a separate gated job that downloads that artifact
- use the GitHub environment `pypi` on the publish job
- grant `id-token: write` only to the publish job
- avoid production upload on ordinary push or pull request events

The publish step should use `pypa/gh-action-pypi-publish@release/v1` without a `repository-url` override so it targets production PyPI.

## Provenance boundaries

Production PyPI Trusted Publishing provenance, GitHub workflow artifact attestations, and GitHub Release asset verification answer related but different questions.

PyPI Trusted Publishing provenance answers:

- was this distribution uploaded to this PyPI project through the configured GitHub publisher identity?
- did the upload use the expected owner, repository, workflow file, and environment?

GitHub workflow artifact attestations answer:

- were these local wheel or source distribution bytes built by `.github/workflows/sbom-diff-and-risk-ci.yml`?
- do the downloaded files match the attested workflow subjects?

GitHub Release verification answers:

- does the GitHub Release record have a valid release attestation?
- does a downloaded release asset match an attested asset from an immutable release?

Do not treat one provenance surface as a replacement for the others. A PyPI package can have valid Trusted Publishing provenance without proving that it is byte-for-byte identical to a GitHub Release asset. Consumers who need cross-surface verification should compare hashes between a PyPI download and the corresponding GitHub Release asset, then use the GitHub verification flows documented in `self-provenance.md` and `release-provenance.md`.

## Consumer guidance after a future production release

After production publishing is enabled in a later PR, consumers should:

- install only the intended project name, `sbom-diff-and-risk`
- check that the PyPI version matches the expected GitHub release tag
- inspect PyPI's Trusted Publishing provenance for the expected publisher identity
- use GitHub artifact attestation verification for workflow-built files when downloading from GitHub
- use GitHub Release verification for immutable release assets when relying on GitHub Releases
- continue to treat TestPyPI as a dry-run environment only

## PR 5 local verification

PR 5 should remain a documentation and gate-design change. Local verification is still required to prove the existing package surface did not regress:

```powershell
python -m build
python -m twine check dist/*
python -m pytest
git diff --check
```
