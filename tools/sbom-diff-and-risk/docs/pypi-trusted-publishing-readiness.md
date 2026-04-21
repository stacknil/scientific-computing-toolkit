# PyPI Trusted Publishing readiness

This page is a readiness checklist, not an enabled publish flow.

`sbom-diff-and-risk` is not enabling PyPI Trusted Publishing in this PR because the repository is not yet cleanly ready for a narrow, durable publish workflow. The goal here is to make the distribution-authentication story explicit without wiring a half-configured upload path.

Official references:

- [PyPI Trusted Publishing overview](https://docs.pypi.org/trusted-publishers/)
- [Creating a PyPI project with a Trusted Publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
- [Publishing with a Trusted Publisher](https://docs.pypi.org/trusted-publishers/using-a-publisher/)

## Current status

Today, the repository is ready for:

- local package builds with `python -m build`
- package metadata validation with `python -m twine check`
- GitHub workflow artifact attestation for built distributions
- GitHub Release asset publication and release-verification guidance

Today, the repository is not yet ready for enabling PyPI Trusted Publishing by default.

## Why Trusted Publishing is not enabled yet

The main blockers are packaging and release-readiness concerns, not OIDC support itself:

1. The current `README.md` is repository-oriented and contains local absolute file links such as `D:/OneDrive/...`.
   Those links are acceptable for the local Codex app, but they are not a clean PyPI-facing long description.
2. The package does not yet have a dedicated, publish-only GitHub Actions workflow with the minimal Trusted Publishing permissions and a clear separation between build and upload responsibilities.
3. PyPI-side configuration has not been established yet.
   That includes either:
   - a pending publisher for a new `sbom-diff-and-risk` project, or
   - a trusted publisher entry on an existing PyPI project
4. The first PyPI release version and release sequencing have not been pinned down yet.
   The repository currently builds version `0.3.0`, while the repository work is now in the `v0.4` release-hardening theme.

Because of those gaps, enabling a publish job now would create a fragile or misleading path.

## Local checks that already pass

These checks are useful, but they are not sufficient to justify enabling Trusted Publishing:

```bash
cd tools/sbom-diff-and-risk
python -m build
$files = Get-ChildItem dist | ForEach-Object { $_.FullName }
python -m twine check $files
```

What those checks prove:

- the package can be built locally
- the built distributions pass Twine's metadata/rendering validation

What they do not prove:

- that the README and linked documentation are appropriate for PyPI users
- that the repository and PyPI project are wired together for OIDC publishing
- that GitHub-side and PyPI-side Trusted Publishing configuration matches exactly

## Readiness checklist before enabling Trusted Publishing

Complete these items first:

### 1. Make the package description PyPI-facing

- Replace local absolute-path links in `tools/sbom-diff-and-risk/README.md` with links that render sensibly on PyPI.
- If the repository still needs desktop-specific local links, create a separate PyPI-oriented readme or another long-description strategy for packaging.
- Re-run:

```bash
cd tools/sbom-diff-and-risk
python -m build
$files = Get-ChildItem dist | ForEach-Object { $_.FullName }
python -m twine check $files
```

### 2. Decide the first PyPI-published version and release sequence

- Decide whether the first PyPI upload should be `0.3.0`, `0.4.0`, or a later release.
- Ensure the tag, package version, release notes, GitHub Release assets, and PyPI upload plan all refer to the same version.

### 3. Configure PyPI-side Trusted Publishing

PyPI Trusted Publishing should use OIDC and short-lived credentials instead of a long-lived API token.

On PyPI, configure either:

- a pending publisher for a new project, or
- a trusted publisher for an existing project

Record the exact values that must match GitHub:

- owner: `stacknil`
- repository: `scientific-computing-toolkit`
- workflow file path that will publish
- optional environment name, if the workflow uses one

### 4. Add a dedicated publish workflow only after the above is true

When the repository is actually ready, add a dedicated publish workflow that:

- uploads only from previously built distribution files
- uses explicit minimal permissions
- uses OIDC via `id-token: write`
- uses the official PyPA publish action
- does not rebuild the package in the upload step

The intended shape is:

- one build job that produces the wheel and sdist
- one publish job that downloads those artifacts and uploads them to PyPI

### 5. Validate on TestPyPI or an equivalent dry-run path first

Before production PyPI adoption:

- validate the workflow against TestPyPI or an equivalent pre-production publisher setup
- confirm the GitHub-side workflow identity exactly matches the PyPI-side trusted publisher configuration
- confirm the upload uses OIDC and no long-lived PyPI token secret

## What the future Trusted Publishing PR should contain

Once the checklist above is complete, the next publishing PR should be narrow and production-oriented:

- add a dedicated publish workflow
- document the exact PyPI-side trusted publisher configuration
- document the exact GitHub trigger path for publishing
- preserve the current GitHub workflow artifact attestation and release-asset provenance story
- explain how PyPI distribution provenance relates to, but does not replace, GitHub artifact and release verification

## Important boundary

This repository already has:

- tool provenance guidance for GitHub workflow artifacts
- release provenance guidance for GitHub Releases and release assets

It does not yet have:

- enabled PyPI Trusted Publishing
- documented TestPyPI validation
- a production-ready PyPI upload workflow
