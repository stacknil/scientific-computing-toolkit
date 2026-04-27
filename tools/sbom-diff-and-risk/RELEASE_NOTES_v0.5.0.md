# v0.5.0

Theme: production PyPI decision gate

## Highlights

- Added the production PyPI publishing decision gate for `sbom-diff-and-risk`.
- Confirmed the intended production package name remains `sbom-diff-and-risk`.
- Documented the future production publisher identity and workflow shape without enabling a production upload path.
- Clarified that TestPyPI, GitHub workflow artifact attestations, GitHub Release asset verification, and PyPI Trusted Publishing provenance are separate trust surfaces.

## Distribution status

- TestPyPI dry-run completed; production PyPI intentionally deferred.
- The TestPyPI package exists for version `0.4.1`.
- The `v0.5.0` release is a GitHub Release and package version bump only.
- No production PyPI workflow is added in this release.
- No production PyPI upload is performed by this release.

## Packaging and release alignment

- Bumped the package version to `0.5.0`.
- Synced `sbom_diff_risk.__version__` with the package metadata.
- Updated sample SARIF metadata to report `0.5.0`.
- Updated the README top-level release narrative for the v0.5.0 gate.

## Not in this release

- No analyzer features were added.
- No SARIF behavior changes were added beyond sample metadata version alignment.
- No policy behavior changes were added.
- No hidden network behavior was added.
- No production PyPI publishing path was enabled.

