# Policy decision examples

These examples show four reviewer-facing policy decision outcomes for CI
consumers. They are small interpretation fixtures, not generated report
artifacts.

Use them when wiring a job summary, dashboard, or review note that needs to
separate local policy status from dependency safety claims.

| Example | Meaning |
| --- | --- |
| [pass.json](pass.json) | Local policy ran and produced no blocking or warning findings. |
| [warn.json](warn.json) | Local policy ran and produced warning findings only. |
| [fail.json](fail.json) | Local policy ran and produced one or more blocking findings. |
| [needs-review.json](needs-review.json) | A consumer cannot make a pass, warn, or fail statement from the available policy surface and should route the change to human review. |

`pass`, `warn`, and `fail` mirror the supported `summary.policy.status` values
emitted by `sbom-diff-risk`. `needs-review` is a consumer interpretation, not a
runtime `summary.policy.status` value.

## Boundaries

- These examples do not resolve CVEs.
- These examples do not prove that a dependency is safe or unsafe.
- These examples do not add network behavior.
- These examples do not imply production PyPI publishing.
