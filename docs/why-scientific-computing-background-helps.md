# Why Scientific Computing Background Helps

This note explains why scientific-computing habits are useful to this
repository's review style. It is a working-method note, not a domain identity
claim and not a reason to expand repository scope.

## Reproducibility

Scientific-computing work rewards runs that can be repeated from explicit
inputs. That habit maps directly to this repository's strongest reviewer
surface:

- checked-in fixtures instead of private source material
- deterministic commands that can be rerun locally
- generated artifacts that can be compared against known outputs
- documentation that separates what was run from what was inferred

For `sbom-diff-and-risk`, this means example reports, policy sidecars, SARIF
samples, and release evidence should stay reproducible from public-safe inputs.
The point is not to claim broad expertise; it is to make review evidence easier
to repeat.

## Data Pipeline

Scientific-computing workflows often make the pipeline visible: ingest,
normalize, transform, summarize, and report. That pattern helps keep this
repository inspectable.

For the flagship SBOM tool, the useful pipeline boundary is:

- parse SBOMs or dependency manifests
- normalize package records into a stable internal shape
- compute local diffs and heuristic findings
- apply explicit local policy when requested
- emit machine-readable and human-readable review artifacts

Each stage should have a clear input and output. When a later report includes
context from an earlier stage, the report should preserve enough provenance for
a reviewer to understand where the value came from. Hidden enrichment, opaque
scoring, and untraceable conclusions work against that goal.

## Uncertainty Boundary

Scientific-computing review also depends on knowing what the data cannot prove.
That habit matters here because dependency evidence is easy to overstate.

The repository should keep uncertainty boundaries explicit:

- local manifests and SBOMs prove what they contain, not what the ecosystem
  currently knows
- optional enrichment is evidence for that run, not a universal truth source
- policy output is a local decision, not a package safety verdict
- missing evidence should stay visible as missing evidence
- unknowns should be reported as unknown or `not_evaluated`, not filled with
  guesses

This is why the docs keep non-claims close to the examples. A reviewer should
be able to say what was observed, what was reproduced, and what remains outside
the evidence boundary.

## Scope Rule

Use scientific-computing background as a discipline for reproducible evidence,
clear data flow, and careful uncertainty handling. Do not use it as a reason to
add unrelated project surfaces, broaden claims, or dilute the flagship
`sbom-diff-and-risk` reviewer route.
