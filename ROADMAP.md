# Roadmap

The repository's current flagship surface is `sbom-diff-and-risk`. The
near-term focus is to stabilize reviewer paths, release evidence, policy
boundaries, and deterministic examples rather than expand the project count.

## External Review Surface

Open review issues should be sparse and grounded in checked-in examples. A
useful issue names the sample input, expected JSON/Markdown/SARIF output, and
acceptance criteria for a bounded artifact or policy-contract review.

The current public review entry is intentionally narrow: trace one
requirements-file dependency change through the generated report and confirm
that local risk buckets remain policy-review evidence rather than package
safety verdicts.

## v1.1: Input and Policy Semantics

The v1.1 route is implementation-led: pin the real input support matrix,
version policy and report contracts, make policy decision evidence explicit,
then harden component identity canonicalization and same-input conflict
diagnostics. The detailed acceptance gates live in
[tools/sbom-diff-and-risk/docs/v1.1-input-and-policy-semantics.md](tools/sbom-diff-and-risk/docs/v1.1-input-and-policy-semantics.md).

The tool remains in this monorepo. Repository extraction is deferred until
real third-party adoption creates an independent release or maintenance
boundary.

## Parked Directions

- Parser-boundary fixtures, only when the before/after input and normalized
  component output are known up front.
- No-network reproduction feedback, only when it names exact command output,
  link drift, or artifact-regeneration mismatch.
- `needs-review` policy examples, only when the remaining human decision is
  explicit and separate from vulnerability or malware claims.
- Additional dependency-pair examples, only when they clarify a distinct risk
  model boundary without adding live enrichment or safety verdicts.
