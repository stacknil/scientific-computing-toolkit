# SBOM Diff as a Bounded Policy Review Artifact

An SBOM diff can answer a useful, limited question: what dependency evidence
changed between two inputs? It cannot decide whether a package is safe.

`sbom-diff-and-risk` keeps those statements separate. The tool produces a
deterministic component diff, local heuristic risk findings, and optional
policy decisions. Each layer remains visible in JSON, Markdown, SARIF, summary,
and policy-sidecar artifacts.

## Diff evidence comes first

The diff layer identifies added, removed, and changed components from
CycloneDX, SPDX, or supported dependency manifests. Component identity and
signature fields determine membership in those sets. They are not reputation
signals.

The local risk layer can attach bounded review buckets such as `new_package`,
`major_upgrade`, `version_change_unclassified`, `unknown_license`,
`suspicious_source`, and `not_evaluated`. The
[risk model boundary](../../../docs/risk-model-boundary.md) defines the exact
inputs for those buckets and the conclusions they do not support.

For example, `new_package` means a component appears only in the after input.
It does not mean the package is vulnerable or malicious. `not_evaluated`
preserves an unanswered question instead of filling an evidence gap with a
guess.

## Policy is a separate decision layer

A local policy can map diff or risk evidence to `pass`, `warn`, or `fail`.
Policy findings expose stable explanation fields:

- `decision_reason`
- `policy_rule`
- `severity_source`
- `matched_threshold`
- `observed_value`

Those fields let a reviewer see whether a decision came from a configured
threshold, a risk bucket, or a default policy severity. They do not upgrade the
decision into a dependency safety verdict. The full contract is documented in
[policy decision explainability](policy-decision-explainability.md) and the
[JSON report schema](report-schema.md).

## A small reproducible review surface

The checked-in examples include before/after inputs, generated reports, summary
JSON, policy sidecars, and bounded policy-decision fixtures for `pass`, `warn`,
`fail`, and consumer-side `needs-review`.

From `tools/sbom-diff-and-risk`, a reviewer can run:

```bash
python -m pip install -e .[dev]
python scripts/regenerate-example-artifacts.py --check
python scripts/regenerate-example-artifacts.py --check --only requirements
```

These checks use committed no-network examples. They verify that the examples
still match the code; they do not prove that a third-party dependency is safe.
The ordered evidence route is in the [reviewer path](reviewer-path.md).

## What remains a human decision

The tool can make a policy choice explicit, but it cannot decide whether that
policy fits a deployment context. Reviewers still need to ask whether a
threshold is appropriate, whether a missing license blocks release, whether a
source allowlist is justified, and whether an evidence gap should fail a gate
or remain `needs-review`.

The boundary is intentional: the artifact records what changed, which local
rule matched, and why the configured policy responded. It does not resolve
CVEs, inspect package contents for malware, infer exploitability, or certify a
package as safe.
