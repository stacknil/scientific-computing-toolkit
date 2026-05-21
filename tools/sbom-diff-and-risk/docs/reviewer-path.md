# Reviewer path

Use this page as the ordered review route for `sbom-diff-and-risk`. It is
designed to make one thing clear at every step: what evidence you are checking,
where to find it, and what it does not prove.

## First choose the review question

| Review question | Start here | Good stopping point |
| --- | --- | --- |
| What is this tool? | [30-second orientation](#30-second-orientation) | You can state the tool's scope and non-claims. |
| What artifacts does it produce? | [5-minute artifact review](#5-minute-artifact-review) | You can point to JSON, summary, policy, Markdown, and SARIF examples. |
| Can the examples be reproduced locally? | [15-minute reproduction check](#15-minute-reproduction-check) | `regenerate-example-artifacts.py --check` passes without enrichment. |
| Can the released tool artifacts be verified? | [Release evidence](#release-evidence) | You can choose the correct GitHub release, checksum, or attestation path. |
| Is this enough for a full review? | [Deep review](#deep-review) | You have followed the reproducible checklist in the evidence pack. |

## 30-second orientation

Read:

- [reviewer-brief.md](reviewer-brief.md)
- the first screen of the [tool README](../README.md)

Confirm these claims only:

- local, deterministic SBOM/dependency diff CLI
- supported inputs: CycloneDX JSON, SPDX JSON, `requirements.txt`, and
  conservative `pyproject.toml`
- output artifacts: JSON, Markdown, SARIF, `summary.json`, and `policy.json`
- local policy checks with reviewer-facing decision explanation fields
- optional PyPI provenance and OpenSSF Scorecard enrichment only when
  explicitly enabled
- production PyPI publishing remains intentionally deferred

Stop here if you only need the project shape for a reviewer, resume, or PR
summary.

Do not infer:

- CVE scanning
- dependency safety verdicts
- package reputation scoring
- hidden network enrichment
- production PyPI availability

## 5-minute artifact review

Inspect the checked-in examples in this order:

| Step | Artifact | What it proves |
| --- | --- | --- |
| 1 | [sample-report.json](../examples/sample-report.json) | Full machine-readable diff, risk, policy, and metadata shape. |
| 2 | [sample-summary.json](../examples/sample-summary.json) | Compact CI-facing `summary` contract. |
| 3 | [sample-policy.json](../examples/sample-policy.json) | Policy-only sidecar for CI consumers. |
| 4 | [sample-report.md](../examples/sample-report.md) | Human-readable reviewer report. |
| 5 | [sample-sarif.sarif](../examples/sample-sarif.sarif) | Conservative code-scanning output for selected high-signal findings. |
| 6 | [github-actions-policy-consumer.yml](../examples/github-actions-policy-consumer.yml) | Copyable consumer path for capturing policy JSON in GitHub Actions. |

Then read:

- [report-schema.md](report-schema.md)
- [policy-decision-explainability.md](policy-decision-explainability.md)
- [github-code-scanning.md](github-code-scanning.md)

Look for these reviewer anchors:

- `summary` is the compact machine-readable entry point
- `summary.policy` appears only when policy evaluation runs
- `summary.enrichment` appears only when enrichment evidence exists
- policy findings explain `decision_reason`, `policy_rule`,
  `matched_threshold`, and `observed_value`
- SARIF is intentionally narrow and does not mirror every report finding

Stop here if you need to understand the review outputs without running code.

## 15-minute reproduction check

From `tools/sbom-diff-and-risk`, run the deterministic example checks:

```powershell
python -m pip install -e .[dev]
python scripts/regenerate-example-artifacts.py --check
python scripts/regenerate-example-artifacts.py --check --only requirements
```

Expected result:

- the full checked-in no-network example set is up to date
- the focused requirements example check passes
- JSON, Markdown, summary, policy sidecar, and SARIF examples match the
  committed artifacts
- no PyPI, Scorecard, CVE, or advisory network lookup is performed

For the exact regeneration scope, read
[example-artifact-regeneration.md](example-artifact-regeneration.md).

Stop here if you need reproducible local evidence that the examples still match
the code.

## Release evidence

Use this section only when the review question is about the released
`sbom-diff-and-risk` tool artifacts. It is not the path for judging third-party
dependency safety.

| Evidence surface | Use when | Read |
| --- | --- | --- |
| Verification decision guide | You need to choose the right release verification path. | [verification.md](verification.md) |
| GitHub Release assets and checksums | You downloaded wheel or source distribution files from a release. | [release-provenance.md](release-provenance.md) |
| Workflow artifact attestations | You are verifying workflow-built wheel or source distribution artifacts. | [self-provenance.md](self-provenance.md) |
| TestPyPI Trusted Publishing dry-run | You are checking whether the dry-run publisher path worked. | [pypi-trusted-publishing-readiness.md](pypi-trusted-publishing-readiness.md) |
| Production PyPI decision gate | You are deciding whether production PyPI should be enabled later. | [pypi-production-publishing-decision.md](pypi-production-publishing-decision.md) |

Keep the evidence surfaces separate:

- GitHub workflow artifact attestation verifies workflow-built artifacts.
- GitHub Release asset checksums verify downloaded release bytes against the
  release checksum manifest.
- GitHub immutable-release verification applies only when the release is
  immutable and GitHub has generated release attestations.
- TestPyPI Trusted Publishing proves the dry-run publisher path worked.
- Production PyPI Trusted Publishing is intentionally deferred and does not
  exist for this project yet.

Stop here if your review question is release provenance rather than dependency
analysis behavior.

## Deep review

Use [reviewer-evidence-pack.md](reviewer-evidence-pack.md) for the full
reproducible checklist, including:

- local demo commands
- release asset inspection
- checksum verification
- artifact attestation verification
- TestPyPI evidence boundaries
- SARIF/code-scanning boundaries
- non-claims

Use these supporting docs for focused review questions:

- [dependency-risk-heuristics.md](dependency-risk-heuristics.md) for risk bucket
  semantics
- [parser-boundaries.md](parser-boundaries.md) for deterministic parser limits
- [policy-schema.md](policy-schema.md) for policy file shape
- [policy-decision-ci-cookbook.md](policy-decision-ci-cookbook.md) for CI policy
  consumption
- [summary-json-ci-cookbook.md](summary-json-ci-cookbook.md) for summary-only CI
  consumption

## Reviewer bottom line

`sbom-diff-and-risk` is review infrastructure. It makes dependency changes,
policy decisions, and selected supply-chain trust signals easier to inspect.
It does not decide whether a dependency is safe.
