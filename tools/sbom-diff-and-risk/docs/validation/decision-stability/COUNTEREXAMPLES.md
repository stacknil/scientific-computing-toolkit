# Counterexamples and rejected hypotheses

Baseline: `29203f9f14e2a3df2ad77a4e874bf752bf44c599`, tree `3e6f45e7968d4ac32f475d6842aaa523860fa4a9`.

Status: baseline probes independently reproduced. C01/C04/C05 and the approved C02 clarification have focused RED/GREEN evidence. C03 now has explicit owner approval and executed repair evidence. All examples below are synthetic. Provider clients consumed in-memory byte streams, never live responses. Raw diagnostic receipts remain outside the checkout.

## C01 — Boolean integer-policy fields

```yaml
version: true
```

The loader accepts this as a version-1 policy because Python Boolean values are integer subclasses. `version: 1` with `max_added_packages: true` or `false` is also accepted, acting as thresholds 1 or 0. `version: false` is already rejected; it is not an accepted counterexample.

Classification: **production defect**. The [policy schema](../../policy-schema.md) declares integer fields and rejects invalid types. Expected outcome is controlled `PolicyError` / CLI exit 2, preserving valid integer versions and non-negative integer thresholds. This does not require a new severity/default policy.

The same regression group includes non-string YAML keys: integer-only unknown
keys raised `TypeError` while formatting diagnostics, and mixed string/integer
keys raised `TypeError` during sorting. The repair validates key types before
sorting. Boolean/invalid-key cases now fail through the existing `PolicyError`
boundary and CLI exit 2, without producing reports.

## C02 — Canonical PyPI aliases and package exceptions

Policy:

```yaml
version: 2
block_on: [missing_attestation]
allow_unattested_packages: [demo-pkg]
```

Added CycloneDX component, with synthetic successful metadata retrieval but no attestations:

```json
{"name":"demo-pkg","version":"1.0.0","purl":"pkg:pypi/demo-pkg@1.0.0"}
```

Change only `name` to `Demo_Pkg` or `demo.pkg`. All three canonical identities are `purl:pkg:pypi/demo-pkg`, canonical version `1.0.0`; comparison between these representations produces no changes. Decisions are respectively **PASS, FAIL, FAIL**. The failures use `attestation_not_published`.

First divergence: `policy_evaluator._package_is_unattested_allowed` matches the observed name after trim/lowercase, not the canonical PyPI name. The identity documents explicitly promise a comparison contract; package-exception documentation does not define alias equivalence.

Classification: **CONTRACT_CLARIFIED_CANONICAL_NAME_EQUIVALENCE**. The owner
explicitly approved PEP 503 name equality for PyPI package exceptions. Both
policy entries and component names use the existing `packaging.utils.canonicalize_name`
semantics. The exception remains package-name scoped, PyPI-only and limited to
missing attestations; it cannot waive unavailable or unverified provenance.
No version/PURL/fuzzy/cross-ecosystem authorization is introduced. Serialized
policy spelling retains the existing parser's normalization only.

The original reproducer exits `[0, 1, 1]` before correction and `[0, 0, 0]`
after correction. The spelling-only transition is **STABLE**, not a justified
policy reversal. The new 29-case boundary regression was 17 failed / 12 passed
before correction, then 29 passed. YAML-loaded and directly constructed policies,
non-equivalent names, unavailable/unverified evidence and ecosystem scope are
covered. The affected policy/report gate passed 216 tests.

## C03 — PURL-only version and opt-in provenance eligibility

Policy:

```yaml
version: 2
block_on: [provenance_unavailable]
```

Compare separate added-component runs:

```json
{"name":"demo-pkg","purl":"pkg:pypi/demo-pkg@1.0.0"}
```

```json
{"name":"demo-pkg","version":"1.0.0","purl":"pkg:pypi/demo-pkg@1.0.0"}
```

Canonical identity/version are equal, and comparison between these representations produces no change. With the same synthetic provider fixture, the first run makes no transport calls, records `unsupported_for_package` and **FAILS** with `provenance_evidence_unavailable`. The second invokes the synthetic release/provenance transports, records fetched release metadata without attestations and **PASSES** this unavailable-only rule. Passing that rule does not mean an attestation exists or a package is verified.

First divergence: `normalize_pypi_provenance` requires raw `Component.version`. The explicit canonical-PURL guarantee in the existing risk documentation applies to version comparison, not all enrichment eligibility.

Classification: **CONTRACT_CLARIFIED_CANONICAL_RELEASE_VERSION** (owner approved).
The original FAIL/PASS reproducer and raw responses remain retained. The first
divergent stage was `normalize_pypi_provenance` rejecting an absent raw version;
the raw-field cache key also conflated distinct PURL-only releases. Canonical
ecosystem/name/version now drive lookup and caching without rewriting observed
components. Equivalent releases are **STABLE** (PASS/PASS with opt-in enabled;
FAIL/FAIL under the same unavailable-only policy offline).

The corrected initial regression gate was 22 failed / 3 passed, then 49 affected
tests passed. A preliminary test invocation also contained mock-serialization
and policy-path comparison errors; it is not the authoritative RED receipt.
Final C03 coverage has 31 tests including direct APIs, CLI inputs, cache separation,
equivalent metadata, no version, malformed/conflicting metadata and error states.

Fresh independent review found that per-item CLI validation still admitted
provider calls before rejecting duplicate/conflicting snapshot indexes. Two
additional RED cases confirmed calls despite eventual exit 2. CLI now reuses
the existing index validator on both sides before creating either enricher;
43 affected tests passed. Direct enrichment release batches can contain repeated
or different valid releases; CLI SBOM snapshots retain their existing uniqueness
contract. Contradictory identities are INVALID_INPUT, never equivalent.

No latest-release fallback, authenticity claim, default network activity, schema
change or new evidence/publisher authorization is introduced. Independent final
review of the index correction remains pending after infrastructure failure.

## C04 — Scorecard response identity laundering

Request the synthetic repository `github.com/example/demo`; return:

```json
{"repo":{"name":"github.com/other/unrelated","commit":"other-commit"},"score":9}
```

The response parser accepts the different identity. The enricher then reports the requested repository mapping while retaining the other repository's commit/score and `scorecard_available`. An explicitly active threshold-7 rule passes.

Classification: **production evidence-binding defect**. An explicit contradiction must not become evidence for another requested repository. Missing repository/name fallback is a separate currently supported case and must remain compatible; case-only GitHub identity spelling is also a separate compatibility control. No redirect, path or universal alias inference is proposed.

Independent review found that the first C04 repair used Unicode `casefold`,
which also equated sharp-s with `ss`, the Kelvin sign with `k`, and the `ff`
ligature with `ff`. All three regressions failed against that repair.
ASCII-only letter folding now preserves non-ASCII distinctions; the affected
gate passed 60 tests. Final independent re-review remains incomplete.

## C05 — Invalid numeric Scorecard evidence and non-JSON output

Synthetic overall scores `true` and `false` become 1.0 and 0.0. Overall `1e309`, `-1e309` and `NaN` become available nonfinite scores. The rendered full JSON contains `Infinity`, `-Infinity` or `NaN`, which a strict JSON reader rejects.

Positive infinity passes a threshold-7 rule. **NaN blocks under the baseline evaluator**; there is no NaN-bypass claim. Invalid per-check infinity/NaN escape as conversion exceptions rather than becoming available evidence; Boolean check scores are accepted as integers.

Classification: **production validation/report contract defect**. Boolean/nonfinite values are not usable finite numeric evidence. They should produce the existing controlled provider-error state, not a new risk bucket, arbitrary severity or a package-safety verdict. Valid finite evidence and currently supported sentinel values must remain compatible.

## Repair evidence for C01/C04/C05

Against unchanged baseline production, the new 32-case regression group had
**25 failed, 7 passed, 0 errors, 0 skips**. All failures reached policy loading,
provider parsing or the actual CLI. After the narrow repairs, **32 passed** and
the then-complete suite passed **505** tests. No golden or schema was changed.

- C01: reject Boolean integer fields and non-string policy keys with the
  existing controlled error type; valid integer values remain accepted.
- C04: reject an explicitly conflicting Scorecard response repository. Missing
  repository/name fallback and case-only GitHub spelling remain accepted.
- C05: reject Boolean/nonfinite numeric evidence with `ScorecardClientError`.
  Existing enrichment error handling records the evidence gap. It does not
  activate a new policy violation, so a rule that only enforces *available*
  low scores can return PASS when malformed evidence becomes unavailable.
  `scorecard_recorded` still describes a recorded error, never verification.

## Rejected oracle assumptions

The first representation gate had **51 passed, 2 failed**. Both failures were
in the qualification expectations, not production:

1. R14 expected source input order instead of the required deterministic lexical
   identity order. The corrected expectation sorts the independently specified
   names.
2. R19 assumed exact manifest pins used coordinate fallback. Both existing
   parsers explicitly call `build_pypi_purl`, so the expected identity is
   `purl:pkg:pypi/qualification-alpha`. The test still checks the independently
   specified package/version and warning rule.

The corrected gate passed **53** tests. These failed experiments remain in
private receipts and are not counted as production defects.

A further cache probe failed twice by returning different attestation states
for `1.0.0-rc` and `1.0.0-RC`. Independent review rejected this distinct-release
assumption: the installed PEP 440 implementation normalizes both to
`1.0.0rc0`. With identical provider evidence, both comparison orders keep the
same missing-attestation decision. The cache records the first lookup's version
spelling; each raw component keeps its own version. No existing field contract
requires a lookup record to echo every equivalent component spelling.

Classification: **TEST_ORACLE_DEFECT**, not an established production cache
defect. The two failed probes and their source are retained privately, and the
invalid probe is excluded from the accepted regression suite. No cache change or
PEP 440 normalization of general component identity is warranted by this probe.

## Qualification harness audit corrections

Independent audit identified Boolean/numeric equality, coherent corruption of
serialized reason/observed/threshold values, and a Markdown message replacement
retaining the row prefix. Seven meaningful regressions failed before repair
because the expected rejection did not occur. The corrected harness compares
serialized rows against literal independent expectations, checks full Markdown
messages and distinguishes nested Boolean/numeric evidence. The affected gate
passed 153 tests. An earlier invocation had a quoting error (exit 4, no tests);
it is retained and is not counted as RED evidence.

## Pre-existing lint limitation

A full Ruff correctness scan reports `F821` at
`tests/test_policy_scorecard.py:58` (`Path` appears only in a postponed type
annotation). That file is byte-identical to the frozen base and was not changed.
Ruff correctness checks pass for the candidate's changed/new Python files.
The full scan is **not** reported as passing; this unrelated existing annotation
finding does not explain a runtime regression in the executed suite.

## Boundaries on the findings

- No change to the already merged strict-SemVer classifier is proposed.
- Recorded attestation/publisher metadata is not a cryptographic verifier, and qualification does not invent one.
- A recorded evidence-confidence label is a source category, not a probability or proof of safety.
- Missing optional Scorecard evidence does not by itself activate an existing score threshold rule.
- Contract gaps are not converted into passing invariants, defects or silently selected policy decisions.
