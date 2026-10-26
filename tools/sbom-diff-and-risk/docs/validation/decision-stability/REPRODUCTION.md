# Reproducing the local decision stability qualification

The frozen base is `29203f9f14e2a3df2ad77a4e874bf752bf44c599`, root tree
`3e6f45e7968d4ac32f475d6842aaa523860fa4a9`. The candidate is an uncommitted
local change on `stacknil/sbom-evidence-decision-stability`. A base commit alone
does not contain these new qualification files. Use the candidate files and
the implementation inventory in `EXECUTION-MANIFEST.json` to identify the
tested source; no release or remote CI result is implied.

## Setup and replay

From `tools/sbom-diff-and-risk`, create a separate environment outside the
entire repository, install the declared dev dependencies, then run:

```sh
python -m pip install -e '.[dev]'
python -m pip check
python -m pytest -q -ra
python scripts/regenerate-example-artifacts.py --check
python scripts/qualify-decision-stability.py \
  --output-root ../../../decision-stability-evidence \
  --seeds 103 117 120
```

`--output-root` must be a new directory outside the checkout. The runner rejects
existing output directories and retains failures. Do not delete a failed run
to make a later run look successful; use a new sibling directory. The three
seeds change YAML key order, record permutations and JSON serialization; they
are repeated validation of the same semantic catalog, not three independent
discoveries of each property.

Dependency/tool installation is setup, separate from qualification. The replay
runner installs no packages and makes no evidence-service requests. It installs
a subprocess audit hook that rejects Internet socket and name-resolution
operations before transport. Provider requests inside the tests are routed to
in-memory synthetic byte streams. Production `network_access_performed` fields
can therefore be true for an explicitly exercised provider lookup path while
actual network attempts remain zero. Those meanings must not be conflated.

Each round records expectations before observations, actual results, synthetic
CLI reports, reached negative controls, full-suite JUnit and stdout/stderr.
The parent records interpreter/package versions, source inventory, artifact
compatibility, bounded timeouts and local consumer-shell checks. No raw output
is written into the source checkout by this runner. Direct pytest commands
above can be given external `--basetemp`, `--junitxml` and
`-o cache_dir=...` paths as done for the retained qualification receipts.

## Focused checks

```sh
python -m pytest -q \
  tests/test_policy_validation_qualification.py \
  tests/test_scorecard_evidence_integrity.py
python -m pytest -q tests/test_policy_package_equivalence.py
python -m pytest -q tests/test_decision_stability*.py
```

The first group originally had 32 tests: the preserved unchanged-production RED result is
25 failed / 7 passed, and the repaired result was 32 passed. It now has 35 tests,
including three Unicode repository-alias regressions added after independent
review. Those three failed against the initial case-folding repair and passed
after ASCII-only case folding. The C02 exception
group has 29 tests: 17 failed / 12 passed before the approved correction, and
29 passed afterward. Negative controls pass only when their deliberate semantic
corruption raises the specific expected `OracleMismatch` code; a collection,
import or unrelated runtime failure cannot count as detection.

To reproduce RED without altering the candidate, export the frozen base into
a separate directory, copy only the two first-group regression test files from
the candidate into that export, and install that export in a different dev
environment. To replay the historical 32-case result, exclude the three
Unicode cases with `-k 'not unicode'`. Running all 35 is a different gate and
must not be attributed to that historical receipt. For C02, copy
`test_policy_package_equivalence.py` instead. Do not copy the repaired production
files or use an editable installation pointing back to the candidate. Check
the actual `sbom_diff_risk` import origin before interpreting the result.

## Deliberate limits

- Native runtime decisions remain pass/warn/fail when policy is applied; exit
  0 covers both pass and warn. `needs-review` is only a consumer classification.
- SARIF is a subset. Unavailable provenance, staleness and unclassified version
  changes are not required to appear there. Missing/unverified provenance
  warning results may be intentionally omitted or superseded by a requirement.
- Recorded provenance and publisher metadata are not cryptographic signature,
  subject-digest, certificate, transparency-log or tool-release verification.
- No evidence-confidence label is a probability, vulnerability finding or
  dependency-safety verdict.
- C03 is approved and repaired. Replay `tests/test_canonical_release_enrichment.py`
  for its 31 regression cases. The original counterexample and first divergent
  stage are retained in `COUNTEREXAMPLES.md`. Final independent audit is pending.
- Remote CI, release builds/publication and live provider behavior are outside
  this campaign. The local environment and actual executed gates are listed
  in the manifest; unexecuted platforms are not counted as passing.
