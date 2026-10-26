# Evidence-to-policy decision stability

Status: **BLOCKED / AUDIT_PENDING**. C03 is explicitly approved and repaired.
All local requalification gates passed; fresh independent reviewers again stopped
with execution-service credit errors before completing final acceptance.

## Scope and authority

This campaign tests whether dependency identity, heuristic observations,
recorded trust evidence, explicit policy and consumer outputs stay distinct.
It is a bounded synthetic qualification, not a vulnerability scanner, generic
alias resolver, reputation model or security certification.

The frozen main/base is `29203f9f14e2a3df2ad77a4e874bf752bf44c599`, tree
`3e6f45e7968d4ac32f475d6842aaa523860fa4a9`. The candidate remains local and
uncommitted. Issues #103 and #117 supplied claim/evidence context; this work
does not close, modify or claim completion of either issue.

## Decision properties

The expected-value module imports only the Python standard library. Its literal
microcases specify decisions, rule identities, severity source, reason codes,
thresholds, observed values, component keys, suppression evidence and confidence
labels. Product functions are used only by the observation adapters. Cross-file
agreement checks supplement that oracle; they are not described as a second
independent policy oracle.

The catalog covers defaults, explicit block/warn priority, ignore precedence,
added-count boundaries, exact source hosts, unavailable provenance, known absent
attestations, unverified publishers, required provenance, package exceptions,
publisher allowlists, Scorecard activation/thresholds, policy version eligibility
and CLI merging/promotion. No blanket monotonicity rule is assumed.

More evidence can reveal a policy failure. A lookup error dominates a recorded
attestation in the current evaluator. A successful metadata lookup without
attestations can satisfy an *unavailable-only* policy while failing a
missing-attestation policy. Losing an available low Scorecard score can remove
a threshold violation because the existing rule does not fabricate an unknown
score. Each transition retains its active policy and evidence-state explanation.

Actual parsers and CLI paths additionally check PEP 503 spelling equivalence,
namespaced PURLs, PURL-only versions, missing references, opaque identities,
unsupported ecosystem equivalence, duplicates/conflicts, the shared CycloneDX/
SPDX subset, overlapping exact manifest pins, order, ignored metadata,
serialization and incomplete/contradictory fields.

The namespace/case tests deliberately preserve unsupported distinctions. An
equal policy outcome for two opaque identities does not establish identity
equivalence. A metadata change that enters `changed.after` policy scope can
legitimately expose an already disallowed source; ignored raw annotations do
not enter that scope.

## Confirmed repairs and compatibility

1. Policy parsing rejects Boolean integer fields and non-string keys through
   `PolicyError` / CLI exit 2. Valid policy integer values and defaults remain.
2. Scorecard parsing rejects Boolean/nonfinite numbers and explicitly conflicting
   response repositories. Missing repository/name fallback, ASCII case-only spelling,
   finite values and the existing per-check `-1` sentinel remain compatible.
3. The explicitly approved C02 policy clarification applies PEP 503 equality
   to both PyPI package exception entries and component names. It preserves
   package-name scope, serialized spelling and the missing/unavailable/unverified
   evidence boundaries. Spelling-only changes now classify as `STABLE`.

Malformed Scorecard evidence becomes an existing error record. Consumers can
observe a policy PASS when an active threshold has no usable score to evaluate;
this is existing unknown-score policy behavior, not a new safety assertion.
Recorded-error confidence remains `scorecard_recorded`.

Canonicalization, diff signatures, risk buckets, strict SemVer rules, report and
policy schema versions, offline defaults and ordinary policy severity rules are
unchanged. Goldens, committed example reports, release workflows, dependency
declarations and repository settings are unchanged. Rollback consists of removing
the narrow validation/matching repairs and their qualification files; no history
rewrite, data migration or remote rollback is involved.

The baseline boundary regressions, C02 decision, rejected oracle assumptions and
original C03 reproducer and approved repair are retained in `COUNTEREXAMPLES.md`. Two wrong
representation expectations and an invalid distinct-PyPI-release cache probe
were rejected without changing production semantics. A first runner-startup
failure caused by a dynamic import table was corrected with an explicit API
mapping and a failing-to-passing actual worker regression. No failed or aborted
run is counted as a successful qualification round.

## Output and consumer mapping

| Consumer | Required correspondence | Deliberate limit |
| --- | --- | --- |
| Full JSON | Evaluation, rule identity, reason, exact evidence, confidence, raw component evidence | Recorded evidence is not verification |
| Summary JSON | Exact full-report summary; status/counts/confidence | No independent list of all finding evidence |
| Policy JSON | Full-report policy sections and policy summary | No component inventory or risk inventory |
| Markdown | Grouped rule/name/level/message, suppression reason, counts, exit/confidence | Does not serialize every JSON explanation field |
| SARIF | Explicit subset mapping, rule/component identity and emitted policy severity | Unsupported or superseded findings may be omitted |
| CLI exit | 1 for blocking; 0 for applied pass/warn; 2 for invalid input | No native needs-review exit |
| Example CI consumer | Preserve captured exit; attempt artifact upload with `if: always()` before enforcement | Invalid input can produce no policy JSON, so upload success is not guaranteed |

The checked-in example workflow captures/enforces exit status and attempts artifact
upload; it does not parse policy JSON. The separate test demonstration consumer
reads warning counts and applied-policy state rather
than treating exit 0 as affirmative safety. No-policy or runtime-error states
remain consumer `needs-review`. Synthetic provider bodies are parsed by actual
clients; their configured lookup flags are distinguished from actual audited
network operations.

## Execution and acceptance gate

The clean baseline passed 473 package tests and the supported offline example
artifact check. The final C03 candidate passed 817 tests in each of three rounds
(seeds 103, 117 and 120), with no failures, errors or skips. The supported
artifact check passed, and audited network attempts were zero. See the manifest
for the exact source inventory and executed environment. Repeated rounds do not
substitute for the interrupted independent final audit.

The final oracle checks literal expected evidence after serialization as well
as on the model, rejects Boolean/numeric substitutions recursively, and checks
complete Markdown messages. Seven deliberate corruptions were first accepted
incorrectly (seven failing regressions), then rejected after the harness repair.
The affected gate passed 153 tests. These are qualification-harness defects,
not additional product defects.

Four protected repositories retained their original HEAD, branch, status,
staged and unstaged diff bytes, existing refs and worktree registrations. Only
the authorized candidate branch/worktree was added. Untracked filenames/status
were compared; there were no initial byte snapshots of untracked contents.

Scoped Ruff correctness checks and pip check passed. The full Ruff scan retains
the documented pre-existing F821 finding. Native Linux CPython 3.11.17 on ext4 passed 817 tests plus a targeted rerun,
golden checks and the network-denial audit on the same semantic source. This was
maintainer execution after the reviewer interruption. Remote CI, live providers
and release builds were not executed for this candidate.

The N01–N14 controls validate removed violations, wrong severity, lost
suppression evidence, unavailable/verified confusion, attestation-state confusion,
publisher acceptance, inactive Scorecard enforcement, threshold boundaries,
identity splitting/conflicts, sidecar disagreement, exit disagreement and
heuristic authority escalation. Each control reaches and records its named
detector after a validated normal observation.

Completion requires executed regression evidence, stable or explained decisions,
detected negative controls, exact source identity, preserved existing work,
unchanged public contracts except the approved clarification, and no unresolved
material audit blocker. Repeated seeds and overlapping integration views are
not added together as independent semantic cases.

## C03 release-coordinate boundary

The approved contract is `CONTRACT_CLARIFIED_CANONICAL_RELEASE_VERSION`.
Canonicalization remains unchanged. Canonical release coordinates now govern
explicit PyPI enrichment and cache isolation; no-version cases remain unsupported.
Both CLI input indexes are validated before either provider is constructed.
Direct PyPI normalization validates the component, and batch enrichment validates
all items before its first lookup. Original component metadata remains intact.
Recorded metadata, attestation availability, verification and publisher permission
retain their prior distinct meanings. See the 31 focused C03 regressions.
