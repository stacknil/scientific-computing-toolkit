# Independent decision invariants

Status: implemented contract catalog with three executed synthetic rounds. C02
adds an explicitly approved canonical-name invariant; C03 remains unresolved.
An invariant is asserted only within its documented scope.

| ID | Independent requirement | Main evidence source / bounded scope |
| --- | --- | --- |
| I01 | Same supported canonical coordinate aligns to one package; namespaces and opaque IDs are preserved | Component identity comparison contract; no universal ecosystem normalization |
| I02 | Duplicate/conflicting same-input coordinates yield explicit invalid-input diagnostics | Identity/diff contract; no first-match reconciliation |
| I03 | Ordinary risk findings remain separate from policy decisions and security verdicts | Risk/report non-claims; SemVer repair is already present |
| I04 | No policy means no policy summary, not an affirmative PASS claim | JSON report contract; consumer needs-review remains consumer-side |
| I05 | Explicit block wins warn, and explicit warn can override a triggered default block | Policy schema and CLI merge contract |
| I06 | Ignore preserves suppressed finding identity, evidence and accounting while removing active enforcement | Policy explainability; inactive severity can be null |
| I07 | Added count equal to the threshold passes; a strictly higher count triggers the configured/default severity | Integer threshold contract |
| I08 | Source host matching is exact; absent/subdomain/different hosts are not authorized by substring inference | Policy source allowlist contract |
| I09 | Unavailable, absent attestation, and unverified publisher states are distinct | Recorded provenance contract; error dominates mixed success |
| I10 | Package missing-attestation exceptions do not waive unavailable or unverified evidence | Narrow PyPI package-name exception scope; C02 equivalence is explicitly approved |
| I11 | Required provenance applies only in its explicitly enabled new-PyPI or suspicious-source context | Capability v2 requirement contract |
| I12 | Scorecard requires an explicit active rule; equality at threshold is not below | Capability v3 contract; missing data alone creates no score violation |
| I13 | YAML version eligibility and CLI rule capability promotion remain separate and deterministic | Policy parser/build contract; v1/v2 files cannot silently accept later-only fields |
| I14 | Accepted Scorecard numbers are numeric and finite; explicit contradictory response identity cannot be rebound | Evidence integrity plus strict machine-consumable JSON; preserve missing/case-only compatibility |
| I15 | Every finding preserves exact component/rule/evidence/reason/severity-source/threshold identity | Public explainability fields; no expected value taken from evaluator output |
| I16 | Full JSON, summary, policy sidecar, Markdown and exit agree under their documented projections | Restricted SARIF map is specified separately; counts alone are insufficient |
| I17 | Repeated identical inputs are byte deterministic; permutations preserve relevant semantic observations | Raw input evidence and format-specific confidence remain visible |
| I18 | No actual network is needed for qualification; arbitrary provider availability is not verification probability | Synthetic byte-stream transport and socket audit, not a live registry |
| I19 | PEP 503-equivalent PyPI names preserve exception eligibility in both policy entries and components | C02 approved clarification; raw evidence and package-name scope are preserved |

| I20 | Valid explicit/PURL-only release representations are enrichment-equivalent; malformed/conflicting input cannot trigger lookup | C03 owner-approved canonical coordinates; CLI snapshot index validation precedes providers, direct APIs validate identities |

## Oracle independence

Expected decisions use literal microcases, explicit finding specifications and
independently calculated count/score boundaries. The expected-value path does not
call the production evaluator, identity resolver, serializer or private matching
helpers. The production adapter calls those functions only to obtain observations
to compare with the frozen expectations.

Negative controls N01–N14 must first pass the corresponding green observation, then corrupt a reached result and demonstrate detection by the named check. Import errors, unreachable branches, unexecuted controls and unrelated assertion failures do not count as detected semantic mutations.

## Reversal classes

- `STABLE`: the chosen transformation preserves the relevant evidence and policy semantics, not merely a raw label.
- `JUSTIFIED_REVERSAL`: a specific authorized rule, threshold, exception, evidence state or added/changed scope changed.
- `SUSPICIOUS_REVERSAL`: a decision changed without a sufficient documented reason.
- `INVALID_INPUT`: the input is contradictory, ambiguous, malformed or outside the supported syntax and must follow its fail-closed contract.
- `UNRESOLVED`: the current contract cannot choose an intended outcome; retain the counterexample rather than blessing implementation behavior.

More evidence need not reduce enforcement. A newly observed error can make provenance unavailable; a real metadata change can bring a previously unchanged component into the documented policy scope. These are separate from serialization/order transformations. Confidence labels classify evidence sources and are never treated as probabilities.
