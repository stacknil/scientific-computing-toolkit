# Trust boundary and authority matrix

This is a qualification contract freeze at base `29203f9f14e2a3df2ad77a4e874bf752bf44c599`, with the explicitly approved C02 clarification. Three synthetic offline rounds have executed; final audit disposition and C03 remain separate gates.

## Pipeline and authority

| Stage | Input authority | Conversion/default | Permitted conclusion | Unsupported inference / failure boundary |
| --- | --- | --- | --- | --- |
| Parsers | Untrusted CycloneDX, SPDX, requirements or pyproject bytes | Supported syntax only; retain raw records and conservative parser notes | Observed dependency fields | Parsing is not verification; strict parser notes may exit 2 |
| Canonical identity | Registered ecosystem rules and parsed PURL coordinate | PURL then opaque bom_ref then ecosystem/name; trim versions without resolving precedence | Comparison/alignment key | Contradictions/duplicates fail closed; no universal aliasing |
| Diff | Canonical identity and normalized compared metadata | Added/removed/changed; sorted keys | Observed change scope | Metadata changes can bring an existing package into policy scope |
| Local risk | Diff and local metadata | Heuristic buckets, with unavailable stale evaluation explicitly `not_evaluated` | Local prioritization evidence | No CVE, malware, exploitability or safety verdict |
| PyPI evidence | Explicit opt-in provider record | Requested/supported/lookup/status/file/publisher fields remain distinct; errors dominate mixed success | Recorded release/attestation facts under the existing provider contract | Publisher-kind matching is not newly introduced cryptographic verification |
| Scorecard evidence | Explicit high-confidence source mapping plus requested response | No mapping or unavailable response retains an unknown/error state | Auxiliary repository evidence | Repository identity must not be silently replaced by contradictory response metadata |
| Policy parser | Explicit user policy and CLI rule flags | Schema/capability validation; flags merge, block wins, capability can rise | Authorized local rule configuration | Unknown keys/rules/types must not silently become policy |
| Policy evaluation | Added/changed after components, findings and recorded evidence | Exact rule matching, explicit defaults, suppression evidence, deterministic sort | PASS/WARN/FAIL for an applied policy | Unknown is not verified; exceptions have narrow documented scope |
| Confidence | Recorded evidence source categories | Scorecard, provenance, matched policy, SBOM, manifest precedence | Source label | Not probability, safety or universal evidence strength |
| Reports/exit | One policy evaluation and observed records | Exit 0/1/2; full JSON plus summary/policy/Markdown and restricted SARIF | Auditable local decision and its reason | SARIF is deliberately not equal to full JSON; error exit is not policy FAIL |
| CI consumer | Schema-checked report and actual CLI exit | Disclose warnings and gaps; missing policy is not a PASS finding | Local gate and reviewer routing | Consumer `needs-review` is not a native tool exit/status |
| Tool release provenance | Distribution, workflow and separate attestation authority | A different verification procedure for the tool itself | Tool artifact provenance, when independently verified | Does not establish third-party dependency provenance |

## Rules, assumptions and failure modes

Rule matching scope is added and changed after-components; removed/unchanged components are not silently added to policy scope. Risk rules have no default active severity. Threshold/source/explicit provenance requirements default to block when triggered. Explicit warn can override such a default; explicit block wins explicit warn. Ignore suppresses and preserves a decision record, including a match with no active severity.

| Rule | Evidence / authority | Assumption and supported output | Unsupported inference / expected failure mode | Existing executable anchors |
| --- | --- | --- | --- | --- |
| `new_package` | Canonical added set / local diff | Heuristic exists; policy only when configured | New does not mean vulnerable; missing/spurious violation is a defect | test_diffing, test_policy, test_version_decision_reports |
| `major_upgrade` | Known canonical versions / local syntax heuristic | Strict eligible syntax and increasing major only | No ecosystem precedence or API compatibility proof | test_version_decisions, test_risk |
| `version_change_unclassified` | Known unequal versions / local diff | Explicit uncertainty, independently selectable rule | Not equivalent to a major upgrade or vulnerability | test_risk, test_version_evidence |
| `unknown_license` | Missing/unknown license field | Missing metadata, not an inferred license fact | Do not guess a license or infer compromise | test_risk, test_policy |
| `suspicious_source` | Local URL/scheme/host | Provenance-quality heuristic | Not malware; provenance requirement can supersede its SARIF presentation | test_risk, test_sarif |
| `stale_package` | `stale_package` or `not_evaluated` finding | Offline unanswered state can match an explicit stale policy | Do not turn unavailable evaluation into age evidence | test_policy, test_cli_no_enrichment_regression |
| `max_added_packages` | Added count and integer threshold / explicit policy | Trigger only when count exceeds threshold; default block | Boundary equality must not fail; Boolean is not an integer-policy input | test_policy, test_cli_exit_codes |
| `allow_sources` | Added/changed `source_url` host and policy host list | Exact normalized host membership; default block | No suffix/subdomain or reputation inference; missing host can fail | test_policy, test_cli_policy_json |
| `provenance_unavailable` | Absent, unsupported or failed provider evidence | Distinct unavailable rule, active only by explicit configuration | Not missing attestations and not verified evidence | test_policy_provenance |
| `missing_attestation` | Successful recorded lookup with no attestation | Explicit rule; package exception waives only this absence | Exception must not waive unavailable/unverified evidence | test_policy_provenance |
| `unverified_provenance` | Attestation present but publisher metadata absent/mismatched | Explicit publisher-kind rule | No new cryptographic proof or implicit permission from missing data | test_policy_provenance, test_cli_provenance_policy |
| `provenance_required` | Explicit new-PyPI/suspicious-source requirement | Default block for unmet requirement; explicit warn/ignore respected | The requirement is not activated for every package by merely naming a rule | test_policy_provenance |
| `scorecard_below_threshold` | Available recorded score and finite configured threshold | Below, not equal; only explicit block/warn/ignore activation | Absent/unmapped is not proof of low score; high score is not safety | test_policy_scorecard, test_scorecard_enrichment |

`allow_unattested_packages`, `allow_provenance_publishers`, version eligibility and CLI merging are policy controls, not additional native risk buckets. Publisher aliases are mutually exclusive keys. Version capability (1/2/3) is distinct from serialized `sbom-diff-risk.policy.v1`; reports remain `sbom-diff-risk.report.v1`.

## Exceptions and unresolved authority

A PyPI package exception matches PEP 503-equivalent names in both policy entries
and component names under the explicitly approved C02 decision. It does not
waive unavailable lookup evidence, unverified publisher evidence or unrelated
rules. Authorization remains at package-name scope; no full-PURL, version-specific,
fuzzy or cross-ecosystem matching is introduced, and serialized policy spelling
retains the existing parser behavior.

C03 is explicitly approved as `CONTRACT_CLARIFIED_CANONICAL_RELEASE_VERSION`.
Opt-in PyPI lookups use canonical ecosystem/name/version coordinates, including
PURL-only versions. Both CLI inputs are indexed before either provider starts;
direct PyPI calls validate identity, and batch calls validate all items first.
No version means unsupported, never latest. Raw component metadata is preserved;
PURL coordinates do not confer authenticity or publisher authorization.

Qualification calls real parsing/normalization/evaluation/report code with controlled synthetic providers. Provider lookup flags in those records describe the exercised lookup path; a separate socket audit establishes that no actual enrichment network access occurs.
