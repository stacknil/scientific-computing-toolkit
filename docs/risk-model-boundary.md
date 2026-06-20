# Risk Model Boundary

This page defines the SBR-02 boundary for the
[`sbom-diff-and-risk`](../tools/sbom-diff-and-risk/README.md) risk model: which
inputs can change risk findings, which inputs are context only, and which
conclusions the tool must never infer.

The model is a deterministic local heuristic layer. It is not a vulnerability
scanner, not a CVE resolver, and not a dependency safety verdict.

Implementation references:

- [`risk.py`](../tools/sbom-diff-and-risk/src/sbom_diff_risk/risk.py)
- [`diffing.py`](../tools/sbom-diff-and-risk/src/sbom_diff_risk/diffing.py)
- [`models.py`](../tools/sbom-diff-and-risk/src/sbom_diff_risk/models.py)
- [`dependency-risk-heuristics.md`](../tools/sbom-diff-and-risk/docs/dependency-risk-heuristics.md)

## Fields that affect risk classification

The risk model evaluates the added component set and the changed component set.
Removed components are reported as diff output but do not currently produce
risk findings.

Some fields affect whether a component enters the added or changed set. A
smaller set of fields directly selects the emitted risk bucket.

### Diff membership inputs

| Input or field | Affects | Boundary |
| --- | --- | --- |
| Component identity from `purl`, `bom_ref`, or `ecosystem` plus `name` | Whether a component is considered added, removed, or shared across inputs. | Identity is used by the diff layer before risk evaluation. It is not a package reputation signal. |
| Component signature fields `name`, `version`, `ecosystem`, `purl`, `license_id`, `supplier`, `source_url`, `bom_ref`, and `raw_type` | Whether a shared component is classified as changed. | A metadata-only change can enter risk evaluation, but bucket selection still comes only from the direct checks below. |

### Direct bucket inputs

| Input or field | Affects | Boundary |
| --- | --- | --- |
| Added component membership | `new_package` | A component that exists only in the after input receives `new_package`. This does not mean the package is unsafe. |
| `before.version` and `after.version` on changed components | `major_upgrade` or `version_change_unclassified` | Parseable SemVer major increases receive `major_upgrade`; other before/after version changes receive `version_change_unclassified`. Missing versions do not get a version-change risk bucket. |
| `license_id` on added components and changed-after components | `unknown_license` | Missing, empty, `UNKNOWN`, and `NOASSERTION` license values receive `unknown_license`. The model does not infer license compatibility. |
| `purl` and `source_url` on added components and changed-after components | `suspicious_source` | Missing source provenance, suspicious schemes, local paths, IP hosts, localhost-style hosts, and selected unqualified hosts can receive `suspicious_source`. |
| Source host allowlist passed to risk evaluation | `suspicious_source` only | The allowlist narrows source-host hygiene checks. It is not an approval list for dependency safety. |
| `stale_enrichment_enabled` | `not_evaluated` | When stale enrichment is disabled, the model records `not_evaluated` instead of guessing `stale_package`. When the flag is enabled, that offline placeholder is suppressed. |

Current risk bucket names are:

- `new_package`
- `major_upgrade`
- `version_change_unclassified`
- `unknown_license`
- `stale_package`
- `suspicious_source`
- `not_evaluated`

`stale_package` is reserved for explicit stale-package enrichment. The offline
default does not infer it; it emits `not_evaluated` for that question.

## Context-only fields

These fields can appear in reports, policy explanations, or enrichment
evidence, but they do not directly select a core risk bucket.

| Field or evidence | How to read it |
| --- | --- |
| `name` | Report identity, finding ordering, and diff-signature context. It does not by itself imply risk. |
| `ecosystem` | Package context and identity fallback. It is not treated as ecosystem risk. |
| `supplier` | Report metadata and diff-signature context. It is not treated as maintainer trust. |
| `bom_ref` | Component identity fallback and report context. It is not a security proof. |
| `raw_type` | Parser/report context and diff-signature context. It is not a risk score. |
| `evidence` | Parser-specific supporting data. The current risk classifier does not derive hidden findings from it. |
| `provenance` | Optional evidence used by reporting and policy paths when explicitly enabled. It does not prove dependency safety. |
| `scorecard` | Optional OpenSSF Scorecard evidence used by reporting and policy paths when explicitly enabled. It does not prove repository trustworthiness. |
| Report `metadata`, `notes`, `summary`, and `policy_evaluation` | Output context. They explain what ran and how policy consumed findings; they do not add hidden risk buckets. |

Policy evaluation is a separate layer. A policy may pass, warn, fail, or ask
for consumer-side review based on findings or enrichment evidence, but policy
evaluation does not change what the risk model itself is allowed to infer.

## Never inferred

The model never infers:

- CVE, advisory, exploitability, or vulnerability status
- package safety or unsafe-package verdicts
- malicious intent, maintainer identity, publisher trust, or account ownership
- current PyPI package truth unless an explicit enrichment path produced
  evidence for that run
- current repository reputation from mocked or checked-in example artifacts
- production PyPI release status
- climate, weather, or meteorology portfolio claims for this repository
- hidden network enrichment in the default local path
- license compatibility or legal suitability
- dependency freshness when stale-package enrichment is disabled
- risk severity beyond the emitted bucket name and rationale
- runtime reachability, deployment exposure, production usage, or transitive
  impact

When the model lacks evidence for a question, it should leave the question
unanswered or emit `not_evaluated`; it should not fill the gap with a guess.

## Bucket boundaries

| Bucket | Allowed basis | Not a claim of |
| --- | --- | --- |
| `new_package` | Component appears only in the after input. | Vulnerability, maliciousness, or policy failure. |
| `major_upgrade` | Strict SemVer major version increased. | Breaking change certainty or security risk. |
| `version_change_unclassified` | Version changed but was not a parseable strict SemVer major upgrade. | Minor risk, safe upgrade, or unknown vulnerability state. |
| `unknown_license` | License metadata is missing, empty, `UNKNOWN`, or `NOASSERTION`. | Legal non-compliance or prohibited redistribution. |
| `suspicious_source` | Source provenance is missing or uses a suspicious scheme, host, or local path pattern. | Malware, compromise, or unsafe package content. |
| `not_evaluated` | A check was intentionally not answered, currently stale-package evaluation in offline mode. | Safe, unsafe, stale, or fresh. |
| `stale_package` | Reserved for future explicit stale-package enrichment. | Must not be emitted from missing data or guesswork. |

## Reading the output

`risk_counts` is a count of local heuristic review findings. It is useful for
review triage, policy gating, and SARIF/report summaries. It is not a security
rating and should not be rewritten as a dependency safety verdict.

## Maintenance checklist

Update this document and the focused docs tests when any of these change:

- [`risk.py`](../tools/sbom-diff-and-risk/src/sbom_diff_risk/risk.py)
- [`diffing.py`](../tools/sbom-diff-and-risk/src/sbom_diff_risk/diffing.py)
- [`models.py`](../tools/sbom-diff-and-risk/src/sbom_diff_risk/models.py)
- parser normalization that changes populated `Component` fields
- enrichment behavior that becomes a direct risk-model input
- policy behavior that might be confused with risk bucket generation
