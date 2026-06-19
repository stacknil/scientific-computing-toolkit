# Risk model boundary

This document defines the SBR-02 boundary for the SBOM risk model: which inputs
can change risk findings, which inputs are context only, and which conclusions the
tool must never infer.

The current risk model is a deterministic heuristic layer implemented in
`tools/sbom-diff-and-risk/src/sbom_diff_risk/risk.py`. It is not a vulnerability
scanner, malware detector, legal reviewer, or package trust oracle.

## Risk-affecting inputs

Only the following inputs may affect emitted risk buckets.

| Input | Risk effect | Boundary |
| --- | --- | --- |
| Diff category: added component | Emits `new_package`. | The component exists in the after input and not in the before input. This is a change signal only. |
| Diff category: changed component | Enables version, hygiene, and stale-evaluation findings on the after component. | Removed and unchanged components are not evaluated by `evaluate_risks`. |
| `ComponentChange.before.version` and `ComponentChange.after.version` | Emit `major_upgrade` or `version_change_unclassified`. | `major_upgrade` requires both versions to parse as strict SemVer `x.y.z` and the after major version to be higher. If both versions are present and changed but do not qualify, the finding is `version_change_unclassified`. |
| `Component.license_id` | Emits `unknown_license`. | Missing, empty, `UNKNOWN`, and `NOASSERTION` are unknown. Other license strings are not interpreted for compliance or risk severity. |
| `Component.purl` | Participates in `suspicious_source`. | If both `purl` and `source_url` are missing, source provenance is suspicious. If `purl` exists and `source_url` is missing, the source is not suspicious solely for missing `source_url`. |
| `Component.source_url` | Emits `suspicious_source` when the value is missing with no `purl`, local, non-HTTPS, or otherwise suspicious. | Suspicious examples include `http://`, `git+`, `git://`, `ssh://`, `file://`, relative paths, absolute local paths, missing URL host, IP-address hosts, `localhost`, `localdomain`, and `.local` hosts. |
| Source allowlist | Participates in `suspicious_source` for single-label hosts. | The allowlist is not a general denylist. In the current implementation, an unallowlisted host is suspicious only when an allowlist is configured and the host has no dot. |
| `stale_enrichment_enabled` | Controls `not_evaluated` for stale package checks. | When false, the model emits `not_evaluated` instead of guessing staleness. When true, the placeholder finding is suppressed; the current model still does not infer `stale_package`. |

## Context-only inputs

These fields may be useful for display, parsing, reporting, policy evaluation, or
future enrichment, but they do not currently select a risk bucket in the risk
model.

| Input | Current role |
| --- | --- |
| `Component.name` | Report identity and stable finding ordering. It does not by itself imply risk. |
| `Component.ecosystem` | Normalized package context used elsewhere in the toolchain. It does not currently change risk buckets. |
| `Component.supplier` | Context only. The risk model does not infer trust, ownership, or maintainer identity from it. |
| `Component.bom_ref` | SBOM identity context only. |
| `Component.raw_type` | Parser/source context only. |
| `Component.evidence` | Parser evidence context only. |
| `Component.provenance` | Enrichment evidence for reporting or policy layers only. The risk model does not convert provenance availability, attestation availability, or enrichment errors into risk buckets. |
| `Component.scorecard` | Scorecard evidence for reporting or policy layers only. The risk model does not convert score, checks, or repository mapping into risk buckets. |
| `ComponentChange.key` | Finding identity for changed components. It does not decide the bucket. |
| `ComponentChange.classification` | Diff context only. The version values drive version-related risk findings. |
| `ReportEnrichmentMetadata` | Report context only. Network flags, candidate counts, and status counts do not change risk buckets. |

Policy evaluation is a separate layer. A policy may warn, fail, or suppress based
on findings or enrichment evidence, but that does not change what the risk model
itself is allowed to infer.

## Never infer

The risk model must never infer or imply any of the following unless a future,
explicitly documented feature adds a dedicated evidence source and tests.

- A package is vulnerable, exploitable, compromised, malicious, or safe.
- A package has or does not have CVEs, advisories, exploit chains, or reachable
  vulnerable code.
- A package is trustworthy because it has a familiar name, domain, supplier,
  repository, PyPI provenance record, or Scorecard result.
- Missing metadata, missing provenance, missing attestations, or enrichment
  errors prove compromise.
- License compliance, legal acceptability, or redistribution permission beyond
  the narrow `unknown_license` metadata check.
- Maintainer identity, project ownership, organization affiliation, or source
  authenticity from package names, supplier strings, URLs, or repository mapping.
- Runtime reachability, deployment exposure, production usage, or transitive
  impact.
- Package staleness when stale enrichment is disabled. The correct output is
  `not_evaluated`, not an invented stale or fresh conclusion.
- Risk severity beyond the emitted bucket name and rationale.
- Network-derived facts when enrichment has not explicitly performed network
  access.

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

## Maintenance checklist

Update this document and the focused risk tests when any of these change:

- `tools/sbom-diff-and-risk/src/sbom_diff_risk/risk.py`
- `tools/sbom-diff-and-risk/src/sbom_diff_risk/models.py`
- parser normalization that changes the populated `Component` fields
- enrichment behavior that becomes a direct risk-model input
- policy behavior that might be confused with risk-model bucket generation
