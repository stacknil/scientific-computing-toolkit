# sbom-diff-and-risk report

## Summary
- Before format: requirements-txt
- After format: requirements-txt
- Added: 2
- Removed: 0
- Version changes: 1

## Risk buckets
- new_package: 2
- major_upgrade: 0
- version_change_unclassified: 1
- unknown_license: 0
- stale_package: 0
- suspicious_source: 0
- not_evaluated: 0

## Policy summary
- Applied: yes
- Policy path: examples/policy-provenance-strict.yml
- Exit code: 1
- Blocking findings: 2
- Warnings: 1
- Suppressed findings: 0

## Provenance summary
- Enrichment mode: opt_in_pypi
- Network access performed: yes
- Candidate components for enrichment: 3
- Supported components for enrichment: 3
- Observed provenance status counts: attestation_available=2, attestation_unavailable=1, provenance_available=2
- Components in scope: 3
- PyPI components in scope: 3
- PyPI components without provenance records: 0
- Components with provenance evidence: 2
- Components with attestations: 2
- Components with attestation gaps: 1
- Components with enrichment errors: 0
- Unsupported components: 0

## Attestation gaps
| component | version | statuses |
|-----------|---------|----------|
| mystery-lib | 1.0.0 | attestation_unavailable |

## Policy impact for provenance-related rules
- Configured provenance policy: yes
- Require attestations for new packages: yes
- Require provenance for suspicious sources: no
- Allow unattested packages: none
- Allowed provenance publishers: github actions
- Provenance policy decisions: blocking=2, warning=1, suppressed=0
| rule id | component | level | message |
|---------|-----------|-------|---------|
| provenance_required | mystery-lib | block | Provenance is required for new package, but no attestations were published for this PyPI package. |
| unverified_provenance | legacy-lib | block | PyPI attestations were present, but publisher kinds manual upload did not match allow_provenance_publishers=github actions. |
| missing_attestation | mystery-lib | warn | PyPI release metadata was fetched, but no attestations were published for this package release. |

## Trust signal notes
- Missing attestations indicate an attestation gap for the release; they are not treated as proof of compromise.
- Observed attestation publisher kinds: github actions, manual upload.
- Policy produced 3 provenance-related blocking or warning decision(s).

## Scorecard summary
- Enrichment enabled: no
- Network access performed: no
- Candidate components for Scorecard enrichment: 0
- Components with supported repository mappings: 0
- Components with mapped repositories: 0
- Components with available Scorecards: 0
- Scorecard unavailable: 0
- Repository unmapped: 0
- Components with enrichment errors: 0
- Observed Scorecard status counts: none

## Scorecard results
| component | version | repository | score | status |
|-----------|---------|------------|-------|--------|
| _none_ |  |  |  |  |

## Policy impact for Scorecard-related rules
| rule id | component | level | message |
|---------|-----------|-------|---------|
| _none_ |  |  |  |

## Added components
| name | version | ecosystem | risk buckets |
|------|---------|-----------|--------------|
| urllib3 | 2.2.1 | pypi | new_package |
| mystery-lib | 1.0.0 | pypi | new_package |

## Removed components
| name | version | ecosystem |
|------|---------|-----------|
| _none_ |  |  |

## Version changes
| name | before | after | classification | risk buckets |
|------|--------|-------|----------------|--------------|
| legacy-lib | 1.0.0 | 1.1.0 | version_changed | version_change_unclassified |

## Risk findings
| bucket | component | version | rationale |
|--------|-----------|---------|-----------|
| new_package | urllib3 | 2.2.1 | Component was not present in the before input. |
| new_package | mystery-lib | 1.0.0 | Component was not present in the before input. |
| version_change_unclassified | legacy-lib | 1.1.0 | Version changed but did not qualify as a parseable SemVer major upgrade. |

## Blocking violations
| rule id | component | level | message |
|---------|-----------|-------|---------|
| provenance_required | mystery-lib | block | Provenance is required for new package, but no attestations were published for this PyPI package. |
| unverified_provenance | legacy-lib | block | PyPI attestations were present, but publisher kinds manual upload did not match allow_provenance_publishers=github actions. |

## Warnings
| rule id | component | level | message |
|---------|-----------|-------|---------|
| missing_attestation | mystery-lib | warn | PyPI release metadata was fetched, but no attestations were published for this package release. |

## Notes
- This tool uses heuristic risk classification.
- PyPI provenance enrichment was requested explicitly.
