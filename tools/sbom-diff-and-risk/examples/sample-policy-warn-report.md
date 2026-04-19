# sbom-diff-and-risk report

## Summary
- Before format: cyclonedx-json
- After format: cyclonedx-json
- Added: 1
- Removed: 0
- Version changes: 1

## Risk buckets
- new_package: 1
- major_upgrade: 0
- version_change_unclassified: 1
- unknown_license: 0
- stale_package: 0
- suspicious_source: 0
- not_evaluated: 2

## Policy summary
- Applied: yes
- Policy path: examples/policy-minimal.yml
- Exit code: 0
- Blocking findings: 0
- Warnings: 1
- Suppressed findings: 0

## Provenance summary
- Enrichment mode: offline_default
- Network access performed: no
- Candidate components for enrichment: 0
- Supported components for enrichment: 0
- Observed provenance status counts: none
- Components in scope: 2
- PyPI components in scope: 2
- PyPI components without provenance records: 2
- Components with provenance evidence: 0
- Components with attestations: 0
- Components with attestation gaps: 0
- Components with enrichment errors: 0
- Unsupported components: 0

## Attestation gaps
| component | version | statuses |
|-----------|---------|----------|
| _none_ |  |  |

## Policy impact for provenance-related rules
| rule id | component | level | message |
|---------|-----------|-------|---------|
| _none_ |  |  |  |

## Trust signal notes
- PyPI components are present, but provenance enrichment was not enabled for this run.

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
| urllib3 | 2.2.1 | pypi | new_package, not_evaluated |

## Removed components
| name | version | ecosystem |
|------|---------|-----------|
| _none_ |  |  |

## Version changes
| name | before | after | classification | risk buckets |
|------|--------|-------|----------------|--------------|
| requests | 2.31.0 | 2.32.0 | version_changed | not_evaluated, version_change_unclassified |

## Risk findings
| bucket | component | version | rationale |
|--------|-----------|---------|-----------|
| new_package | urllib3 | 2.2.1 | Component was not present in the before input. |
| not_evaluated | requests | 2.32.0 | stale_package was not evaluated because enrichment mode is disabled. |
| not_evaluated | urllib3 | 2.2.1 | stale_package was not evaluated because enrichment mode is disabled. |
| version_change_unclassified | requests | 2.32.0 | Version changed but did not qualify as a parseable SemVer major upgrade. |

## Blocking violations
| rule id | component | level | message |
|---------|-----------|-------|---------|
| _none_ |  |  |  |

## Warnings
| rule id | component | level | message |
|---------|-----------|-------|---------|
| new_package | urllib3 | warn | Component was not present in the before input. |

## Notes
- This tool uses heuristic risk classification.
- No network enrichment was performed.
