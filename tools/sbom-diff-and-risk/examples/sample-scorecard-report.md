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
- version_change_unclassified: 0
- unknown_license: 0
- stale_package: 0
- suspicious_source: 0
- not_evaluated: 0

## Policy summary
- Applied: yes
- Policy path: examples/policy-scorecard-minimal.yml
- Exit code: 0
- Blocking findings: 0
- Warnings: 1
- Suppressed findings: 0

## Provenance summary
- Enrichment mode: opt_in_scorecard
- Network access performed: no
- Candidate components for enrichment: 0
- Supported components for enrichment: 0
- Observed provenance status counts: none
- Components in scope: 3
- PyPI components in scope: 3
- PyPI components without provenance records: 3
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
- OpenSSF Scorecard results are auxiliary trust signals and are not proof of safety.
- Scorecard lookups are skipped when no high-confidence repository mapping is available.
- Policy produced 1 Scorecard-related blocking or warning decision(s).

## Scorecard summary
- Enrichment enabled: yes
- Network access performed: yes
- Candidate components for Scorecard enrichment: 3
- Components with supported repository mappings: 2
- Components with mapped repositories: 2
- Components with available Scorecards: 2
- Scorecard unavailable: 0
- Repository unmapped: 1
- Components with enrichment errors: 0
- Observed Scorecard status counts: repository_unmapped=1, scorecard_available=2

## Scorecard results
| component | version | repository | score | status |
|-----------|---------|------------|-------|--------|
| requests | 2.32.0 | github.com/psf/requests | 6.0 | scorecard_available |
| urllib3 | 2.2.1 |  |  | repository_unmapped |
| certifi | 2026.1.1 | github.com/certifi/python-certifi | 8.4 | scorecard_available |

## Policy impact for Scorecard-related rules
| rule id | component | level | message |
|---------|-----------|-------|---------|
| scorecard_below_threshold | requests | warn | Scorecard score 6.0 is below minimum_scorecard_score=7.0 for repository github.com/psf/requests. |

## Added components
| name | version | ecosystem | risk buckets |
|------|---------|-----------|--------------|
| requests | 2.32.0 | pypi | new_package |
| urllib3 | 2.2.1 | pypi | new_package |

## Removed components
| name | version | ecosystem |
|------|---------|-----------|
| _none_ |  |  |

## Version changes
| name | before | after | classification | risk buckets |
|------|--------|-------|----------------|--------------|
| certifi | 2025.1.0 | 2026.1.1 | version_changed |  |

## Risk findings
| bucket | component | version | rationale |
|--------|-----------|---------|-----------|
| new_package | requests | 2.32.0 | Component was not present in the before input. |
| new_package | urllib3 | 2.2.1 | Component was not present in the before input. |

## Blocking violations
| rule id | component | level | message |
|---------|-----------|-------|---------|
| _none_ |  |  |  |

## Warnings
| rule id | component | level | message |
|---------|-----------|-------|---------|
| scorecard_below_threshold | requests | warn | Scorecard score 6.0 is below minimum_scorecard_score=7.0 for repository github.com/psf/requests. |

## Notes
- This tool uses heuristic risk classification.
- OpenSSF Scorecard enrichment was requested explicitly.
