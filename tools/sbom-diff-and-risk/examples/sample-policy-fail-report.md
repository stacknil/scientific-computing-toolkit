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
- Policy path: examples/policy-strict.yml
- Exit code: 1
- Blocking findings: 3
- Warnings: 1
- Suppressed findings: 0

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
| max_added_packages |  | block | Added package count 1 exceeds max_added_packages=0. |
| stale_package | requests | block | stale_package was not evaluated because enrichment mode is disabled. |
| stale_package | urllib3 | block | stale_package was not evaluated because enrichment mode is disabled. |

## Warnings
| rule id | component | level | message |
|---------|-----------|-------|---------|
| new_package | urllib3 | warn | Component was not present in the before input. |

## Notes
- This tool uses heuristic risk classification.
- No network enrichment was performed.
