# sbom-diff-and-risk report

## Summary
- Before format: requirements-txt
- After format: requirements-txt
- Added: 1
- Removed: 0
- Version changes: 1

## Risk buckets
- new_package: 1
- major_upgrade: 0
- version_change_unclassified: 1
- unknown_license: 2
- stale_package: 0
- suspicious_source: 0
- not_evaluated: 2

## Added components
| name | version | ecosystem | risk buckets |
|------|---------|-----------|--------------|
| urllib3 | 2.2.1 | pypi | new_package, not_evaluated, unknown_license |

## Removed components
| name | version | ecosystem |
|------|---------|-----------|
| _none_ |  |  |

## Version changes
| name | before | after | classification | risk buckets |
|------|--------|-------|----------------|--------------|
| requests | 2.31.0 | 2.32.0 | version_changed | not_evaluated, unknown_license, version_change_unclassified |

## Risk findings
| bucket | component | version | rationale |
|--------|-----------|---------|-----------|
| new_package | urllib3 | 2.2.1 | Component was not present in the before input. |
| not_evaluated | requests | 2.32.0 | stale_package was not evaluated because enrichment mode is disabled. |
| not_evaluated | urllib3 | 2.2.1 | stale_package was not evaluated because enrichment mode is disabled. |
| unknown_license | requests | 2.32.0 | License is missing, empty, UNKNOWN, or NOASSERTION. |
| unknown_license | urllib3 | 2.2.1 | License is missing, empty, UNKNOWN, or NOASSERTION. |
| version_change_unclassified | requests | 2.32.0 | Version changed but did not qualify as a parseable SemVer major upgrade. |

## Notes
- This tool uses heuristic risk classification.
- No network enrichment was performed.
