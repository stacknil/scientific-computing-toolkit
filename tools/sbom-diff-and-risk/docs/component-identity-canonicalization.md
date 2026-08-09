# Component identity canonicalization matrix

`sbom-diff-and-risk` uses an explicit ecosystem matrix before it aligns
components across inputs. The matrix is intentionally narrow: the tool does
not apply a universal lowercase rule and does not infer package-manager
equivalence beyond the rows below.

The executable rule set lives in `sbom_diff_risk.component_identity` as
`canonicalization_rules()`.

## Matrix

| Ecosystem | Package name rule | Namespace rule | Version rule | Boundary |
| --- | --- | --- | --- | --- |
| `pypi` | `pep503`: trim, lowercase, and collapse `-`, `_`, and `.` name runs through `packaging.utils.canonicalize_name` | Preserve any parsed purl namespace; do not invent one | Preserve the observed version string after trimming | Does not resolve Python extras, environment markers, indexes, or package availability |
| `maven` | `preserve-observed`: trim only | Preserve the parsed purl namespace in `component_key` | Preserve the observed version string after trimming | Does not validate Maven group/artifact naming rules or registry identity |
| `npm` | `packageurl-npm-name`: trim and lowercase the package name to match the `packageurl-python` npm purl name form | Preserve the parsed purl namespace, including scope-like namespaces when present | Preserve the observed version string after trimming | Does not query the npm registry or infer scoped package aliases |
| `nuget` | `preserve-observed`: trim only | Preserve the parsed purl namespace | Preserve the observed version string after trimming | Does not apply NuGet registry lookup or package ID equivalence |
| `generic` | `preserve-observed`: trim only | Preserve the parsed purl namespace | Preserve the observed version string after trimming | No package-manager semantics are inferred |
| unknown ecosystem | `preserve-observed`: trim only | Preserve the parsed purl namespace | Preserve the observed version string after trimming | Treated as a local coordinate, not as a supported package-manager model |

The ecosystem identifier itself is always trimmed and lowercased so purl type
comparison stays deterministic. That rule does not imply package-name
lowercasing.

## Identity precedence

Identity authority remains:

1. purl package coordinate, without version;
2. `bom_ref`, when no purl is present;
3. normalized `(ecosystem, package_name)` coordinate.

When no purl is present, `bom_ref` is an opaque local identifier: trim
surrounding whitespace only, preserve case, and do not infer aliases. A record
with a purl uses the purl identity even when `bom_ref` is also populated; a
bom_ref-only record never aliases a purl string.

When a purl is present, its type, package name, and version must agree with
explicit component fields. Disagreement fails closed as `conflicting_metadata`.
Within a single input, repeated identical canonical identities fail as
`duplicate_component`; repeated identities with different normalized metadata
fail as `conflicting_metadata`.

## Non-claims

This matrix is a deterministic comparison contract, not a resolver:

- it does not query package registries;
- it does not decide whether two ecosystem-specific coordinates are aliases;
- it does not rewrite versions into semantic-version equivalents;
- it does not make safety, malware, or CVE claims.
