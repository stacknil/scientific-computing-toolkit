# Input format support matrix and parser boundaries

`sbom-diff-and-risk` intentionally supports a conservative parser subset so local runs remain deterministic, auditable, and CI-friendly.

The project does not try to emulate a package installer. When syntax would require resolver behavior, implicit includes, index lookups, or environment-specific side effects, the parser fails closed with an explicit error.

## Support matrix

Every row below describes parser behavior implemented and covered by tests. A
recognized container format does not imply full specification conformance.

| Input | CLI format | Implemented subset | Not claimed |
| --- | --- | --- | --- |
| CycloneDX JSON | `cyclonedx-json` | Top-level `components`; component name, version, purl, bom-ref, type, first usable license, supplier/author, and selected external-reference URLs | CycloneDX schema validation, dependency graphs, services, vulnerabilities, compositions, or recursive nested components |
| SPDX JSON | `spdx-json` | Top-level `packages`; package name, versionInfo, SPDXID, primary purpose, declared/concluded license, supplier/originator, purl external reference, and selected source URLs | SPDX schema validation, relationship graphs, files, snippets, annotations, or license analysis |
| requirements file | `requirements-txt` | The PEP 508 requirement subset listed below, with comments and deterministic line continuation | pip installation semantics, includes, constraints, index configuration, hashes, URLs, VCS references, archives, or local paths |
| `pyproject.toml` | `pyproject-toml` | PEP 621 dependency arrays and explicitly selected PEP 735 dependency groups, including local group includes | A general Python lockfile/parser, build backend interpretation, or Poetry/Hatch/PDM tool-specific tables |

No XML SBOM, SPDX tag-value, YAML SBOM, package-lock, poetry.lock, uv.lock,
or other lockfile parser is currently registered. Such formats are unsupported,
not silently treated as one of the rows above.

## CycloneDX JSON

The parser requires a top-level JSON object with `bomFormat: CycloneDX`. It
reads only the top-level `components` array. Each component requires `name`;
all other normalized fields are optional.

The parser does not currently constrain `specVersion` or validate the document
against a CycloneDX schema. Acceptance therefore means the implemented fields
were readable, not that the entire document is CycloneDX-conformant.

## SPDX JSON

The parser requires a top-level JSON object with a string `spdxVersion` and
reads only the top-level `packages` array. Each package requires `name`.

The parser does not currently constrain the SPDX version or validate the
document against an SPDX schema. Relationships and file-level data do not
affect component identity or policy decisions.

## Component identity validation

After parsing, purl-bearing components are canonicalized before diff indexing.
The purl type, name, and version must agree with the corresponding explicit
component fields. Invalid or conflicting identity metadata fails closed as
`conflicting_metadata`; repeated identical records fail as
`duplicate_component`. See
[component-identity-canonicalization.md](component-identity-canonicalization.md)
for the ecosystem-specific canonicalization matrix and
[v1.1-input-and-policy-semantics.md](v1.1-input-and-policy-semantics.md) for the
typed identity contract.

## Requirements files

`requirements.txt` is treated as a narrow manifest format, not as "everything pip can do in a file".

| Syntax | Status | Notes |
| --- | --- | --- |
| Plain PEP 508 names and version specifiers | Supported | Example: `requests==2.31.0` |
| Extras and markers | Supported | Example: `pytest[testing]>=8.0 ; python_version >= "3.11"` |
| Comments and blank lines | Supported | Stripped before parsing |
| Line continuations | Supported | Continued lines are joined deterministically |
| `-r`, `--requirement` | Unsupported | Include chains are rejected |
| `-c`, `--constraint` | Unsupported | Constraint files are rejected |
| `-e`, `--editable` | Unsupported | Editable installs are rejected |
| Direct URL, VCS, or local path references | Unsupported | Includes `pkg @ https://...`, `git+...`, `file://...`, wheels, and local archives |
| Index and source options | Unsupported | Includes `--index-url`, `--extra-index-url`, `--find-links`, `--trusted-host`, `--no-index` |
| Other pip-only install flags | Unsupported | Includes hash flags, binary toggles, prerelease flags, and related installer controls |

When unsupported syntax appears, the parser raises `UnsupportedInputError` and the CLI returns exit code `2`.

## `pyproject.toml`

`pyproject.toml` support is also intentionally narrow:

| Section | Status | Notes |
| --- | --- | --- |
| `[project]` `dependencies` | Supported | Parsed by default as a PEP 508 string array |
| `[project.optional-dependencies]` | Supported | Every declared optional group is parsed by default and kept distinct from dependency groups |
| `[dependency-groups]` | Supported | Requires explicit `--pyproject-group <name>` selection |
| `{ include-group = "name" }` inside dependency groups | Supported | Includes are resolved locally and deterministically |
| PEP 508 direct references in supported arrays | Supported | Recorded as local manifest evidence; no URL is fetched by the parser |
| Missing requested dependency group | Explicit error | Reported as `InputSelectionError` |
| Poetry, Hatch, PDM, or other tool-specific dependency sections | Unsupported | Not parsed |

Dependency groups are not merged automatically with `[project.optional-dependencies]`. They solve different problems and are kept separate on purpose.

## Error taxonomy

The parser uses explicit error classes so CI logs are understandable:

- `MalformedInputError`: the file is syntactically malformed.
- `UnsupportedInputError`: the file is valid enough to read, but deterministic mode intentionally does not support the construct.
- `InputSelectionError`: the user asked for a parser selection the input cannot satisfy, such as a missing dependency group.

The CLI maps these parser failures to exit code `2`.
