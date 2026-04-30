# SBOM basics

This project treats SBOMs as one possible source of dependency inventory data.

For v0.2, the tool is intentionally limited to local-file parsing, normalization, diffing, and conservative heuristic reporting.

## Supported local inputs

- CycloneDX JSON
- SPDX JSON
- `requirements.txt`
- `pyproject.toml`

## Intentional parser boundaries

`requirements.txt` support is intentionally conservative in v0.1:

- supported: plain PEP 508 requirement entries
- supported: comments and blank lines
- supported: line continuations
- not supported: `-r`, `--requirement`, `-c`, `--constraint`, editable installs, direct URL/path refs, or pip index/options

`pyproject.toml` support is intentionally conservative in v0.2:

- supported: PEP 621 `[project.dependencies]`
- supported: PEP 621 `[project.optional-dependencies]`
- supported: PEP 735 `[dependency-groups]` with explicit `--pyproject-group` selection
- not supported: Poetry, Hatch, PDM, or other tool-specific dependency sections

These boundaries are deliberate so the tool can stay deterministic and explicit about what it does and does not parse.

For the detailed supported/unsupported matrix, see [parser-boundaries.md](parser-boundaries.md).

## Normalization goals

- keep one internal `Component` model
- preserve source evidence for auditability
- prefer purl identity when available
- stay deterministic and local-file based

## Diff identity precedence

1. `purl`
2. `bom_ref`
3. `(ecosystem, name)`

When a purl includes a version, the full purl is retained for auditability, but the diff identity uses the versionless package coordinate so upgrades still classify as `changed`.

## Outputs

- `report.json` for machine consumption
- `report.md` for human review

## What this tool is not

- not a vulnerability scanner
- not a package resolver
- not a provenance verifier
- not a web service
