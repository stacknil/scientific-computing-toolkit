# sbom-diff-and-risk

`sbom-diff-and-risk` is a local, deterministic CLI for comparing two SBOMs or dependency manifests and producing JSON plus Markdown reports.

It uses conservative heuristics for change intelligence. By default it does not resolve CVEs, does not act as a reputation oracle, and does not perform hidden network enrichment.

## Scope

- Normalize two local inputs into a shared component schema.
- Diff components as `added`, `removed`, and `changed`.
- Apply conservative, heuristic risk buckets to newly added and changed components.
- Apply optional local policy enforcement over those findings.
- Produce machine-friendly JSON and reviewer-friendly Markdown reports.
- Stay fully local-file based by default.

## v0.1 Internal Component Model

The normalized schema is the core design choice for the project:

- `name: str`
- `version: str | None`
- `ecosystem: str`
- `purl: str | None`
- `license_id: str | None`
- `supplier: str | None`
- `source_url: str | None`
- `bom_ref: str | None`
- `raw_type: str | None`
- `evidence: dict`

Diff identity is intentionally conservative and uses this precedence:

1. `purl`
2. `bom_ref`
3. `(ecosystem, name)`

When a `purl` includes a version, the tool keeps the full value in `Component.purl` for auditability but uses the versionless package coordinate for identity so upgrades still diff as `changed`.

## Non-goals

- No vulnerability database integration in v0.1.
- No CVE, advisory, or exploit resolution in v0.1.
- No reputation scoring or malware verdicts.
- No hidden enrichment or implicit network access.
- No web UI.
- No packaged GitHub Marketplace Action.

## Supported Formats

- CycloneDX JSON
- SPDX JSON
- `requirements.txt`
- `pyproject.toml` via PEP 621 `[project]` metadata
- `pyproject.toml` dependency groups via PEP 735 `[dependency-groups]` with explicit selection

## Risk Bucket Semantics

The current heuristic buckets are:

- `new_package`
- `major_upgrade`
- `version_change_unclassified`
- `unknown_license`
- `stale_package`
- `suspicious_source`
- `not_evaluated`

Offline `stale_package` evaluation is intentionally deferred. When enrichment is disabled, the tool emits `not_evaluated` findings instead of guessing.

## Output Formats

- `report.json`
- `report.md`
- `report.sarif`

## Install

```bash
python -m pip install -e .[dev]
```

## Usage

Generate reports from the bundled CycloneDX example inputs:

```bash
sbom-diff-risk compare \
  --before examples/cdx_before.json \
  --after examples/cdx_after.json \
  --format auto \
  --out-json outputs/report.json \
  --out-md outputs/report.md
```

Generate reports from the `requirements.txt` examples:

```bash
sbom-diff-risk compare \
  --before examples/requirements_before.txt \
  --after examples/requirements_after.txt \
  --format auto \
  --out-json outputs/requirements-report.json \
  --out-md outputs/requirements-report.md
```

Use explicit format flags when you do not want auto-detection:

```bash
sbom-diff-risk compare \
  --before examples/spdx_before.json \
  --after examples/spdx_after.json \
  --before-format spdx-json \
  --after-format spdx-json \
  --out-json outputs/spdx-report.json \
  --out-md outputs/spdx-report.md
```

Generate reports from PEP 621 `pyproject.toml` examples:

```bash
sbom-diff-risk compare \
  --before examples/pyproject_before.toml \
  --after examples/pyproject_after.toml \
  --format auto \
  --out-json outputs/pyproject-report.json \
  --out-md outputs/pyproject-report.md
```

Generate reports for a specific PEP 735 dependency group:

```bash
sbom-diff-risk compare \
  --before examples/pyproject_groups_before.toml \
  --after examples/pyproject_groups_after.toml \
  --format pyproject-toml \
  --pyproject-group dev \
  --out-json outputs/pyproject-groups-report.json \
  --out-md outputs/pyproject-groups-report.md
```

## CLI Flags

- `--before path`
- `--after path`
- `--format auto|cyclonedx-json|spdx-json|requirements-txt|pyproject-toml`
- `--before-format cyclonedx-json|spdx-json|requirements-txt|pyproject-toml`
- `--after-format cyclonedx-json|spdx-json|requirements-txt|pyproject-toml`
- `--pyproject-group name`
- `--out-json path`
- `--out-md path`
- `--out-sarif path`
- `--policy path`
- `--fail-on rule[,rule...]`
- `--warn-on rule[,rule...]`
- `--strict`
- `--enrich-pypi`
- `--source-allowlist pypi.org,files.pythonhosted.org,github.com`

`--enrich-pypi` is reserved for future work and currently returns a clear error.

## Examples

The [examples/](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/examples) directory includes:

- before/after inputs for CycloneDX JSON, SPDX JSON, `requirements.txt`, and `pyproject.toml`
- dependency-group examples at `examples/pyproject_groups_before.toml` and `examples/pyproject_groups_after.toml`
- example policies at `examples/policy-minimal.yml` and `examples/policy-strict.yml`
- a sample pass JSON report at [sample-report.json](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/examples/sample-report.json)
- a sample pass Markdown report at [sample-report.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/examples/sample-report.md)
- sample policy-warn reports at [sample-policy-warn-report.json](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/examples/sample-policy-warn-report.json) and [sample-policy-warn-report.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/examples/sample-policy-warn-report.md)
- sample policy-fail reports at [sample-policy-fail-report.json](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/examples/sample-policy-fail-report.json) and [sample-policy-fail-report.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/examples/sample-policy-fail-report.md)
- a sample SARIF export at [sample-sarif.sarif](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/examples/sample-sarif.sarif)
- requirements-based sample reports at [sample-requirements-report.json](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/examples/sample-requirements-report.json) and [sample-requirements-report.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/examples/sample-requirements-report.md)

## Enforcement Mode

Policy enforcement is optional and deterministic. Exit codes are stable:

- `0` = success / no blocking violations
- `1` = blocking policy violations
- `2` = usage, parse, policy, or runtime error

Minimal policy enforcement example:

```bash
sbom-diff-risk compare \
  --before examples/requirements_before.txt \
  --after examples/requirements_after.txt \
  --policy examples/policy-minimal.yml \
  --out-json outputs/report.json \
  --out-md outputs/report.md
```

Ad hoc enforcement without a policy file:

```bash
sbom-diff-risk compare \
  --before examples/cdx_before.json \
  --after examples/cdx_after.json \
  --fail-on suspicious_source,unknown_license \
  --warn-on new_package \
  --out-json outputs/report.json \
  --out-md outputs/report.md
```

Failed runs still write reports on exit code `1`; stderr prints a concise blocking summary so CI logs are understandable without opening raw JSON.

## SARIF Export

SARIF export is intentionally conservative. The current renderer emits a GitHub-compatible SARIF 2.1.0 subset for:

- `suspicious_source`
- `unknown_license`
- `major_upgrade`
- selected blocking policy results such as `max_added_packages` and `allow_sources`

It does not turn every diff or informational heuristic into a code scanning alert.

```bash
sbom-diff-risk compare \
  --before examples/sarif_before.json \
  --after examples/sarif_after.json \
  --policy examples/policy-strict.yml \
  --out-sarif outputs/report.sarif
```

For GitHub code scanning integration guidance and a minimal upload workflow, see [docs/github-code-scanning.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/github-code-scanning.md).

## Parser Boundaries

Deterministic local mode intentionally supports a conservative subset of packaging syntax. The detailed matrix lives in [docs/parser-boundaries.md](D:/OneDrive/Code/scientific-computing-toolkit/tools/sbom-diff-and-risk/docs/parser-boundaries.md).

### requirements.txt subset

| Syntax | Status | Notes |
| --- | --- | --- |
| Plain PEP 508 requirement entries | Supported | Names, specifiers, extras, and markers |
| Comments, blank lines, line continuations | Supported | Normalized locally without installer behavior |
| `-r`, `--requirement` | Unsupported | Include chains fail closed |
| `-c`, `--constraint` | Unsupported | Constraint files fail closed |
| Editable installs | Unsupported | `-e` and `--editable` are rejected |
| Direct URL, VCS, and local path refs | Unsupported | Includes `pkg @ https://...`, `git+...`, wheels, archives, and local paths |
| Index and source options | Unsupported | Includes `--index-url`, `--extra-index-url`, `--find-links`, and related flags |

### pyproject.toml subset

- default parsing supports PEP 621 `[project.dependencies]` and `[project.optional-dependencies]`
- dependency groups are supported through PEP 735 `[dependency-groups]`
- dependency groups must be selected explicitly with `--pyproject-group <name>`
- dependency groups are not treated as aliases for `[project.optional-dependencies]`
- tool-specific layouts such as Poetry, Hatch, and PDM remain out of scope in v0.2

## Limitations

- default mode is local-file based only.
- `generated_at` remains `null` to preserve deterministic report output.
- `stale_package` is not resolved offline. The report emits `not_evaluated` instead.
- SARIF export intentionally covers only a conservative subset of findings in v0.2.
- No vulnerability database integration, CVE matching, or advisory enrichment.
- `requirements.txt` support intentionally covers a conservative subset: plain PEP 508 requirement entries, comments, extras, markers, and line continuations.
- `requirements.txt` intentionally rejects include/constraint directives, editable installs, direct URL/path refs, index/source options, and other pip-only install flags in deterministic mode.
- `pyproject.toml` support intentionally covers a conservative subset: PEP 621 `[project.dependencies]`, `[project.optional-dependencies]`, and explicit PEP 735 `[dependency-groups]` selection.
- `pyproject.toml` intentionally does not support tool-specific layouts such as Poetry, Hatch, or PDM sections in v0.2.
- Risk buckets are heuristics, not security verdicts.
- Runtime-generated `outputs/` artifacts are ignored; tracked examples live in `examples/`.
- Policy files are YAML-only in v0.2 and unknown rule ids fail closed.

## Current Status

The project now normalizes local CycloneDX JSON, SPDX JSON, `requirements.txt`, and conservative `pyproject.toml` inputs, including explicit PEP 735 dependency-group selection, into the shared component model, diffs them deterministically, and generates stable JSON/Markdown/SARIF reports with tests and optional policy enforcement.
