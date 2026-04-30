# sbom-diff-and-risk

v0.5.1 is a release-only maintenance update for the GitHub Release checksum manifest path. It keeps CLI analysis behavior unchanged, keeps dependency analysis local and deterministic by default, preserves the completed TestPyPI dry-run story, and keeps production PyPI publishing intentionally deferred.

`sbom-diff-and-risk` is a local, deterministic CLI for comparing two SBOMs or dependency manifests and producing JSON plus Markdown reports.

It uses conservative heuristics for change intelligence. By default it does not resolve CVEs, does not act as a reputation oracle, and does not perform hidden network enrichment.

## Start Here

This project has two different provenance stories:

For a concise reviewer-facing overview, start with [docs/reviewer-brief.md](docs/reviewer-brief.md). For reproducible review evidence and verification commands, use [docs/reviewer-evidence-pack.md](docs/reviewer-evidence-pack.md). For machine-readable JSON output shape, see [docs/report-schema.md](docs/report-schema.md).

1. If you want to verify `sbom-diff-and-risk` itself, start with [docs/verification.md](docs/verification.md).
2. If you want to use `sbom-diff-and-risk` to analyze third-party dependency provenance, start with [Dependency provenance analysis](#dependency-provenance-analysis-opt-in) and [Dependency provenance reporting](#dependency-provenance-reporting).

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
- `--summary-json path`
- `--out-md path`
- `--out-sarif path`
- `--policy path`
- `--fail-on rule[,rule...]`
- `--warn-on rule[,rule...]`
- `--strict`
- `--enrich-pypi`
- `--pypi-timeout seconds`
- `--enrich-scorecard`
- `--scorecard-timeout seconds`
- `--source-allowlist pypi.org,files.pythonhosted.org,github.com`

Offline mode remains the default. No network access occurs unless `--enrich-pypi` or `--enrich-scorecard` is set explicitly.

`--summary-json PATH` writes only the stable `report.json["summary"]` object for compact machine consumption. It uses the same summary schema as the full JSON report.

## Dependency Provenance Analysis (Opt-in)

This section is about analyzing third-party package provenance signals. It is not about verifying the `sbom-diff-and-risk` tool's own release artifacts.

PyPI provenance and integrity enrichment is explicit and additive in this PR:

- only Python / PyPI packages are queried
- no hidden network access occurs in default mode
- enrichment results are captured as evidence and summarized in the reports
- per-component `evidence.provenance` records stable lookup fields such as `supported`, `lookup_performed`, and per-file attestation totals
- lack of attestation is treated as unavailable metadata, not as proof of compromise
- policy evaluation can use these signals explicitly when configured
- SARIF stays conservative and only emits selected high-signal provenance policy violations

When enabled, the tool queries PyPI-facing release metadata plus file-level provenance data and records stable evidence fields under component `evidence.provenance`, along with run metadata under `metadata.enrichment` and the top-level trust-signal report fields in the JSON report.

```bash
sbom-diff-risk compare \
  --before examples/requirements_before.txt \
  --after examples/requirements_after.txt \
  --enrich-pypi \
  --pypi-timeout 3 \
  --out-json outputs/report-enriched.json
```

## Dependency Provenance Reporting

When provenance enrichment is enabled, the reports surface trust signals directly instead of burying them in component evidence:

- JSON includes `provenance_summary`, `attestation_summary`, `enrichment_metadata`, `trust_signal_notes`, and `provenance_policy_impact`
- Markdown includes `Provenance summary`, `Attestation gaps`, `Policy impact for provenance-related rules`, and `Trust signal notes`
- core diff semantics do not change when enrichment is enabled
- SARIF maps only selected high-signal provenance decisions such as `provenance_required`, blocking `missing_attestation`, and blocking `unverified_provenance`
- provenance-related SARIF alerts prefer file-level locations that point to the relevant compared manifest or SBOM input

Routine enrichment outcomes remain JSON and Markdown evidence for review. Non-blocking enrichment facts do not automatically become SARIF alerts.

## Opt-in Scorecard Enrichment

OpenSSF Scorecard enrichment is also explicit and advisory:

- no Scorecard requests are made unless `--enrich-scorecard` is set
- lookups only occur when a component can be mapped to a repository with high confidence from explicit metadata
- repository registry pages and ambiguous URLs are treated as unmapped instead of inferred
- Scorecard results are auxiliary trust signals, not proof of safety
- Scorecard-only SARIF alerts are emitted only when policy explicitly turns a threshold breach into a violation

```bash
sbom-diff-risk compare \
  --before examples/cdx_before.json \
  --after examples/cdx_after.json \
  --enrich-scorecard \
  --scorecard-timeout 3 \
  --out-json outputs/report-scorecard.json
```

If you want policy gating, make it explicit with a v3 policy such as [policy-scorecard-minimal.yml](examples/policy-scorecard-minimal.yml), which sets `minimum_scorecard_score` and opts into the `scorecard_below_threshold` rule.

Setting `minimum_scorecard_score` alone is advisory metadata for review. It only affects policy outcomes when `scorecard_below_threshold` is configured explicitly in `block_on`, `warn_on`, or `ignore_rules`.

## Tool Provenance And Verification

This section is about verifying `sbom-diff-and-risk` itself. If you want the shortest path to the right verification instructions, start with [docs/verification.md](docs/verification.md).

This repository also records provenance for `sbom-diff-and-risk` itself by generating GitHub artifact attestations for the wheel and source distribution produced by the `sbom-diff-and-risk-ci` workflow.

- the attested files are the wheel and source distribution built by `python -m build` from `tools/sbom-diff-and-risk`
- the build files are uploaded together as the `sbom-diff-and-risk-dist` workflow artifact
- version-tag runs also publish those same built files as GitHub Release assets for the matching tag
- releases produced by the updated workflow include `sbom-diff-and-risk-SHA256SUMS.txt` for local SHA256 verification of downloaded wheel and source distribution files
- only trusted non-PR runs publish the attestation
- consumers can verify workflow-built artifacts with `gh attestation verify`
- consumers can verify immutable releases and downloaded release assets with `gh release verify` and `gh release verify-asset`
- this complements the tool's analysis of third-party supply-chain inputs, but it does not replace that analysis

Verification docs:

- [docs/verification.md](docs/verification.md) for the quick decision guide
- [docs/self-provenance.md](docs/self-provenance.md) for workflow-artifact attestation
- [docs/release-provenance.md](docs/release-provenance.md) for release-asset verification and immutable release guidance
- [docs/pypi-trusted-publishing-readiness.md](docs/pypi-trusted-publishing-readiness.md) for TestPyPI Trusted Publishing readiness and dry-run notes
- [docs/pypi-production-publishing-decision.md](docs/pypi-production-publishing-decision.md) for the production PyPI decision gate, publisher identity, future workflow shape, and production prerequisites

## Examples

The [examples/](examples/) directory includes:

- before/after inputs for CycloneDX JSON, SPDX JSON, `requirements.txt`, and `pyproject.toml`
- dependency-group examples at `examples/pyproject_groups_before.toml` and `examples/pyproject_groups_after.toml`
- example policies at `examples/policy-minimal.yml` and `examples/policy-strict.yml`
- provenance-aware policy examples at `examples/policy-provenance-minimal.yml` and `examples/policy-provenance-strict.yml`
- a Scorecard-aware policy example at `examples/policy-scorecard-minimal.yml`
- a sample pass JSON report at [sample-report.json](examples/sample-report.json)
- a sample pass Markdown report at [sample-report.md](examples/sample-report.md)
- sample policy-warn reports at [sample-policy-warn-report.json](examples/sample-policy-warn-report.json) and [sample-policy-warn-report.md](examples/sample-policy-warn-report.md)
- sample policy-fail reports at [sample-policy-fail-report.json](examples/sample-policy-fail-report.json) and [sample-policy-fail-report.md](examples/sample-policy-fail-report.md)
- a sample SARIF export at [sample-sarif.sarif](examples/sample-sarif.sarif)
- provenance-aware sample reports at [sample-provenance-report.json](examples/sample-provenance-report.json), [sample-provenance-report.md](examples/sample-provenance-report.md), and [sample-provenance-report.sarif](examples/sample-provenance-report.sarif)
- Scorecard-aware sample reports at [sample-scorecard-report.json](examples/sample-scorecard-report.json), [sample-scorecard-report.md](examples/sample-scorecard-report.md), and [sample-scorecard-report.sarif](examples/sample-scorecard-report.sarif)
- requirements-based sample reports at [sample-requirements-report.json](examples/sample-requirements-report.json) and [sample-requirements-report.md](examples/sample-requirements-report.md)

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
- selected policy results such as `max_added_packages`, `allow_sources`, `provenance_required`, and blocking provenance violations like `missing_attestation` or `unverified_provenance`
- explicit Scorecard policy violations such as `scorecard_below_threshold`

It does not turn every enrichment fact, diff, or informational heuristic into a code scanning alert.

```bash
sbom-diff-risk compare \
  --before examples/sarif_before.json \
  --after examples/sarif_after.json \
  --policy examples/policy-strict.yml \
  --out-sarif outputs/report.sarif
```

For GitHub code scanning integration guidance and a minimal upload workflow, see [docs/github-code-scanning.md](docs/github-code-scanning.md).

For the shortest path to the tool-verification docs, start with [docs/verification.md](docs/verification.md).

For details on how this repository attests the tool's own wheel and source distribution artifacts, see [docs/self-provenance.md](docs/self-provenance.md).

For details on how version-tag releases publish those same build outputs as release assets, and how consumers can verify immutable releases with GitHub CLI, see [docs/release-provenance.md](docs/release-provenance.md).

For TestPyPI Trusted Publishing readiness and the completed dry-run path, see [docs/pypi-trusted-publishing-readiness.md](docs/pypi-trusted-publishing-readiness.md).

For the production PyPI decision gate, including the intended package name, first-version rule, publisher identity, future workflow shape, and provenance boundaries, see [docs/pypi-production-publishing-decision.md](docs/pypi-production-publishing-decision.md).

## Parser Boundaries

Deterministic local mode intentionally supports a conservative subset of packaging syntax. The detailed matrix lives in [docs/parser-boundaries.md](docs/parser-boundaries.md).

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
- PyPI provenance enrichment is opt-in only via `--enrich-pypi`; default runs stay offline.
- `generated_at` remains `null` to preserve deterministic report output.
- `stale_package` is not resolved offline. The report emits `not_evaluated` instead.
- provenance evidence is recorded for supported PyPI packages only; unsupported and failed lookups remain explicit evidence gaps.
- SARIF export intentionally covers only a conservative subset of findings in v0.2, including only selected high-signal provenance policy violations.
- Scorecard enrichment is opt-in only via `--enrich-scorecard`, uses only high-confidence repository mappings, and remains advisory unless policy explicitly gates it.
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
