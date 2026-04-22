# sbom-diff-and-risk

`sbom-diff-and-risk` is a local, deterministic CLI for comparing two SBOMs or dependency manifests and producing review-friendly reports.

It is designed for conservative supply-chain review workflows:

- compare `before` and `after` dependency inventories
- identify added, removed, and changed components
- apply heuristic risk buckets to new and changed dependencies
- emit JSON, Markdown, and SARIF outputs
- keep default runs local-file based and deterministic

## Supported inputs

- CycloneDX JSON
- SPDX JSON
- `requirements.txt`
- `pyproject.toml` via PEP 621 `[project]` metadata
- `pyproject.toml` dependency groups via PEP 735 `[dependency-groups]`

## Output formats

- `report.json`
- `report.md`
- `report.sarif`

## Install

```bash
python -m pip install sbom-diff-and-risk
```

## Quick start

```bash
sbom-diff-risk compare \
  --before before.sbom.json \
  --after after.sbom.json \
  --format auto \
  --out-json report.json \
  --out-md report.md
```

## Defaults and scope

- default operation is local and deterministic
- no hidden network access occurs unless enrichment is enabled explicitly
- no CVE or vulnerability database integration is performed
- risk buckets are heuristic review signals, not security verdicts

Optional enrichment can be enabled explicitly for:

- PyPI provenance and integrity signals
- OpenSSF Scorecard signals

## Typical use cases

- compare two release SBOMs during code review
- review dependency manifest changes in CI
- produce machine-readable and reviewer-readable change reports
- add conservative policy gates around dependency changes
