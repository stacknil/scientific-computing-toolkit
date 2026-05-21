# Precipitation Anomaly Diagnostics

A compact spatiotemporal diagnostics module for reproducible precipitation
anomaly analysis.

Repository role:
This is the compact reviewer-facing precipitation diagnostics mini-lab. It is a
supporting scientific-data project inside `scientific-computing-toolkit`, not
part of the `sbom-diff-and-risk` release surface and not a separate meteorology
portfolio.

This project demonstrates how to turn gridded scientific data into a
reviewable analysis workflow:

- preprocessing and quality-preserving subsetting;
- climatology, anomaly, and standardized-index construction;
- dimensionality reduction with EOF analysis;
- representative-period selection from standardized time coefficients;
- composite analysis for contrasting phases;
- reviewable figures and lightweight Markdown reports.

The repository is designed as a reproducible research mini-lab, not as an
operational forecast system. Domain-specific choices such as the target month,
region, and variables are documented as configurable analysis context rather
than as the public identity of the project.

## Repository Layout

```text
.
├─ assets/sanitized-figures/       # derived, metadata-stripped demonstration figures
├─ configs/example.yaml            # placeholder local data paths and analysis settings
├─ docs/
│  ├─ data-policy.md
│  ├─ inference-framework.md
│  ├─ methodology.md
│  └─ reproducibility.md
├─ examples/
│  ├─ regional_precipitation_summary_1961_2022.csv
│  └─ sample_metadata.json
├─ PUBLICATION_BOUNDARIES.md
├─ reports/example-report.md
├─ scripts/
│  ├─ run_composite_analysis.py
│  ├─ run_eof_analysis.py
│  └─ run_preprocessing.py
└─ src/climate_diagnostics/
   ├─ composite.py
   ├─ config.py
   ├─ eof.py
   ├─ plotting.py
   └─ preprocess.py
```

## Reviewer Path

1. Read [`docs/data-policy.md`](docs/data-policy.md) for public data boundaries.
2. Read [`PUBLICATION_BOUNDARIES.md`](PUBLICATION_BOUNDARIES.md) for identity and publication boundaries.
3. Read [`docs/methodology.md`](docs/methodology.md) for the analysis workflow.
4. Read [`docs/inference-framework.md`](docs/inference-framework.md) for the reasoning chain.
5. Skim [`reports/example-report.md`](reports/example-report.md) for the public-facing output.
6. Inspect [`tests/`](tests/) for synthetic-data behavior checks.

## Installation

Use Python 3.10+.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Optional plotting dependencies such as `cartopy` may require platform-specific geospatial libraries. The core numerical workflow uses `numpy`, `pandas`, `xarray`, `scipy`, `matplotlib`, and `pyyaml`.

## Expected Inputs

This repository does not redistribute raw climate datasets. Users should obtain datasets from their original providers and configure local paths in `configs/example.yaml`.

Typical inputs:

- monthly precipitation fields with `time`, `lat`, and `lon` dimensions;
- atmospheric circulation fields such as `uwnd`, `vwnd`, `hgt`, and `omega`;
- a target month, region bounds, and reference climatology period.

## Example Usage

```bash
python scripts/run_preprocessing.py --config configs/example.yaml
python scripts/run_eof_analysis.py --config configs/example.yaml
python scripts/run_composite_analysis.py --config configs/example.yaml
```

The example CSV under `examples/` is a small derived demonstration artifact.
It is not a raw dataset, a canonical dataset release, or a substitute for
provider-sourced scientific data.

## Demonstration Figures

The `assets/sanitized-figures/` directory contains derived figures suitable for a public project page:

- regional precipitation time series;
- decadal precipitation and category counts;
- EOF spatial regression modes;
- Monte Carlo variance screening;
- standardized EOF1 principal component;
- circulation climatology and phase-composite panels.

## Diagnostic Inference

The public version keeps a small amount of scientific interpretation while avoiding institutional or personal context. The key inference pattern is:

```text
climatology -> anomaly field -> EOF modes -> screened signals -> representative years -> circulation composites -> mechanism hypothesis
```

The main methodological takeaway is that EOF modes should be treated as diagnostic coordinates, not as final explanations. Physical interpretation is added only after checking variance contribution, Monte Carlo screening, representative-year behavior, and vertically coherent circulation composites.

See `docs/inference-framework.md` for the reusable reasoning framework.

## Limitations

- EOF signs are arbitrary. This project normalizes the first EOF mode so that positive PC values correspond to positive regional precipitation anomalies.
- Representative-year thresholds are configurable and should be treated as analysis choices, not universal physical constants.
- Composite diagnostics are descriptive and should be interpreted with physical context and uncertainty checks.
- The repository does not include raw climate data and cannot be fully reproduced until users provide compatible local datasets.

## Data Policy

Raw gridded climate datasets can be large and may have separate access policies. This repository does not redistribute CN05.1, NCEP/NCAR Reanalysis, or any other raw third-party climate dataset. See `docs/data-policy.md`.

## Public-Safe Scope

This public version is framed as a neutral scientific-computing project. It excludes course documents, institutional templates, personal identifiers, local-machine paths, and raw restricted datasets.
