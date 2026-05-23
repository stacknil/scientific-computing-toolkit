# Python Weather Diagnostics Toolkit

A public-safe scientific-computing mini-lab for reproducible Python weather
diagnostics on ERA5-style gridded atmospheric fields.

Repository role:
This is a supporting atmospheric diagnostics module inside
`scientific-computing-toolkit`. It demonstrates reusable Python workflows for
weather-field analysis, data-policy discipline, and reviewer-friendly
interpretation. It is not part of the `sbom-diff-and-risk` release surface, not
an operational forecast system, and not a separate meteorology portfolio.

## What It Does

The toolkit preserves the technical substance of local weather-analysis
experiments while removing course, personal, local-machine, and raw-data
artifacts. It focuses on:

- ERA5-style coordinate and variable-name normalization
- 2 m temperature, 10 m wind, 500 hPa height, and 850 hPa wind/temperature fields
- Magnus-formula dewpoint diagnostics and round-trip humidity checks
- geopotential-height conversion
- relative-vorticity and horizontal-advection diagnostics
- cosine-latitude regional means
- a deterministic time-ordered ridge-regression baseline for 24-hour temperature prediction
- synthetic ensemble summaries for Nino-style forecast-plume interpretation

## Repository Structure

```text
python-weather-diagnostics-toolkit/
+-- configs/example.yaml
+-- docs/
|   +-- data-policy.md
|   +-- calculation-methods.md
|   +-- diagnostic-analysis.md
|   +-- methodology.md
|   +-- reproducibility.md
|   +-- reviewer-path.md
|   +-- source-to-public-mapping.md
+-- examples/
|   +-- sample_metadata.json
|   +-- synthetic-weather-diagnostics-report.md
+-- scripts/
|   +-- run_dynamics_summary.py
|   +-- run_synthetic_ensemble.py
|   +-- run_thermodynamic_check.py
+-- src/python_weather_diagnostics_toolkit/
+-- tests/
+-- PUBLICATION_BOUNDARIES.md
+-- SANITIZATION_REPORT.md
```

## Installation

From this project directory:

```bash
python -m pip install -e .[dev]
```

Optional meteorological plotting and unit-aware diagnostics can use:

```bash
python -m pip install -e .[meteo]
```

## Example Usage

Run the deterministic test suite:

```bash
python -m pytest
```

Inspect the public CLI surfaces:

```bash
python scripts/run_thermodynamic_check.py --help
python scripts/run_dynamics_summary.py --help
python scripts/run_synthetic_ensemble.py --help
```

Generate a synthetic ensemble summary:

```bash
python scripts/run_synthetic_ensemble.py --out outputs/synthetic_ensemble_summary.csv
```

## Scientific Computing Surface

The project exposes three reviewable calculation layers.

Thermodynamic layer:

- converts temperature and relative humidity into dewpoint with the Magnus approximation
- accepts relative humidity as either percent or 0-1 ratio
- reconstructs humidity from dewpoint as a round-trip consistency check
- keeps this calculation independent of any real dataset

Dynamic layer:

- converts geopotential to geopotential height using standard gravity
- estimates latitude/longitude grid spacing from spherical Earth geometry
- computes relative vorticity as `dv/dx - du/dy`
- computes horizontal scalar advection as `-(u dS/dx + v dS/dy)`
- keeps finite-difference assumptions explicit for reviewer inspection

Statistical layer:

- reduces gridded fields to cosine-latitude area means
- constructs time-ordered forecast tables from regional features
- fits a deterministic ridge-regression baseline without random shuffling
- reports RMSE, MAE, bias, and correlation as workflow diagnostics
- summarizes synthetic ensemble spread, quantiles, and threshold probabilities

For formulas and numerical assumptions, see
[`docs/calculation-methods.md`](docs/calculation-methods.md).

## Diagnostic Analysis

The intended analysis pattern is:

```text
normalize input metadata
-> compute derived thermodynamic or dynamic fields
-> summarize fields into small artifacts
-> interpret the pattern with explicit limits
```

Examples:

- A coherent 500 hPa vorticity feature can identify rotation or shear, but it
  should be interpreted with height contours and wind context.
- Negative 850 hPa temperature advection can indicate cold-air import by
  horizontal flow, but it is not a complete temperature tendency budget.
- A ridge-regression baseline can test whether simple regional predictors carry
  signal, but it is not a forecast-skill claim without real validation data and
  comparison baselines.
- Ensemble threshold probabilities summarize member agreement; synthetic
  probabilities in this repository are examples of mechanics, not real climate
  information.

For interpretation guidance, see
[`docs/diagnostic-analysis.md`](docs/diagnostic-analysis.md).

## Expected Inputs

For real analysis, users provide their own local ERA5-style NetCDF files through
`configs/example.yaml`. The toolkit expects common variables such as:

- single-level fields: `t2m`, `d2m`, `u10`, `v10`, `tp`, or their long ERA5 names
- pressure-level fields: `t`, `u`, `v`, `z`, `r`, `w`, `vo`, or their long ERA5 names
- coordinates: `time` or `valid_time`, `latitude`, `longitude`, and optionally `pressure_level`

## Generated Outputs

The reusable scripts and library functions can produce:

- JSON summaries for thermodynamic and dynamic diagnostics
- CSV ensemble summaries from synthetic reviewer-safe data
- local figures or NetCDF-derived summaries when users connect their own data

Generated outputs are intentionally ignored by Git unless they are explicitly
small, synthetic, and documentation-oriented.

## Limitations

- This project is a compact diagnostics mini-lab, not a production forecasting system.
- The built-in data are synthetic and should not be interpreted as climate evidence.
- The ridge baseline is a transparent benchmark, not a claim of forecast skill.
- Map rendering and MetPy/Cartopy workflows are optional because they can require heavier system dependencies.
- Scientific interpretation depends on user-supplied data provenance, spatial domain, temporal sampling, and quality control.

## Data Policy

This repository does not redistribute ERA5, ECMWF, GRIB, NetCDF, station
datasets, course documents, personal reports, or local-machine artifacts. Users
must obtain datasets from their original providers and follow provider access
and licensing policies. See [`docs/data-policy.md`](docs/data-policy.md).

## Reviewer Path

Use [`docs/reviewer-path.md`](docs/reviewer-path.md) for a 30-second,
5-minute, and 15-minute review route.

The more detailed technical route is:

1. [`docs/calculation-methods.md`](docs/calculation-methods.md)
2. [`docs/diagnostic-analysis.md`](docs/diagnostic-analysis.md)
3. [`docs/source-to-public-mapping.md`](docs/source-to-public-mapping.md)

## Privacy-Safe Scope

The public version is maintained under the pseudonymous technical identity
`stacknil`. It is not an official institutional project and does not include
raw school materials, personal identifiers, local paths, provider account
material, or restricted data.
