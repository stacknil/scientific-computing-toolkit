# Precipitation Anomaly Diagnostics Lab

This repository is a public-safe scientific-computing mini-lab for gridded climate diagnostics. It focuses on precipitation anomaly analysis, climatology and standard deviation fields, representative-year selection, EOF/PC diagnostics, composite circulation analysis, correlation and regression checks, trend diagnostics, and MCA-style coupled-field analysis.

Repository role:
This is the extended precipitation diagnostics lab variant with configurable
diagnostics utilities. It is a supporting scientific-data project inside
`scientific-computing-toolkit`, not part of the `sbom-diff-and-risk` release
surface and not a separate meteorology portfolio. For the compact
reviewer-facing version, see
[`projects/precipitation-anomaly-diagnostics`](../precipitation-anomaly-diagnostics/README.md).

The project is maintained under the pseudonymous technical identity `stacknil`. It is not an official institutional project and does not include raw course materials, restricted datasets, or personal identifiers.

## Workflow

1. Prepare local climate datasets outside Git.
2. Copy `configs/example.yaml` to `configs/local.yaml`.
3. Replace placeholder paths with your local dataset paths.
4. Install the Python environment.
5. Run one or more analysis scripts from `scripts/`.
6. Review generated figures and tables in `outputs/`.

## Reviewer Path

1. Start with [`docs/data-policy.md`](docs/data-policy.md) to understand what data is intentionally excluded.
2. Read [`docs/methodology.md`](docs/methodology.md) for the workflow and diagnostic boundaries.
3. Use [`docs/calculation-methods.md`](docs/calculation-methods.md) for formulas and implementation details.
4. Use [`docs/inference-analysis.md`](docs/inference-analysis.md) for how to reason from the outputs without overclaiming.
5. Run `python -m unittest discover -s tests` for lightweight synthetic-data checks.

## Repository Structure

```text
configs/                 Example configuration with placeholder paths
docs/                    Method notes, formulas, inference guidance, data policy
scripts/                 Command-line workflows for each diagnostic
src/climate_diagnostics/ Shared utilities for gridded climate analysis
tests/                   Synthetic-data checks for core diagnostics
SANITIZATION_REPORT.md   Local cleanup summary for this public-safe export
```

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e .
```

On macOS/Linux, activate the environment with `source .venv/bin/activate`.

Run the lightweight synthetic-data checks with:

```powershell
python -m unittest discover -s tests
```

## Example Usage

```powershell
Copy-Item configs/example.yaml configs/local.yaml
# Edit configs/local.yaml with local dataset paths.

python scripts/run_precipitation_anomalies.py --config configs/local.yaml
python scripts/run_eof.py --config configs/local.yaml
python scripts/run_composite_circulation.py --config configs/local.yaml
```

## Synthetic Demonstration

The repository includes a deterministic synthetic figure generator for reviewers who want to inspect the expected chart style without downloading climate datasets:

```powershell
python examples/generate_synthetic_demo_assets.py
```

The committed demonstration figures are synthetic and do not represent real climate findings.

![Synthetic target-year precipitation anomaly](assets/synthetic-figures/synthetic-precipitation-anomaly-map.png)

![Synthetic regional precipitation anomaly index](assets/synthetic-figures/synthetic-regional-anomaly-series.png)

The companion [`examples/synthetic-inference-report.md`](examples/synthetic-inference-report.md) shows how to translate the charts into cautious diagnostic language.

## Expected Inputs

- Gridded precipitation data as NetCDF, with a time, latitude, and longitude dimension.
- Optional climate-index table with a year column and one or more index columns.
- Optional reanalysis fields for circulation composites, such as 500 hPa height.
- Optional SST fields for coupled precipitation-SST diagnostics.

The example configuration uses placeholders only. Users must obtain datasets from original providers and follow the relevant licensing and access policies.

## Generated Outputs

Scripts write derived figures and compact tables to `outputs/` by default, including anomaly maps, climatology fields, standardized regional time series, EOF maps, PC time series, composite-difference maps, correlation maps, and diagnostic CSV files. Raw datasets and large generated NetCDF files are ignored by default.

## Methods At A Glance

- Climatology: gridpoint mean over the configured baseline period.
- Anomaly: target field minus climatology; percentage anomaly masks zero-climatology cells.
- Regional mean: cosine-latitude weighted box mean.
- Representative years: low, high, and near-normal rankings from standardized regional anomalies.
- Correlation maps: gridpoint Pearson correlation with pointwise t-test p-values.
- EOF/PC: SVD of standardized, optionally latitude-weighted anomalies.
- Composites: group mean differences with pointwise Welch two-sample t-tests.
- MCA: SVD of the precipitation-SST cross-covariance matrix.

Detailed formulas are in [`docs/calculation-methods.md`](docs/calculation-methods.md).

## Inference At A Glance

The strongest public-safe interpretation pattern is:

```text
baseline departure
-> standardized regional unusualness
-> recurring EOF/PC structure
-> transparent representative-year composites
-> physically cautious circulation or coupled-field hypothesis
```

The workflow supports diagnostic hypotheses. It does not claim causal attribution, field-significant map testing, operational predictability, or production readiness.

## Limitations

- The scripts assume locally prepared seasonal or monthly climate fields.
- Region definitions are simple latitude/longitude boxes unless users supply their own preprocessing.
- Statistical diagnostics are exploratory and should be interpreted with domain context.
- No benchmark, forecast-skill, production-readiness, or operational-use claim is made.

## Data Policy

No raw climate datasets are included. Publicly downloadable official datasets do not need privacy sanitization, but they are kept outside Git by default to avoid license ambiguity, large-file churn, and accidental redistribution. Keep local data under an ignored path such as `data/raw/`, cite providers in downstream reports as required by their terms, and commit only small synthetic fixtures or explicitly licensed lightweight samples when needed.

## Privacy-Safe Note

This public version removes course-submission packaging, local machine paths, personal identifiers, institution-specific references, and raw assignment materials. File names and documentation are written for a neutral public portfolio context.
