# Reproducibility

The public project is designed to reproduce without raw weather datasets.

## Local Setup

```bash
python -m pip install -e .[dev]
```

Optional meteorological plotting dependencies:

```bash
python -m pip install -e .[meteo]
```

## Checks

Run:

```bash
python -m pytest
python -m compileall src scripts
python scripts/run_thermodynamic_check.py --help
python scripts/run_dynamics_summary.py --help
python scripts/run_synthetic_ensemble.py --help
```

## Synthetic Demo

```bash
python scripts/run_thermodynamic_check.py
python scripts/run_dynamics_summary.py
python scripts/run_synthetic_ensemble.py --out outputs/synthetic_ensemble_summary.csv
```

These commands use deterministic synthetic values or toy fields. They verify the
public calculation paths without requiring ERA5, ECMWF, station, or local course
data.

## Real-Data Reproduction

To run the workflow on real data:

1. Obtain data from the original provider.
2. Confirm the provider permits your use case.
3. Copy `configs/example.yaml` to a local untracked config file.
4. Replace placeholder paths with local dataset paths.
5. Run diagnostics locally and keep raw data outside Git.

## Final Checklist

- no raw datasets included
- no personal identifiers
- no school identifiers
- no local paths
- no course submission artifacts
- no provider account material
- no generated binary artifacts with unknown metadata
- synthetic examples are labeled as synthetic
- baseline outputs are not presented as forecast skill claims
