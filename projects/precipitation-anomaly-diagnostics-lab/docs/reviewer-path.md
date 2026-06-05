# Reviewer path

This reviewer path is the ordered route for reading the extended precipitation
diagnostics lab. It keeps the lab reviewable as supporting scientific-computing
evidence without presenting it as the repository's flagship release surface.

## 30-second orientation

Read the project [README](../README.md) first. Confirm this is a public-safe
extended diagnostics lab, not a course archive, not a raw-data mirror, and not
an operational forecast system.

Check the first screen for the project role:

- extended precipitation diagnostics lab variant
- supporting scientific-data project inside `scientific-computing-toolkit`
- not part of the `sbom-diff-and-risk` release surface
- not a separate meteorology portfolio

## 5-minute workflow review

Inspect:

- [`docs/data-policy.md`](data-policy.md)
- [`docs/methodology.md`](methodology.md)
- [`docs/calculation-methods.md`](calculation-methods.md)
- [`docs/inference-analysis.md`](inference-analysis.md)
- [`examples/synthetic-inference-report.md`](../examples/synthetic-inference-report.md)

This pass should answer whether the lab explains its configurable diagnostics,
synthetic demonstration assets, and inference boundaries without requiring raw
climate datasets or private local materials.

## 15-minute reproducibility review

The command files covered by this pass are
[`scripts/run_precipitation_anomalies.py`](../scripts/run_precipitation_anomalies.py),
[`scripts/run_eof.py`](../scripts/run_eof.py),
[`scripts/run_composite_circulation.py`](../scripts/run_composite_circulation.py),
[`scripts/run_index_correlations.py`](../scripts/run_index_correlations.py),
[`scripts/run_lag_diagnostics.py`](../scripts/run_lag_diagnostics.py),
[`scripts/run_mca.py`](../scripts/run_mca.py),
[`scripts/run_regression.py`](../scripts/run_regression.py), and
[`scripts/run_trend_diagnostics.py`](../scripts/run_trend_diagnostics.py).

Run:

```bash
python -m pip install -e .
python -m unittest discover -s tests
python scripts/run_precipitation_anomalies.py --help
python scripts/run_eof.py --help
python scripts/run_composite_circulation.py --help
python scripts/run_index_correlations.py --help
python scripts/run_lag_diagnostics.py --help
python scripts/run_mca.py --help
python scripts/run_regression.py --help
python scripts/run_trend_diagnostics.py --help
```

Then inspect the synthetic demonstration path:

The generator is
[`examples/generate_synthetic_demo_assets.py`](../examples/generate_synthetic_demo_assets.py).

```bash
python examples/generate_synthetic_demo_assets.py
```

Expected result:

- tests pass with synthetic fixtures
- CLI help surfaces are available without local dataset paths
- committed demonstration figures remain clearly synthetic
- generated outputs stay outside the committed source tree unless explicitly
  intended as example artifacts

## Boundaries

Read:

- [`docs/data-policy.md`](data-policy.md)
- [`SANITIZATION_REPORT.md`](../SANITIZATION_REPORT.md)
- [`docs/reproducibility.md`](reproducibility.md)

This project is a supporting extended lab for scientific-computing review. It
does not claim causal attribution, forecast skill, field-significant map
testing, production readiness, or public redistribution of raw climate data.

## Technical deep-dive route

For a deeper review, read the project in this order:

1. [`src/climate_diagnostics/config.py`](../src/climate_diagnostics/config.py)
   for typed configuration boundaries.
2. [`src/climate_diagnostics/io.py`](../src/climate_diagnostics/io.py) for
   dataset loading and derived-output path handling.
3. [`src/climate_diagnostics/grids.py`](../src/climate_diagnostics/grids.py)
   for anomaly, climatology, EOF, and composite helpers.
4. [`src/climate_diagnostics/statistics.py`](../src/climate_diagnostics/statistics.py)
   for correlation, regression, trend, lag, and MCA helpers.
5. [`src/climate_diagnostics/plotting.py`](../src/climate_diagnostics/plotting.py)
   for reviewer-visible synthetic charts.
6. [`docs/calculation-methods.md`](calculation-methods.md) for formulas and
   interpretation constraints.

This route should make the lab reviewable as a public-safe diagnostics workflow
rather than as a claim about an operational climate product.
