# Synthetic Weather Diagnostics Report

This example report uses synthetic toy values only. It demonstrates the shape of
a reviewer-safe interpretation without claiming real weather results.

## Thermodynamic Check

A sample temperature of `22 C` with relative humidity of `68%` gives a
dewpoint near `15.8 C` using the Magnus approximation. Reconstructing relative
humidity from that dewpoint returns the original humidity ratio within numerical
precision.

Command:

```bash
python scripts/run_thermodynamic_check.py --temperature-c 22 --relative-humidity 68
```

Interpretation:
The check verifies that the implementation is internally consistent. It does
not validate a real observation, station record, or reanalysis field.

## Dynamic Check

The synthetic gridded field has smooth wind and temperature gradients. The
dynamic summary computes:

- relative vorticity from `dv/dx - du/dy`
- horizontal temperature advection from `-(u dT/dx + v dT/dy)`
- geopotential height from geopotential divided by standard gravity

Command:

```bash
python scripts/run_dynamics_summary.py
```

Interpretation:
A sign-coherent advection field can indicate whether the synthetic flow imports
warmer or colder air across the toy domain. In real analysis, this inference
would need unit checks, map-domain checks, temporal context, and source-data
quality control.

## Baseline Prediction

The ridge-regression baseline uses region-mean features and a time-ordered
train/test split. It is intentionally simple and transparent.

Diagnostic readout:

- `rmse` reports typical prediction error magnitude in target units
- `mae` is less sensitive to isolated large residuals than RMSE
- `bias` indicates systematic overprediction or underprediction
- `correlation` indicates phase tracking, not absolute calibration

Interpretation:
The baseline is useful as a workflow sanity check. It should not be described
as operational forecast skill without independent validation, comparison
baselines, and real-data provenance.

## Synthetic Ensemble

The Nino-style ensemble example summarizes deterministic synthetic plume data:

| Field | Meaning |
| --- | --- |
| `mean` | ensemble mean by lead month |
| `spread` | ensemble standard deviation |
| `p10`, `p90` | central spread envelope |
| `warm_probability` | fraction of members above `0.5` |
| `cold_probability` | fraction of members below `-0.5` |

Command:

```bash
python scripts/run_synthetic_ensemble.py --out outputs/synthetic_ensemble_summary.csv
```

Example interpretation:
Early synthetic lead months have high warm-threshold agreement. Middle lead
months become less certain as spread increases. Later lead months shift toward
cold-threshold agreement. This demonstrates how an ensemble plume can be
summarized as central tendency, spread, and threshold agreement.

Interpretation:
The example shows how to report ensemble spread and threshold probabilities
without embedding real forecast products or provider-restricted files.

## Misuse Checks

Do not treat this report as:

- evidence for a real historical weather event
- a forecast product
- a benchmark against operational numerical weather prediction
- proof that any data provider permits redistribution

The report is a reviewer-safe explanation of mechanics only.
