# Methodology

This mini-lab focuses on July precipitation anomaly diagnostics over eastern China using gridded climate data.

## 1. Preprocessing

1. Load monthly precipitation fields.
2. Select the target month, usually July.
3. Subset the target region.
4. Compute a reference climatology over a configurable period.
5. Compute anomalies as raw values minus climatology.

For gridded spatial averages, latitude weights are computed with `cos(lat)`.

## 2. EOF Analysis

EOF analysis decomposes a space-time anomaly field into spatial modes and time coefficients. The workflow uses `sqrt(cos(lat))` area weighting before decomposition.

Core outputs:

- EOF spatial patterns;
- principal component time series;
- variance contribution by mode;
- cumulative explained variance.

The first few modes are usually the most interpretable, but the exact number should be selected with variance contribution, statistical screening, and physical interpretation.

## 3. Monte Carlo Screening

Monte Carlo screening can be used to estimate whether observed EOF variance exceeds a random baseline. A common approach is:

1. shuffle the time order independently at each grid point;
2. recompute EOF variance fractions;
3. repeat for many iterations;
4. compare observed variance against a selected quantile, such as the 95th percentile.

This test evaluates whether spatially coherent variance is stronger than a randomized field with similar local variance.

## 4. Representative Years

Representative years are selected from a standardized principal component. In this project, a configurable threshold such as `0.9` standard deviations is used:

- positive phase: standardized PC >= threshold;
- negative phase: standardized PC <= -threshold.

EOF signs are arbitrary, so the project normalizes interpretation so that a positive EOF1 PC corresponds to positive regional precipitation anomalies.

## 5. Circulation Composites

Representative-year composites summarize atmospheric circulation differences between phases. Typical variables include:

- `uwnd` and `vwnd` for wind fields;
- `hgt` for geopotential height;
- `omega` for vertical velocity.

Composite maps are diagnostic summaries. They should be interpreted together with uncertainty checks and domain knowledge.
