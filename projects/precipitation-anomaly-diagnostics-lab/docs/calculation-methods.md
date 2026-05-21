# Calculation Methods

This document describes the numerical calculations used by the mini-lab. The formulas are written for gridded precipitation, but the same utilities can be reused for other gridded climate fields when the input dimensions are compatible.

## Notation

Let:

- `P(t, y, x)` be precipitation at time `t`, latitude grid cell `y`, and longitude grid cell `x`.
- `R(t, y, x)` be a reanalysis circulation variable such as 500 hPa geopotential height.
- `S(t, y, x)` be SST.
- `I_k(t)` be the `k`th climate index time series.
- `B` be the climatology baseline period.
- `T` be the full analysis period.
- `W(y) = cos(latitude_y)` be the latitude-area weight.

The scripts normalize common coordinate names to `time`, `latitude`, and `longitude` before calculation.

## Climatology

For each grid cell, the baseline climatology is the arithmetic mean over the configured baseline period:

```text
C(y, x) = mean_{t in B} P(t, y, x)
```

The baseline standard deviation is:

```text
SD(y, x) = sqrt(mean_{t in B} (P(t, y, x) - C(y, x))^2)
```

The implementation uses `ddof=0` for climatology standardization. Grid cells with missing or zero standard deviation are masked.

## Anomaly and Anomaly Percentage

For a configured target year `t0`, the absolute anomaly is:

```text
A(t0, y, x) = P(t0, y, x) - C(y, x)
```

The anomaly percentage is:

```text
AP(t0, y, x) = 100 * (P(t0, y, x) - C(y, x)) / C(y, x)
```

Cells with zero or missing climatology are set to missing in the anomaly-percentage output.

## Standardized Anomaly

For EOF, representative-year, and regional-index diagnostics, standardized anomaly is:

```text
Z(t, y, x) = (P(t, y, x) - mean_t P(t, y, x)) / std_t P(t, y, x)
```

The scripts mask grid cells with non-finite or zero standard deviation. For one-dimensional representative-year ranking, a constant finite series is assigned zero z-scores so that the output remains deterministic rather than producing undefined values.

## Area-Weighted Regional Mean

For a configured latitude/longitude box `D`, the regional mean uses cosine-latitude weights:

```text
P_region(t) = sum_{(y,x) in D} W(y) * P(t, y, x) / sum_{(y,x) in D} W(y)
```

This is a grid-box approximation. If the scientific question requires an exact basin or administrative boundary, users should preprocess the field with an appropriate mask and then run the same diagnostics.

## Representative Years

Representative years are selected from the standardized regional series:

```text
z_region(t) = (P_region(t) - mean_t P_region(t)) / std_t P_region(t)
```

The workflow ranks:

- low years: smallest `z_region(t)`;
- high years: largest `z_region(t)`;
- near-normal years: smallest absolute `z_region(t)`.

The output is a ranking aid for downstream diagnostics. It is not an automatic physical classification and does not claim that the selected years are the only valid composites.

## Pearson Correlation Maps

For a field `P(t, y, x)` and an index `I(t)`, the gridpoint Pearson correlation is:

```text
r(y, x) =
  sum_t (P(t,y,x) - mean(P(y,x))) * (I(t) - mean(I))
  / sqrt(sum_t (P(t,y,x) - mean(P(y,x)))^2 * sum_t (I(t) - mean(I))^2)
```

The p-value uses the standard t approximation:

```text
t_stat = r * sqrt((n - 2) / (1 - r^2))
df = n - 2
p = 2 * survival_t(abs(t_stat), df)
```

Samples are pairwise valid. Cells with fewer than three valid pairs are masked.

## Partial Correlation

For a set of climate-index columns, the workflow computes the correlation matrix `R`, then uses the pseudo-inverse precision matrix:

```text
P = pinv(R)
partial_r(i, j | others) = -P_ij / sqrt(P_ii * P_jj)
```

The p-value uses:

```text
df = n - p
t_stat = partial_r * sqrt(df / (1 - partial_r^2))
```

where `n` is the number of complete rows and `p` is the number of variables. The function rejects configurations where complete rows are not greater than variables.

## Auto- and Cross-Correlation

Autocorrelation for lag `k` is:

```text
acf(k) = corr(X_t, X_{t-k})
```

Cross-correlation uses the explicit convention:

```text
ccf_xy(k) = corr(X_t, Y_{t+k})
```

Positive lag means the second series is shifted forward relative to the first. This convention is documented in CSV outputs so that lead/lag interpretation remains reproducible.

## Linear Trend

Gridpoint trend is estimated with ordinary least squares against calendar year:

```text
P(t, y, x) = beta0(y, x) + beta1(y, x) * year(t) + error(t, y, x)
```

The reported trend is:

```text
trend_per_decade(y, x) = 10 * beta1(y, x)
```

The p-value is the two-sided p-value for the slope coefficient from `scipy.stats.linregress`. It is a pointwise test, not a field-significance test.

## Ordinary Least Squares Regression

The regression workflow fits:

```text
Y = beta0 + beta1 * X1 + ... + betap * Xp + error
```

with:

```text
beta = argmin_beta ||Y - X beta||^2
```

The implementation uses `numpy.linalg.lstsq`, reports coefficient standard errors, t statistics, p-values, fitted values, residuals, residual degrees of freedom, and `R^2`. It rejects inputs where the number of complete observations is not greater than the number of model parameters.

## EOF and Principal Components

The EOF workflow uses standardized anomalies, then stacks the field into a matrix:

```text
X = Z(time, space)
```

With latitude weighting enabled:

```text
X_weighted(time, space) = X(time, space) * sqrt(cos(latitude_space))
```

The weighted matrix is centered in time and decomposed by singular value decomposition:

```text
X_weighted = U S V^T
```

The eigenvalues and variance fractions are:

```text
lambda_j = S_j^2 / (n_time - 1)
variance_fraction_j = lambda_j / sum_k lambda_k
```

Principal component time series are:

```text
PC_j(t) = U(t, j) * S_j
```

EOF maps are unweighted back to the original grid. EOF sign is mathematically arbitrary; the implementation uses a mean-positive sign convention for deterministic display.

## North Rule-of-Thumb Error

The EOF scree output includes the North rule-of-thumb sampling error:

```text
error_j = lambda_j * sqrt(2 / n_time)
```

This is a screening aid. It does not prove that an EOF mode is physically meaningful by itself.

## Composite Analysis

For two configured year groups `A` and `B`, the composite means are:

```text
M_A(y, x) = mean_{t in A} R(t, y, x)
M_B(y, x) = mean_{t in B} R(t, y, x)
```

The difference field is:

```text
D(y, x) = M_A(y, x) - M_B(y, x)
```

The p-value is computed with a gridpoint Welch two-sample t-test. The script requires at least two years in each group and does not choose composite years automatically.

## Maximum Covariance Analysis

The MCA workflow standardizes precipitation and SST fields, selects common years, and stacks both fields:

```text
X = precip_z(time, precip_space)
Y = sst_z(time, sst_space)
```

The cross-covariance matrix is:

```text
C = X^T Y / (n_time - 1)
```

SVD gives:

```text
C = U S V^T
```

The paired score time series are:

```text
a_j(t) = X(t, :) U(:, j)
b_j(t) = Y(t, :) V(:, j)
```

The squared covariance fraction is:

```text
SCF_j = S_j^2 / sum_k S_k^2
```

Heterogeneous correlation maps are computed by correlating each field with the opposite-field score. MCA modes are diagnostic coordinates for coupled variability and are not causal mechanisms by themselves.

## Numerical and Statistical Boundaries

- All tests are pointwise unless explicitly documented otherwise.
- P-values do not correct for spatial multiple testing.
- Missing values are handled by masking or pairwise-valid samples depending on the diagnostic.
- Region boxes are approximations unless a user supplies a scientifically justified mask.
- Script outputs are reproducible for fixed input files, periods, variables, and configuration values.
