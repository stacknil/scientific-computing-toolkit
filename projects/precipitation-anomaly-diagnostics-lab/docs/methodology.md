# Methodology

This mini-lab contains exploratory diagnostics for gridded climate fields. The workflows are intentionally modular so that users can swap in locally obtained datasets and region definitions.

## Precipitation Anomaly Diagnostics

The precipitation workflow computes:

- A climatology field over a configurable baseline period.
- A standard-deviation field over the same baseline.
- A target-year anomaly and anomaly percentage.
- A regional mean time series using cosine-latitude area weighting.
- Standardized regional anomalies and representative dry, wet, and near-normal years.

The default region is a simple latitude/longitude box. Users should replace this with a scientifically appropriate mask when basin boundaries matter.

## Correlation and Lag Diagnostics

The index diagnostics read a year-index table and align it with gridded precipitation by year. Pearson correlation maps are computed gridpoint by gridpoint with pairwise-valid samples. Lag diagnostics include:

- Partial correlation among index columns using the inverse correlation matrix.
- Autocorrelation for each index.
- Cross-correlation for each index pair across configurable lags.

These diagnostics are descriptive; multiple-testing and field significance are not handled automatically.

## Linear Trend

The trend workflow estimates a linear trend at each grid point with ordinary least squares against calendar year. Trends are reported per decade, with two-sided p-values from `scipy.stats.linregress`.

## EOF and PC Analysis

The EOF workflow standardizes each grid point across time, optionally applies square-root cosine-latitude weighting, and performs SVD on the time-space matrix. It writes EOF loading maps, standardized PC series, and a scree plot with North rule-of-thumb sampling errors.

EOF sign is arbitrary. The implementation uses a mean-positive sign convention only to make repeated runs easier to compare.

## Composite Circulation Analysis

The composite workflow compares circulation fields for two user-provided representative-year groups. It computes group means, their difference, and a Welch two-sample t-test at each grid point. Empty year lists are treated as a configuration error, because the script should not invent representative years.

## Coupled-Field MCA

The MCA workflow standardizes precipitation and SST fields, selects common years, stacks valid grid points, and performs SVD on the cross-covariance matrix. It writes leading heterogeneous correlation maps and paired score time series.

## Regression Diagnostics

The regression workflow fits a regional precipitation mean against a selected climate index using ordinary least squares with an intercept. It reports coefficients, residual diagnostics, and prediction intervals only for the configured local dataset.
