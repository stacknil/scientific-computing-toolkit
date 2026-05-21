# Methodology

This mini-lab contains exploratory diagnostics for gridded climate fields. The workflows are intentionally modular so that users can swap in locally obtained datasets, variables, periods, and region definitions.

For implementation-level formulas, see [Calculation Methods](calculation-methods.md). For interpretation guidance and inference boundaries, see [Inference Analysis](inference-analysis.md).

## Workflow Overview

The project follows a reproducible diagnostic sequence:

```text
local gridded inputs
-> coordinate normalization
-> period and region selection
-> climatology and anomaly diagnostics
-> regional time-series diagnostics
-> statistical association checks
-> EOF/PC decomposition
-> representative-year composites
-> coupled-field MCA
-> documented interpretation limits
```

Each script reads the same YAML configuration style. This makes it possible to rerun the analysis after changing only the local input paths, year ranges, or region boxes.

## Data Preparation Assumptions

The scripts assume that the input files are already prepared as seasonal, monthly, or otherwise analysis-ready fields. They do not download provider data, apply quality-control flags, regrid between products, or resolve unit conversions automatically.

Expected gridded dimensions are:

- `time`
- `latitude`
- `longitude`

The loader recognizes common coordinate aliases and normalizes them before calculation. Users should still inspect units, calendar conventions, missing-value encodings, and aggregation periods before interpreting outputs.

## Precipitation Anomaly Diagnostics

The precipitation workflow computes:

- a climatology field over a configurable baseline period;
- a standard-deviation field over the same baseline;
- a target-year anomaly field;
- a target-year anomaly-percentage field;
- a cosine-latitude weighted regional mean;
- regional anomalies, standardized anomalies, moving average, and cumulative anomaly;
- representative low, high, and near-normal years.

The default region is a simple latitude/longitude box. Users should replace this with a scientifically appropriate mask when basin boundaries matter.

Primary outputs:

- `precip_climatology.png`
- `precip_standard_deviation.png`
- `precip_anomaly_<year>.png`
- `regional_precipitation_series.csv`
- `representative_years.csv`

Interpretation boundary:

An anomaly map says how a field differs from the configured baseline. It does not by itself identify a physical driver.

## Correlation and Lag Diagnostics

The index diagnostics read a year-index table and align it with the gridded field by year. Pearson correlation maps are computed gridpoint by gridpoint with pairwise-valid samples.

Lag diagnostics include:

- partial correlation among index columns using the inverse correlation matrix;
- autocorrelation for each index;
- cross-correlation for each index pair across configurable lags.

Interpretation boundary:

These diagnostics describe association. They do not establish causality, and map p-values are pointwise unless a user adds field-significance testing.

## Linear Trend Diagnostics

The trend workflow estimates a linear trend at each grid point with ordinary least squares against calendar year. Trends are reported per decade, and p-values are the two-sided pointwise slope-test p-values.

The workflow also computes regional moving-average and cumulative-anomaly plots so that the trend map can be read alongside a time-series view.

Interpretation boundary:

A significant linear trend can describe background change over the analysis period, but it does not explain individual events without additional evidence.

## EOF and PC Analysis

The EOF workflow standardizes each grid point across time, optionally applies square-root cosine-latitude weighting, and performs singular value decomposition on the time-space matrix.

Outputs include:

- EOF loading maps;
- standardized PC time series;
- an eigenvalue scree plot;
- a summary CSV containing variance fractions and North rule-of-thumb errors.

EOF sign is arbitrary. The implementation uses a mean-positive sign convention only to make repeated displays easier to compare.

Interpretation boundary:

EOF modes are statistical coordinates. A mode should be interpreted physically only when it is supported by additional evidence such as representative years, composites, or known circulation behavior.

## Composite Circulation Analysis

The composite workflow compares circulation fields for two user-provided representative-year groups. It computes:

- group-A mean;
- group-B mean;
- group-A minus group-B difference;
- pointwise Welch two-sample t-test p-values.

Empty year lists are treated as a configuration error because the script should not invent representative years.

Interpretation boundary:

Composite differences are conditional averages over selected years. They are useful for mechanism hypotheses, but they are not causal attribution by themselves.

## Coupled-Field MCA

The MCA workflow standardizes precipitation and SST fields, selects common years, stacks valid grid points, and performs singular value decomposition on the cross-covariance matrix.

Outputs include:

- heterogeneous precipitation correlation maps;
- heterogeneous SST correlation maps;
- paired score time series;
- squared covariance fraction summary.

Interpretation boundary:

MCA identifies coupled covariance patterns. It does not determine direction of influence or separate direct SST forcing from atmospheric mediation.

## Regression Diagnostics

The regression workflow fits a regional precipitation mean against a selected climate index using ordinary least squares with an intercept.

Outputs include:

- coefficient table;
- fitted values and residuals;
- `R^2`;
- residual degrees of freedom.

Interpretation boundary:

Regression coefficients depend on the configured region, index scaling, sample size, and period. A regression association should be reported with these settings.

## Quality Controls in the Public Version

The public mini-lab includes lightweight synthetic-data tests for core numerical behavior:

- standardized anomaly masking;
- representative-year ranking;
- lag-diagnostic input validation;
- linear trend recovery;
- EOF output dimensions and variance fractions;
- composite means and differences;
- OLS coefficient recovery.

These tests are not a scientific validation of a specific dataset. They verify that the implementation behaves deterministically for known synthetic inputs.
