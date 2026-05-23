# Climate Statistical Diagnostics

The source materials included basic climate-statistics workflows: anomalies,
correlation, regression, composites, and simple machine-learning baselines. The
public toolkit now exposes a small set of deterministic helpers for these
tasks, while keeping datasets and claims outside the repository.

## Anomalies

An anomaly is a departure from a reference baseline:

```text
anomaly = value - climatology_mean
```

A standardized anomaly divides that departure by a reference spread:

```text
standardized_anomaly = (value - climatology_mean) / climatology_std
```

If the baseline spread is zero, the public implementation returns `NaN` rather
than an infinite value. That makes degenerate baselines visible during review.

## Composite Means

Composite analysis averages samples selected by an event mask:

```text
composite = mean(field[event_mask])
```

The event mask should be defined before looking at the composite field. Useful
examples include warm-event days, heavy-precipitation days, or high-index
periods. Public examples should document:

- how the event mask was defined
- the number of selected samples
- whether the composite is a mean field, difference field, or anomaly field
- whether statistical significance was assessed separately

## Correlation Fields

The helper `pearson_correlation_field` computes the Pearson correlation between
a one-dimensional index and every grid point in a field:

```text
r = cov(index, field_point) / (std(index) * std(field_point))
```

The implementation handles missing values pairwise and returns `NaN` for grid
points with too few finite pairs or zero variance.

## Regression And Prediction Boundaries

The toolkit already includes a ridge-regression baseline for time-ordered
temperature prediction. The climate-statistics helpers are meant to support
feature exploration before modeling:

```text
anomaly map -> regional feature -> time-ordered split -> transparent baseline
```

They do not establish forecast skill on their own. A public result should
include an explicit validation period, comparison baseline, sampling design,
and error metric before making predictive claims.

## Review Checklist

For any climate-statistics result, verify:

- the baseline period is stated
- missing-value handling is documented
- the sample axis is time ordered when used for prediction
- event definitions are chosen before composite interpretation
- correlation or regression output is not described as causation
