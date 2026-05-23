# Station And Precipitation Workflows

The source materials included station observations, gridded reanalysis, and
forecast-style accumulated precipitation examples. The public toolkit keeps the
reusable methods but does not redistribute station tables, NetCDF files, plots,
or report artifacts.

## Station Quality Control

Station tables often encode missing observations with a numeric sentinel. The
public helper `mark_missing_sentinel` replaces that code with `NaN` before any
interpolation, event total, or verification step.

Recommended order:

```text
load local station table
-> normalize column names outside this repo
-> replace missing sentinel with NaN
-> remove non-finite longitude/latitude/value rows
-> interpolate or summarize
```

This keeps missingness explicit and prevents sentinel values from becoming
false heavy-precipitation or temperature extremes.

## Station-To-Grid Interpolation

The toolkit includes inverse-distance weighting (IDW) for lightweight
station-to-grid examples:

```text
weight = 1 / distance**power
grid_value = sum(weight * station_value) / sum(weight)
```

The implementation:

- accepts 1D station longitude, latitude, and value arrays
- accepts either 1D target longitude/latitude axes or matching 2D grids
- ignores stations with non-finite coordinates or values
- preserves exact station-grid matches
- supports a maximum search distance and minimum-neighbor count

IDW is intentionally simple. For formal spatial analysis, compare against
ordinary kriging, objective analysis, or domain-specific interpolation methods,
and document station density, terrain effects, and validation error.

## Accumulated Precipitation

Forecast products can store precipitation as an accumulation over lead time.
The public helper first differences a non-decreasing accumulated series:

```text
increment[0] = accumulated[0]
increment[t] = accumulated[t] - accumulated[t - 1]
```

For a 6-hour step, a per-step amount can be expressed as a mm/day-equivalent
rate:

```text
rate = increment * 24 / 6
```

The helper raises an error when a finite accumulated sequence decreases. This
is a quality-control signal: the user may have mixed forecast cycles, used the
wrong lead dimension, or encountered a product reset that should be handled
before conversion.

## Event Totals And Thresholds

The public precipitation utilities also provide:

- `event_total`: sum over an event axis while returning `NaN` for all-missing
  grid points
- `threshold_exceedance`: mark finite values that meet or exceed a configured
  threshold

Thresholds are intentionally user-supplied. Public examples should explain
whether a threshold is absolute, percentile-based, or standardized-anomaly
based, and should avoid official warning language unless the source authority
and rule are documented.

## What Is Not Included

The public project does not include:

- station observation tables
- provider forecast products
- gridded reanalysis files
- generated maps from local analysis
- private report text or templates

The code is a reusable calculation scaffold. Users connect their own licensed
data locally.
