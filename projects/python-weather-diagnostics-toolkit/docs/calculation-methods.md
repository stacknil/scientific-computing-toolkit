# Calculation Methods

This document describes the scientific-computing calculations implemented in
the public toolkit. The emphasis is on transparent numerical steps that can be
reviewed independently of any private or provider-restricted dataset.

## Data Model

The toolkit assumes gridded atmospheric data with latitude, longitude, time,
and optionally pressure-level coordinates. ERA5-style files often use different
names for the same physical field. The public code therefore separates the
scientific operation from provider-specific naming.

Canonical coordinates:

| Canonical name | Accepted aliases |
| --- | --- |
| `time` | `time`, `valid_time` |
| `latitude` | `latitude`, `lat` |
| `longitude` | `longitude`, `lon` |
| `pressure_level` | `pressure_level`, `level`, `isobaricInhPa` |

Canonical variables:

| Canonical name | Common aliases | Typical unit |
| --- | --- | --- |
| `t2m` | `t2m`, `2m_temperature`, `2t` | K |
| `d2m` | `d2m`, `2m_dewpoint_temperature`, `2d` | K |
| `u10` | `u10`, `10m_u_component_of_wind`, `10u` | m/s |
| `v10` | `v10`, `10m_v_component_of_wind`, `10v` | m/s |
| `temperature` | `t`, `temperature` | K |
| `relative_humidity` | `r`, `relative_humidity` | percent or ratio |
| `u` | `u`, `u_component_of_wind` | m/s |
| `v` | `v`, `v_component_of_wind` | m/s |
| `omega` | `w`, `omega`, `vertical_velocity` | Pa/s |
| `geopotential` | `z`, `geopotential` | m2/s2 |
| `relative_vorticity` | `vo`, `relative_vorticity` | s^-1 |

Latitude is sorted into ascending order when needed. This keeps finite
differences consistent and avoids silently flipping north/south derivatives.

## Thermodynamic Calculation

The dewpoint calculation uses a Magnus-form approximation. For temperature
`T` in degrees Celsius and relative humidity ratio `RH`:

```text
gamma = ln(RH) + aT / (b + T)
Td = b gamma / (a - gamma)
```

The public implementation uses:

```text
a = 17.625
b = 243.04
```

Inputs may use either percent humidity (`68`) or ratio humidity (`0.68`). The
implementation converts percent-like values to ratios and clips the ratio to
`[1e-6, 1]` to avoid logarithm singularities.

The inverse check reconstructs humidity from temperature and dewpoint:

```text
RH = exp(a Td / (b + Td)) / exp(a T / (b + T))
```

This is a numerical consistency check, not independent observational
validation. It confirms that the forward and inverse formulas agree.

## Geopotential Height

ERA5 pressure-level geopotential is commonly stored as geopotential in
`m2/s2`. The toolkit converts it to approximate geopotential height:

```text
height = geopotential / g0
g0 = 9.80665 m/s2
```

This conversion supports 500 hPa height diagnostics and contour overlays.

## Horizontal Grid Spacing

For compact diagnostics on regular latitude/longitude grids, spacing is
approximated with spherical Earth geometry:

```text
dy = R d(phi)
dx = R cos(phi) d(lambda)
R = 6,371,000 m
```

where `phi` is latitude in radians and `lambda` is longitude in radians. This
is sufficient for reviewer-safe synthetic tests and first-pass diagnostics. For
formal research, users should validate map projection assumptions, grid
staggering, resolution, and polar behavior.

At exact pole rows, `cos(phi)` is effectively zero and the zonal derivative is
not well defined on a regular longitude grid. The implementation masks those
`d/dx` rows as `NaN` instead of returning infinite or spuriously amplified
values. Downstream regional reductions use finite-value weighting, so non-polar
rows remain usable while the polar boundary is explicit.

## Relative Vorticity

Relative vorticity is computed as:

```text
zeta = dv/dx - du/dy
```

where `u` is zonal wind and `v` is meridional wind. The implementation uses
centered finite differences through `numpy.gradient`, with edge differences
handled by NumPy's boundary behavior.

Diagnostic meaning:

- positive/negative sign depends on coordinate conventions and hemisphere
- coherent extrema can identify rotation or shear features
- a vorticity field should be interpreted together with height contours and wind flow

## Horizontal Advection

For a scalar field `S`, horizontal advection is:

```text
advection = -(u dS/dx + v dS/dy)
```

For temperature, negative values indicate cooling tendency from horizontal flow
under the chosen units and coordinate assumptions; positive values indicate
warming tendency. In a full thermodynamic budget, this is only one term. The
public mini-lab intentionally keeps the default implementation to horizontal
advection so that tests remain small and dependency-light.

## Moisture Flux Divergence

For lower-tropospheric precipitation diagnostics, the toolkit includes a
horizontal specific-humidity flux divergence:

```text
div(qV) = d(q u)/dx + d(q v)/dy
```

where `q` is specific humidity, `u` is zonal wind, and `v` is meridional wind.
Negative values are often read as moisture-flux convergence under the chosen
coordinate and unit assumptions. This diagnostic should be interpreted with
precipitation, vertical motion, and synoptic context rather than as a complete
rainfall budget.

## Area-Weighted Regional Mean

Regional features use cosine-latitude weighting:

```text
weight(phi) = cos(phi)
area_mean = sum(field * weight) / sum(valid_weight)
```

This avoids treating all latitude rows as equal-area rows. The implementation
supports arrays with time or pressure dimensions before the final
latitude/longitude dimensions. If a reduction window contains no finite values,
the result is `NaN`; this keeps missing-data coverage explicit instead of
converting an empty region into a numerical zero.

## Time-Ordered Baseline Model

The baseline model transforms gridded fields into region-mean features:

```text
X = [Z500_mean, T850_mean, T2m_current_mean]
y = T2m_future_mean
```

The target is formed by shifting the current 2 m temperature series by a
configured lead:

```text
y(t) = T2m(t + lead_steps)
```

The split is time ordered:

```text
train = first train_fraction of rows
test = remaining rows
```

This avoids temporal leakage that would occur if samples were randomly shuffled.

The ridge objective is:

```text
minimize ||X beta - y||^2 + alpha ||beta||^2
```

Features are standardized using the training partition only. The intercept is
not penalized.

## Evaluation Metrics

The toolkit reports:

```text
RMSE = sqrt(mean((prediction - truth)^2))
MAE = mean(abs(prediction - truth))
bias = mean(prediction - truth)
correlation = corr(prediction, truth)
```

Metrics should be interpreted as workflow diagnostics unless the data source,
sampling design, baseline comparisons, and validation periods are documented.

## Synthetic Ensemble Summary

The synthetic Nino-style ensemble generates deterministic plume values with a
fixed seed. It then computes:

```text
mean = ensemble mean
spread = ensemble population standard deviation
p10 = 10th percentile
p90 = 90th percentile
warm_probability = fraction(member >= 0.5)
cold_probability = fraction(member <= -0.5)
```

The summary requires finite member values. The spread uses the population
standard deviation (`ddof=0`), so a one-member reviewer fixture has spread `0`
instead of an undefined sample standard deviation. These calculations
demonstrate ensemble-summary mechanics without embedding real forecast
products.

Example synthetic summary rows:

| Lead month | Mean | Spread | P10 | P90 | Warm probability | Cold probability |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1.514 | 0.253 | 1.127 | 1.829 | 1.00 | 0.00 |
| 6 | 1.104 | 0.440 | 0.523 | 1.629 | 0.90 | 0.00 |
| 12 | 0.116 | 0.654 | -0.680 | 0.924 | 0.25 | 0.25 |
| 18 | -0.768 | 1.019 | -1.577 | 0.187 | 0.05 | 0.55 |
| 24 | -1.469 | 1.204 | -3.092 | 0.213 | 0.10 | 0.85 |

These values are synthetic. They are useful for verifying table generation and
reviewer interpretation, not for climate diagnosis.

## Station And Precipitation Utilities

The precipitation helpers cover common data-preparation steps:

```text
missing sentinel -> NaN
accumulated precipitation -> per-step amount
per-step amount -> mm/day-equivalent rate
event total -> sum over finite event samples
threshold exceedance -> finite value >= configured threshold
```

Accumulated precipitation is required to be non-decreasing along the selected
lead axis. A decreasing finite sequence raises an error because it usually
indicates mixed forecast cycles, an incorrect lead dimension, or an unhandled
product reset.

Station-to-grid examples use inverse-distance weighting:

```text
weight = 1 / distance**power
grid_value = sum(weight * station_value) / sum(weight)
```

This is a transparent interpolation baseline, not a claim that IDW is optimal
for every terrain, network density, or precipitation regime.

## Climate Statistics

Climate-statistics helpers include anomalies, standardized anomalies,
composites, and grid-point correlations:

```text
anomaly = value - climatology_mean
standardized = anomaly / climatology_std
composite = mean(field[event_mask])
r = cov(index, field_point) / (std(index) * std(field_point))
```

Zero-spread baselines, too-small samples, and zero-variance correlation points
return `NaN` so review surfaces show where the statistic is undefined.
