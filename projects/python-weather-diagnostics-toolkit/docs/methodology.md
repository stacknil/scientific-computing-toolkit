# Methodology

This mini-lab converts local weather-analysis exercises into reusable,
public-safe scientific-computing components. The workflow is intentionally
compact: every calculation should be inspectable, deterministic, and runnable on
synthetic data before a user connects real datasets.

## 1. Dataset Normalization

ERA5-style files can use short names (`t2m`, `u`, `v`, `z`) or long names
(`2m_temperature`, `u_component_of_wind`, `geopotential`). The toolkit uses
alias maps to normalize common coordinate and variable names:

- `valid_time` -> `time`
- `lat` / `lon` -> `latitude` / `longitude`
- `level` / `isobaricInhPa` -> `pressure_level`
- common ERA5 short and long variable names -> canonical diagnostic names

Latitude is sorted into ascending order when needed so array derivatives are
consistent.

## 2. Thermodynamic Diagnostics

The public thermodynamic check uses the Magnus approximation:

```text
gamma = ln(RH) + aT / (b + T)
Td = b gamma / (a - gamma)
```

where `T` is temperature in degrees Celsius, `RH` is relative humidity as a
0-1 ratio, and `Td` is dewpoint temperature. The default constants are
`a = 17.625` and `b = 243.04`.

The reviewer-safe check computes dewpoint and then reconstructs relative
humidity from temperature and dewpoint. This confirms implementation
consistency without requiring real ERA5 files.

## 3. Dynamic Diagnostics

The dynamic calculations operate on regular latitude/longitude grids:

```text
geopotential height = geopotential / g0
relative vorticity = dv/dx - du/dy
horizontal advection = -(u dS/dx + v dS/dy)
```

Grid spacing is approximated from spherical Earth geometry:

```text
dy = R d(latitude)
dx = R cos(latitude) d(longitude)
```

This is adequate for compact diagnostics and tests. For formal research or
forecast operations, users should validate projection assumptions, grid
staggering, units, vertical coordinates, and boundary behavior.

## 4. Regional Features

Region-mean features use cosine-latitude weighting so higher-latitude grid rows
do not receive the same area weight as lower-latitude rows. A typical feature
table can include:

- regional 500 hPa geopotential height
- regional 850 hPa temperature
- current 2 m temperature
- future 2 m temperature target shifted by a configured lead

## 5. Baseline Prediction

The included baseline is a transparent ridge regression:

```text
minimize ||X beta - y||^2 + alpha ||beta||^2
```

The split is time ordered: the first part of the series trains the model, and
the later part evaluates it. This avoids random leakage across time and keeps
the result reproducible. Metrics include RMSE, MAE, bias, and correlation.

The baseline is included for workflow demonstration only. It is not a claim of
forecast skill.

## 6. Synthetic Ensemble Summary

The synthetic Nino-style ensemble utility creates deterministic plume data with
a fixed random seed. It demonstrates:

- multi-model spread
- ensemble mean
- 10th and 90th percentile envelope
- warm/cold threshold probabilities

The generated values are synthetic and should be read only as an example of
summary mechanics.

## 7. Interpretation Boundaries

A public interpretation should say what was computed and what the diagnostic
suggests, while avoiding unsupported claims. For example:

- A coherent vorticity maximum can identify a circulation feature in the chosen field.
- Temperature advection sign can indicate whether the local flow imports warmer or colder air.
- A ridge baseline can expose whether simple regional features carry predictive information.

These are diagnostics, not operational warnings, official forecasts, or
production climate conclusions.
