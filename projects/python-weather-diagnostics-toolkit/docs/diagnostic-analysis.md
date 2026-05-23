# Diagnostic Analysis

This document explains how to read the toolkit's diagnostics as scientific
computing outputs. The goal is to make interpretation explicit while keeping
the project clearly outside operational forecasting.

## Analysis Chain

The public workflow follows a conservative chain:

```text
input metadata
-> coordinate and variable normalization
-> unit-aware or unit-documented calculation
-> derived diagnostic field or regional feature
-> small summary artifact
-> bounded interpretation
```

Each step is intentionally inspectable. A reviewer should be able to identify
which variables were used, which equation was applied, what assumptions entered
the calculation, and what conclusion is justified.

## Surface Field Analysis

Typical surface diagnostics combine:

- 2 m temperature as a filled field
- 10 m wind vectors or streamlines
- optional precipitation accumulation or pressure fields

Interpretation pattern:

```text
temperature gradient + wind direction -> possible thermal advection context
```

What this supports:

- identifying warm/cold spatial gradients
- checking whether low-level wind is aligned with the gradient
- selecting cases for deeper pressure-level diagnostics

What it does not support by itself:

- official weather warnings
- attribution of a weather event
- forecast-skill claims

## Dewpoint and Humidity Consistency

The dewpoint check is a calculation validation surface. It compares a custom
Magnus-form calculation with an inverse humidity reconstruction. In real-data
workflows, it can also be compared against a library such as MetPy.

Interpretation pattern:

```text
small round-trip difference -> formula and unit handling are internally consistent
large difference -> inspect humidity scale, temperature units, missing values, or metadata
```

The public synthetic run returns a dewpoint of about `15.8 C` for `22 C` and
`68%` humidity, with a reconstructed humidity ratio of `0.68`. This demonstrates
calculation consistency only.

## 500 hPa Height and Vorticity

The 500 hPa layer is often used as a mid-tropospheric circulation diagnostic.
The toolkit supports:

- geopotential-to-height conversion
- relative-vorticity computation
- contour/fill separation for interpretation

Interpretation pattern:

```text
height contours -> large-scale trough/ridge structure
vorticity extrema -> local rotation/shear features
co-location -> possible dynamically active region
```

Care points:

- vorticity sign depends on wind gradients and coordinate orientation
- boundary rows/columns are less stable under finite differences
- height and vorticity should be read together, not as isolated fields

## 850 hPa Temperature Advection

The 850 hPa layer is useful for lower-tropospheric thermal advection. The public
calculation is:

```text
-(u dT/dx + v dT/dy)
```

Interpretation pattern:

```text
positive advection -> horizontal flow imports warmer air
negative advection -> horizontal flow imports colder air
```

This is a horizontal term only. A full temperature tendency diagnosis may also
need vertical motion, diabatic heating, boundary-layer processes, surface
fluxes, and analysis increments. The public project keeps the default
calculation narrow so it remains reproducible and testable without heavy
external data.

## Regional Temperature Baseline

The baseline model is intentionally simple:

- reduce gridded fields to region-mean predictors
- use previous/current circulation and temperature features
- predict a future regional 2 m temperature target
- split by time order
- report transparent metrics

Interpretation pattern:

```text
low error relative to a persistence baseline -> features may carry predictive signal
high bias -> missing physics, bad sampling, or target-period drift
low correlation -> poor phase tracking
large residual tails -> weak extreme-event handling
```

The current public implementation does not claim skill because it does not
bundle a real validation dataset or persistence comparison. It provides the
calculation structure needed for such a review.

## Ensemble Plume Interpretation

The synthetic ensemble output demonstrates how to summarize multiple model
members:

- ensemble mean shows the central tendency
- spread shows member disagreement
- quantiles show an uncertainty envelope
- threshold probabilities translate members into categorical risk-like summaries

The public implementation treats missing or infinite ensemble values as input
quality problems. Synthetic fixtures are deliberately complete, which makes
review outputs deterministic and keeps missing-data policy separate from
forecast interpretation.

Interpretation pattern:

```text
mean crosses threshold + high member agreement -> stronger synthetic signal
mean near zero + large spread -> uncertain phase
probability shifts over lead time -> changing member consensus
```

In the deterministic synthetic example, the ensemble starts warm, becomes
mixed near lead month 12, and shifts cold by lead month 24. This is an example
of interpreting an artificial plume, not a statement about the real ocean.

## Reviewer Questions

Useful reviewer questions:

- Are variable aliases explicit enough to avoid silent field swaps?
- Are units documented at each calculation boundary?
- Are coordinate assumptions visible?
- Is the model split time ordered?
- Are synthetic values labeled synthetic?
- Are real-data claims avoided unless data provenance is documented?

The intended answer should be yes for the public mini-lab.
