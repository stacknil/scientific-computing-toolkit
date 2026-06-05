# Reviewer Path

## 30-second orientation

Read the project [README](../README.md) first. Confirm this is a sanitized
Python weather-diagnostics mini-lab, not a course archive, not a raw-data
mirror, and not an operational forecast system.

Check the first screen for the project role:

- supporting atmospheric diagnostics module
- public-safe scientific-computing workflow
- not part of the `sbom-diff-and-risk` release surface
- not a separate meteorology portfolio

## 5-minute workflow review

Inspect:

- [`docs/methodology.md`](methodology.md)
- [`docs/calculation-methods.md`](calculation-methods.md)
- [`docs/diagnostic-analysis.md`](diagnostic-analysis.md)
- [`docs/station-precipitation-workflows.md`](station-precipitation-workflows.md)
- [`docs/climate-statistical-diagnostics.md`](climate-statistical-diagnostics.md)
- [`docs/focused-case-abstraction.md`](focused-case-abstraction.md)
- [`docs/data-policy.md`](data-policy.md)
- [`examples/synthetic-weather-diagnostics-report.md`](../examples/synthetic-weather-diagnostics-report.md)
- [`examples/sample_metadata.json`](../examples/sample_metadata.json)

This pass should show how local weather-analysis scripts were converted into
reusable calculation modules and reviewer-safe examples.

Questions to answer:

- Are field aliases separated from scientific calculations?
- Are dewpoint, vorticity, advection, regional means, and ensemble summaries
  described with equations or explicit numerical assumptions?
- Are station interpolation, precipitation accumulation conversion, and
  climate-statistics helpers documented with missing-data behavior?
- Are temperature-tendency components and ridge alpha-grid evaluation separated
  from original case-study prose and data?
- Are synthetic examples clearly labeled as synthetic?
- Are forecast-skill claims avoided unless real validation data are supplied?

## 15-minute reproducibility review

Run:

```bash
python -m pip install -e .[dev]
python -m pytest
python -m compileall src scripts
python scripts/run_thermodynamic_check.py --help
python scripts/run_dynamics_summary.py --help
python scripts/run_focused_case_summary.py --help
python scripts/run_precipitation_workflow.py --help
python scripts/run_climate_statistics.py --help
python scripts/run_synthetic_ensemble.py --help
```

Then run one synthetic path:

```bash
python scripts/run_focused_case_summary.py
python scripts/run_synthetic_ensemble.py --out outputs/synthetic_ensemble_summary.csv
```

Expected result:

- tests pass without raw ERA5, ECMWF, station, or course files
- CLI help surfaces are available
- the focused case command emits a tendency/model summary from synthetic arrays
- the ensemble command writes a small CSV under ignored `outputs/`
- no generated caches or output files need to be committed

## Boundaries

Read:

- [`docs/data-policy.md`](data-policy.md)
- [`PUBLICATION_BOUNDARIES.md`](../PUBLICATION_BOUNDARIES.md)
- [`SANITIZATION_REPORT.md`](../SANITIZATION_REPORT.md)
- [`docs/source-to-public-mapping.md`](source-to-public-mapping.md)

This project is portfolio evidence for Python scientific-computing structure,
not a public redistribution of raw weather data or course material.

## Technical Deep-Dive Route

For a deeper review, read the project in this order:

1. `src/python_weather_diagnostics_toolkit/aliases.py` for input-name
   normalization.
2. `src/python_weather_diagnostics_toolkit/thermodynamics.py` and
   `docs/calculation-methods.md` for dewpoint formulas and round-trip checks.
3. `src/python_weather_diagnostics_toolkit/dynamics.py` for grid spacing,
   vorticity, advection, temperature-tendency terms, and moisture flux
   divergence.
4. `src/python_weather_diagnostics_toolkit/precipitation.py` and
   `src/python_weather_diagnostics_toolkit/interpolation.py` for station and
   precipitation preparation helpers.
5. `src/python_weather_diagnostics_toolkit/climate.py` for anomaly,
   composite, and correlation helpers.
6. `src/python_weather_diagnostics_toolkit/features.py` for cosine-latitude
   regional means, time-ordered baseline modeling, and alpha-grid review.
7. `src/python_weather_diagnostics_toolkit/ensemble.py` for deterministic
   synthetic plume summaries.

This route should make the project reviewable as code, not just as a
documentation wrapper.
