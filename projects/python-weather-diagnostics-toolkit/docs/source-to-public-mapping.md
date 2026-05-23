# Source-to-Public Mapping

This document explains how local weather-analysis materials were converted into
a public-safe technical project. It avoids preserving original filenames,
assignment framing, or private source context.

## Public Design Principle

The public project keeps reusable scientific-computing logic and discards
course-specific packaging. The result should look like a small technical module,
not a submitted report archive.

## Mapping Table

| Local analysis theme | Public module or document | What changed |
| --- | --- | --- |
| ERA5 field loading and variable-name handling | `aliases.py`, `configs/example.yaml` | local paths replaced by placeholders; aliases made reusable |
| surface temperature and wind plotting | `README.md`, `methodology.md` | plotting task reframed as diagnostics workflow |
| dewpoint verification | `thermodynamics.py`, `run_thermodynamic_check.py`, tests | formula isolated and tested with synthetic values |
| 500 hPa height and vorticity maps | `dynamics.py`, `diagnostic-analysis.md`, tests | map-specific code converted to numerical fields |
| 850 hPa temperature advection | `dynamics.py`, `run_dynamics_summary.py` | calculation made dependency-light and synthetic-testable |
| moisture transport diagnostics | `dynamics.py`, `diagnostic-analysis.md` | water-vapor process reframed as flux-divergence calculation |
| focused cold-season case-study report | `focused-case-abstraction.md`, `dynamics.py`, `features.py` | report structure abstracted into tendency decomposition and alpha-grid review |
| station observation cleaning and interpolation | `precipitation.py`, `interpolation.py`, `station-precipitation-workflows.md` | sentinel handling and IDW interpolation made synthetic-testable |
| accumulated precipitation conversion | `precipitation.py`, `station-precipitation-workflows.md` | forecast accumulations converted without redistributing products |
| anomaly, composite, and correlation exercises | `climate.py`, `climate-statistical-diagnostics.md` | statistical methods separated from local datasets |
| regional feature construction | `features.py` | area weighting and target shifting made explicit |
| simple temperature prediction baseline | `features.py`, `diagnostic-analysis.md` | baseline framed as workflow sanity check, not forecast skill |
| ensemble plume exercises | `ensemble.py`, `run_synthetic_ensemble.py` | real or teaching data replaced by deterministic synthetic data |
| generated figures and reports | `examples/synthetic-weather-diagnostics-report.md` | binary outputs replaced by text explanation |
| course documents and templates | excluded | not suitable for public repository |
| raw NetCDF and station data | excluded | users must obtain data from providers |

## Why Not Preserve Original Scripts?

The original scripts mixed local paths, case-specific assumptions, plotting
side effects, and report-oriented output names. The public version separates:

- calculation functions in `src/`
- CLI smoke paths in `scripts/`
- reproducibility checks in `tests/`
- public interpretation in `docs/` and `examples/`

This makes the project easier to review and safer to publish.

## What Technical Substance Was Preserved?

Preserved:

- ERA5-style gridded data handling
- humidity and dewpoint diagnostics
- geopotential-height conversion
- relative-vorticity and advection calculations
- dry temperature-tendency term decomposition
- moisture flux divergence
- station interpolation and precipitation accumulation conversion
- anomaly, composite, and correlation helpers
- regional feature engineering
- time-ordered baseline modeling
- ridge alpha-grid metric review
- ensemble summary interpretation

Not preserved:

- private filenames or source-folder structure
- raw datasets
- provider account material
- classroom prompts or report templates
- generated binary artifacts with unknown metadata
- personal or institutional identifiers
