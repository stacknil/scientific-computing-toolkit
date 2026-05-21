# Reproducibility

## Environment

Create an isolated Python environment and install the project in editable mode:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e .
```

## Configuration

Use the example configuration as a template:

```powershell
Copy-Item configs/example.yaml configs/local.yaml
```

Replace placeholder paths with local dataset locations. Keep `configs/local.yaml` out of Git because it may contain local paths or private data locations.

## Deterministic Runs

The main diagnostics are deterministic for fixed input files, region definitions, and periods. Scripts write derived outputs under `outputs/` by default. Remove the output directory before a clean rerun if you want a fresh artifact set.

## Validation

At minimum, run:

```powershell
python -m compileall src scripts
```

For data-backed validation, run the target scripts against local data and compare:

- Number of years selected.
- Coordinate ranges.
- Variable names.
- Output file names.
- Whether figures and CSVs are regenerated without manual edits.

## Final Public-Release Checklist

- [ ] No raw datasets included.
- [ ] No personal identifiers.
- [ ] No school identifiers.
- [ ] No local paths.
- [ ] No course submission artifacts.
- [ ] No secrets or credentials.
- [ ] No generated binary artifacts with unknown metadata.
