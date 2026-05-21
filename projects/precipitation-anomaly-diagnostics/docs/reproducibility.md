# Reproducibility

## Environment

Create a Python environment and install the package:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

## Configuration

Copy `configs/example.yaml` to a local, gitignored file:

```bash
cp configs/example.yaml configs/local.yaml
```

Edit local paths under `paths:` so they point to datasets stored outside the public repository or under a gitignored `data/` directory.

## Pipeline

```bash
python scripts/run_preprocessing.py --config configs/local.yaml
python scripts/run_eof_analysis.py --config configs/local.yaml
python scripts/run_composite_analysis.py --config configs/local.yaml --field /path/to/field.nc --variable hgt --years 1973,1975,1983
```

## Public Release Checklist

- [ ] No raw datasets included.
- [ ] No personal identifiers included.
- [ ] No institution or course identifiers included.
- [ ] No local absolute paths included.
- [ ] No course submission artifacts included.
- [ ] No secrets, API keys, credentials, or tokens included.
- [ ] No generated binary artifacts with unknown metadata included.
- [ ] All local configs are ignored by `.gitignore`.

## Known Reproducibility Limits

This public repository cannot fully reproduce the scientific results until users provide compatible local datasets. The included figures and CSV files are derived demonstration artifacts.
