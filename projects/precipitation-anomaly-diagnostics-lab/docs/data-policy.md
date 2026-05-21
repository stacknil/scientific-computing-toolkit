# Data Policy

This repository does not include raw climate datasets.

Users are responsible for obtaining data from original providers and following their licenses, access controls, citation requirements, and redistribution policies. This includes, but is not limited to, gridded precipitation products, reanalysis products, and SST datasets.

Publicly downloadable official datasets do not need privacy sanitization. They can be used directly as local inputs and referenced by provider/source in documentation. The repository still avoids committing raw climate data by default unless the dataset is small, explicitly redistributable, and intentionally added as a fixture or example.

## What Should Stay Out of Git

- Raw NetCDF, GRIB, HDF, Zarr, or other climate-data files, unless intentionally added as a small, redistributable fixture.
- Restricted, provider-controlled, or institution-distributed datasets.
- Course PDFs, slide decks, assignment sheets, reports, and templates.
- Personal notes, local absolute paths, usernames, or identifying metadata.
- Generated binary artifacts with unknown authorship or metadata.

## Recommended Local Layout

```text
data/
  raw/        # ignored; local provider data
  interim/    # ignored; local preprocessing outputs
outputs/      # ignored; generated diagnostics
configs/
  local.yaml  # ignored; local paths and private run settings
```

## Shareable Artifacts

Small derived CSV tables, sanitized figures, and scripts may be shared when they do not reveal private identity, school submission context, provider-restricted data, or license-restricted materials. When in doubt, regenerate outputs from a clean local run and inspect metadata before publication.
