# Data Policy

This repository does not redistribute raw climate datasets.

## Raw Data

Users are expected to obtain gridded precipitation and reanalysis datasets from original providers and follow the corresponding licensing, citation, and access policies.

Examples of compatible data types:

- gridded monthly precipitation datasets;
- NCEP/NCAR-style reanalysis fields;
- wind, geopotential height, and omega variables.

## What Is Included

The repository includes only:

- small derived CSV summaries;
- derived demonstration figures;
- reusable code;
- configuration templates;
- public-facing documentation.

## What Is Excluded

The repository intentionally excludes:

- raw NetCDF or GRIB climate datasets;
- institutional course documents;
- presentation decks and word-processing reports;
- local-machine paths;
- personal identifiers;
- credentials or tokens.

## Reproducing the Workflow

To reproduce the full workflow, place locally obtained datasets outside the repository or under a gitignored `data/` directory, then point `configs/local.yaml` to those paths.
