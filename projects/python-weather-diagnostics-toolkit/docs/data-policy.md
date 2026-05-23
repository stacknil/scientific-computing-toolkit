# Data Policy

This project is designed around reproducible methods, not redistributed raw
weather datasets.

## Included

- reusable Python source code
- configuration templates with placeholder paths
- deterministic synthetic examples
- small text summaries and documentation
- tests that run without external datasets

## Excluded

- raw ERA5, ECMWF, NetCDF, GRIB, HDF, station, or forecast files
- raw course PDFs, PowerPoint decks, Word templates, assignment instructions, or reports
- local-machine paths and usernames
- personal, institutional, classroom, or collaborator identifiers
- provider account material or local access configuration
- generated binary artifacts with unknown metadata

## User Responsibility

Users who run this toolkit on real weather data must obtain datasets from their
original providers and follow the providers' access, citation, redistribution,
and licensing policies. For ERA5-style workflows, that usually means obtaining
data through the Copernicus Climate Data Store or another authorized provider.

The repository intentionally avoids bundling downloader access material. If a
user uses `cdsapi` or another data client, provider account material should
remain in local user configuration outside this repository.

## Public Outputs

Public outputs should be limited to small derived summaries, synthetic
demonstrations, or figures with metadata stripped or regenerated from public-safe
inputs. Do not commit raw data, private station files, or binary course
materials.
