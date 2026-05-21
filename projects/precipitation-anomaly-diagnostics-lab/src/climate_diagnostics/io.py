from __future__ import annotations

from pathlib import Path

import pandas as pd
import xarray as xr

from climate_diagnostics.grids import data_var, standardize_dataset


def open_field(path: str | Path, variable: str | None = None) -> xr.DataArray:
    """Open a NetCDF field and normalize coordinate names."""
    ds = xr.open_dataset(path)
    ds = standardize_dataset(ds)
    return data_var(ds, variable)


def read_year_table(path: str | Path, year_column: str = "year") -> pd.DataFrame:
    """Read a whitespace- or comma-delimited table with a year column."""
    table_path = Path(path)
    df = pd.read_csv(table_path, sep=None, engine="python")
    if len(df.columns) == 1:
        df = pd.read_csv(table_path, sep=r"\s+", engine="python")
    df.columns = [str(c).strip() for c in df.columns]
    year_match = next((c for c in df.columns if c.lower() == year_column.lower()), None)
    if year_match is None:
        year_match = next((c for c in df.columns if c.lower() in ("year", "yr")), None)
    if year_match is None:
        raise ValueError(f"Cannot find a year column in {table_path}. Columns: {list(df.columns)}")
    df = df.rename(columns={year_match: "year"})
    df["year"] = df["year"].astype(int)
    return df.sort_values("year").reset_index(drop=True)
