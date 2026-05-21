from __future__ import annotations

from collections.abc import Iterable

import xarray as xr


def composite_by_years(field: xr.DataArray, years: Iterable[int]) -> xr.DataArray:
    """Average a field over selected calendar years."""
    years_set = set(int(year) for year in years)
    selected = field.sel(time=field["time.year"].isin(years_set))
    return selected.mean("time", skipna=True)


def composite_anomaly(field: xr.DataArray, years: Iterable[int], climatology: xr.DataArray) -> xr.DataArray:
    """Composite anomaly relative to a provided climatology."""
    return composite_by_years(field, years) - climatology
