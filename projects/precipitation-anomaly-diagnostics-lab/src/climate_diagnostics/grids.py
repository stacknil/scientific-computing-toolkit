from __future__ import annotations

from typing import Iterable

import numpy as np
import pandas as pd
import xarray as xr


TIME_NAMES = ("time", "Time", "TIME", "date", "year", "Year", "YEAR")
LAT_NAMES = ("latitude", "lat", "LAT", "Latitude", "y")
LON_NAMES = ("longitude", "lon", "LON", "Longitude", "x")


def guess_name(obj: xr.Dataset | xr.DataArray, candidates: Iterable[str]) -> str | None:
    """Guess a coordinate, dimension, or variable name."""
    for name in candidates:
        if name in obj.coords or name in obj.dims:
            return name
        if isinstance(obj, xr.Dataset) and name in obj.variables:
            return name
    return None


def standardize_dataset(
    ds: xr.Dataset,
    time: str | None = None,
    latitude: str | None = None,
    longitude: str | None = None,
) -> xr.Dataset:
    """Rename common coordinate names to time, latitude, and longitude."""
    time_name = time or guess_name(ds, TIME_NAMES)
    lat_name = latitude or guess_name(ds, LAT_NAMES)
    lon_name = longitude or guess_name(ds, LON_NAMES)

    rename: dict[str, str] = {}
    if time_name and time_name != "time":
        rename[time_name] = "time"
    if lat_name and lat_name != "latitude":
        rename[lat_name] = "latitude"
    if lon_name and lon_name != "longitude":
        rename[lon_name] = "longitude"
    if rename:
        ds = ds.rename(rename)

    missing = [name for name in ("time", "latitude", "longitude") if name not in ds.coords and name not in ds.dims]
    if missing:
        raise ValueError(f"Missing coordinates or dimensions: {missing}. Found dims={list(ds.dims)} coords={list(ds.coords)}")
    return ds


def data_var(ds: xr.Dataset, preferred: str | None = None) -> xr.DataArray:
    """Return the requested data variable, or the first available variable."""
    if preferred:
        if preferred not in ds.data_vars:
            raise KeyError(f"Variable {preferred!r} not found. Available variables: {list(ds.data_vars)}")
        return ds[preferred]
    if not ds.data_vars:
        raise ValueError("Dataset contains no data variables.")
    return ds[next(iter(ds.data_vars))]


def years_from_time(da: xr.DataArray) -> np.ndarray:
    """Convert the time coordinate to integer years."""
    if "time" not in da.coords:
        raise ValueError("DataArray must include a time coordinate.")
    values = da["time"].values
    if np.issubdtype(values.dtype, np.datetime64):
        return pd.to_datetime(values).year.astype(int)
    try:
        return da["time"].dt.year.values.astype(int)
    except Exception:
        return np.asarray(values, dtype=float).astype(int)


def select_years(da: xr.DataArray, start: int | None = None, end: int | None = None) -> xr.DataArray:
    """Select a time range by integer year."""
    years = years_from_time(da)
    mask = np.ones_like(years, dtype=bool)
    if start is not None:
        mask &= years >= int(start)
    if end is not None:
        mask &= years <= int(end)
    return da.sel(time=da["time"].where(xr.DataArray(mask, dims=("time",), coords={"time": da["time"]}), drop=True))


def subset_box(da: xr.DataArray, box: dict[str, float] | None) -> xr.DataArray:
    """Subset a latitude/longitude box when a box is provided."""
    if not box:
        return da
    lon_min = box.get("lon_min", float(da.longitude.min()))
    lon_max = box.get("lon_max", float(da.longitude.max()))
    lat_min = box.get("lat_min", float(da.latitude.min()))
    lat_max = box.get("lat_max", float(da.latitude.max()))
    lat_values = da.latitude.values
    lat_slice = slice(lat_min, lat_max) if lat_values[0] <= lat_values[-1] else slice(lat_max, lat_min)
    return da.sel(longitude=slice(lon_min, lon_max), latitude=lat_slice)


def area_mean(da: xr.DataArray) -> xr.DataArray:
    """Cosine-latitude weighted mean over latitude and longitude."""
    weights = np.cos(np.deg2rad(da["latitude"]))
    return da.weighted(weights).mean(dim=("latitude", "longitude"), skipna=True)


def align_by_year(da: xr.DataArray, years: np.ndarray) -> xr.DataArray:
    """Select a DataArray by integer years and preserve the time coordinate."""
    da_years = years_from_time(da)
    keep = np.isin(da_years, years)
    return da.sel(time=da["time"].where(xr.DataArray(keep, dims=("time",), coords={"time": da["time"]}), drop=True))
