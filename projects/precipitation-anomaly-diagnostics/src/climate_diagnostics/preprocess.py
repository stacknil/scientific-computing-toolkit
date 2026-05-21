from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import xarray as xr


def _coordinate_slice(coord: xr.DataArray, lower: float, upper: float) -> slice:
    if coord.size == 0:
        raise ValueError("Cannot subset an empty coordinate.")
    if float(coord[0]) <= float(coord[-1]):
        return slice(lower, upper)
    return slice(upper, lower)


def subset_region(field: xr.DataArray, region: dict[str, float]) -> xr.DataArray:
    """Subset a gridded field to lon/lat bounds."""
    return field.sel(
        lon=_coordinate_slice(field.lon, region["lon_min"], region["lon_max"]),
        lat=_coordinate_slice(field.lat, region["lat_min"], region["lat_max"]),
    )


def select_month(field: xr.DataArray, month: int) -> xr.DataArray:
    """Select one calendar month from a monthly time series."""
    return field.sel(time=field["time.month"] == month)


def climatology(field: xr.DataArray, start_year: int, end_year: int) -> xr.DataArray:
    """Compute climatology over an inclusive year range."""
    selected = field.sel(time=slice(f"{start_year}-01-01", f"{end_year}-12-31"))
    return selected.mean("time", skipna=True)


def anomaly(field: xr.DataArray, reference: xr.DataArray) -> xr.DataArray:
    """Return anomalies relative to a reference climatology."""
    return field - reference


def area_weighted_mean(field: xr.DataArray) -> xr.DataArray:
    """Compute a latitude-weighted spatial mean."""
    weights = xr.DataArray(np.cos(np.deg2rad(field.lat)), coords={"lat": field.lat}, dims="lat")
    return field.weighted(weights).mean(("lat", "lon"), skipna=True)


def build_precipitation_anomaly_dataset(config: dict[str, Any]) -> xr.Dataset:
    """Open precipitation data and build a regional monthly anomaly dataset."""
    path = Path(config["paths"]["precipitation_file"])
    var_name = config["variables"]["precipitation"]
    month = int(config["analysis"]["month"])
    period = config["analysis"]["climatology_period"]
    region = config["analysis"]["region"]

    dataset = xr.open_dataset(path)
    precip = subset_region(dataset[var_name], region)
    precip_month = select_month(precip, month)
    reference = climatology(precip_month, int(period[0]), int(period[1]))
    anomalies = anomaly(precip_month, reference)
    anomalies.name = "precipitation_anomaly"
    return anomalies.to_dataset()
