"""Coordinate and variable aliases for ERA5-style weather datasets."""

from __future__ import annotations

from collections.abc import Iterable

import xarray as xr

COORDINATE_ALIASES: dict[str, tuple[str, ...]] = {
    "time": ("time", "valid_time"),
    "latitude": ("latitude", "lat"),
    "longitude": ("longitude", "lon"),
    "pressure_level": ("pressure_level", "level", "isobaricInhPa"),
}

VARIABLE_ALIASES: dict[str, tuple[str, ...]] = {
    "t2m": ("t2m", "2m_temperature", "2t"),
    "d2m": ("d2m", "2m_dewpoint_temperature", "2d"),
    "u10": ("u10", "10m_u_component_of_wind", "10u"),
    "v10": ("v10", "10m_v_component_of_wind", "10v"),
    "tp": ("tp", "total_precipitation"),
    "temperature": ("t", "temperature"),
    "relative_humidity": ("r", "relative_humidity"),
    "u": ("u", "u_component_of_wind"),
    "v": ("v", "v_component_of_wind"),
    "omega": ("w", "omega", "vertical_velocity"),
    "geopotential": ("z", "geopotential"),
    "relative_vorticity": ("vo", "relative_vorticity"),
    "msl": ("msl", "mean_sea_level_pressure"),
}


def _first_present(candidates: Iterable[str], names: Iterable[str]) -> str | None:
    available = set(names)
    for candidate in candidates:
        if candidate in available:
            return candidate
    return None


def standardize_coordinates(ds: xr.Dataset) -> xr.Dataset:
    """Rename common ERA5 coordinate variants to canonical names.

    The function intentionally avoids mutating data variables. It only renames
    coordinates/dimensions when a canonical name is absent and a known alias is
    present.
    """

    rename: dict[str, str] = {}
    names = set(ds.coords) | set(ds.dims)
    for canonical, aliases in COORDINATE_ALIASES.items():
        if canonical in names:
            continue
        found = _first_present(aliases, names)
        if found is not None and found != canonical:
            rename[found] = canonical

    out = ds.rename(rename) if rename else ds
    if "latitude" in out.coords and out.latitude.size > 1:
        values = out.latitude.values
        if values[0] > values[-1]:
            out = out.sortby("latitude")
    return out


def get_data_array(ds: xr.Dataset, canonical_name: str) -> xr.DataArray:
    """Return a data variable by canonical name or known alias."""

    if canonical_name in ds.data_vars:
        return ds[canonical_name]

    aliases = VARIABLE_ALIASES.get(canonical_name, (canonical_name,))
    found = _first_present(aliases, ds.data_vars)
    if found is None:
        available = ", ".join(sorted(ds.data_vars))
        raise KeyError(f"Missing variable '{canonical_name}'. Available variables: {available}")
    return ds[found]
