"""Small deterministic synthetic fields for examples and tests."""

from __future__ import annotations

import numpy as np
import xarray as xr


def make_synthetic_weather_dataset() -> xr.Dataset:
    """Create a tiny ERA5-like dataset with no real climate data."""

    lat = np.linspace(30.0, 45.0, 6)
    lon = np.linspace(105.0, 125.0, 8)
    lon2d, lat2d = np.meshgrid(lon, lat)

    t2m = 273.15 + 2.0 + 0.12 * (lon2d - 105.0) - 0.35 * (lat2d - 30.0)
    t850 = 273.15 - 4.0 - 0.25 * (lat2d - 30.0)
    z500 = 5_650.0 + 12.0 * (lat2d - 37.5) - 5.0 * (lon2d - 115.0)
    u850 = 8.0 + 0.05 * (lat2d - 37.5)
    v850 = -2.0 + 0.08 * (lon2d - 115.0)
    relative_humidity = 65.0 + 10.0 * np.sin(np.deg2rad(lon2d))

    return xr.Dataset(
        data_vars={
            "t2m": (("latitude", "longitude"), t2m),
            "temperature": (("pressure_level", "latitude", "longitude"), np.stack([z500 * 0 + t850])),
            "geopotential": (("pressure_level", "latitude", "longitude"), np.stack([z500 * 9.80665])),
            "u": (("pressure_level", "latitude", "longitude"), np.stack([u850])),
            "v": (("pressure_level", "latitude", "longitude"), np.stack([v850])),
            "relative_humidity": (("pressure_level", "latitude", "longitude"), np.stack([relative_humidity])),
        },
        coords={
            "pressure_level": [850],
            "latitude": lat,
            "longitude": lon,
        },
        attrs={
            "source": "synthetic",
            "note": "Deterministic toy data for documentation and tests only.",
        },
    )
