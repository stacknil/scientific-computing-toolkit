"""Lightweight station-to-grid interpolation utilities."""

from __future__ import annotations

import numpy as np


def _one_dimensional(name: str, values) -> np.ndarray:
    array = np.asarray(values, dtype=float)
    if array.ndim != 1:
        raise ValueError(f"{name} must be one-dimensional")
    return array


def _grid_mesh(longitude, latitude) -> tuple[np.ndarray, np.ndarray]:
    lon = np.asarray(longitude, dtype=float)
    lat = np.asarray(latitude, dtype=float)
    if lon.ndim == 1 and lat.ndim == 1:
        return np.meshgrid(lon, lat)
    if lon.shape != lat.shape:
        raise ValueError("grid longitude and latitude must both be 1D or have matching shapes")
    return lon, lat


def idw_interpolate_station_to_grid(
    station_longitude,
    station_latitude,
    station_values,
    grid_longitude,
    grid_latitude,
    *,
    power: float = 2.0,
    max_distance_degrees: float | None = None,
    min_neighbors: int = 1,
) -> np.ndarray:
    """Interpolate station values to a regular or curvilinear grid with IDW."""

    station_lon = _one_dimensional("station_longitude", station_longitude)
    station_lat = _one_dimensional("station_latitude", station_latitude)
    values = _one_dimensional("station_values", station_values)
    if not (station_lon.size == station_lat.size == values.size):
        raise ValueError("station longitude, latitude, and values must have matching lengths")
    if power <= 0.0:
        raise ValueError("power must be positive")
    if min_neighbors <= 0:
        raise ValueError("min_neighbors must be positive")
    if max_distance_degrees is not None and max_distance_degrees <= 0.0:
        raise ValueError("max_distance_degrees must be positive when provided")

    grid_lon, grid_lat = _grid_mesh(grid_longitude, grid_latitude)
    output = np.full(grid_lon.shape, np.nan, dtype=float)
    valid = np.isfinite(station_lon) & np.isfinite(station_lat) & np.isfinite(values)
    if valid.sum() < min_neighbors:
        return output

    station_lon = station_lon[valid]
    station_lat = station_lat[valid]
    values = values[valid]

    flat_lon = grid_lon.ravel()
    flat_lat = grid_lat.ravel()
    flat_output = output.ravel()
    for idx, (lon, lat) in enumerate(zip(flat_lon, flat_lat, strict=True)):
        if not np.isfinite(lon) or not np.isfinite(lat):
            continue
        dlon = (station_lon - lon) * np.cos(np.deg2rad(lat))
        dlat = station_lat - lat
        distance = np.hypot(dlon, dlat)
        exact = np.isclose(distance, 0.0)
        if exact.any():
            flat_output[idx] = float(np.nanmean(values[exact]))
            continue
        neighbor = np.isfinite(distance)
        if max_distance_degrees is not None:
            neighbor &= distance <= max_distance_degrees
        if neighbor.sum() < min_neighbors:
            continue
        weights = 1.0 / np.power(distance[neighbor], power)
        flat_output[idx] = float(np.sum(weights * values[neighbor]) / np.sum(weights))
    return output
