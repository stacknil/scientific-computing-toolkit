"""Dynamic diagnostics for regular latitude/longitude weather fields."""

from __future__ import annotations

import numpy as np

EARTH_RADIUS_M = 6_371_000.0
STANDARD_GRAVITY = 9.80665
POLAR_COSINE_TOLERANCE = 1e-12


def geopotential_to_height(geopotential) -> np.ndarray:
    """Convert geopotential from m2/s2 to geopotential height in meters."""

    return np.asarray(geopotential, dtype=float) / STANDARD_GRAVITY


def _spacing_m(latitude, longitude) -> tuple[np.ndarray, np.ndarray]:
    lat = np.asarray(latitude, dtype=float)
    lon = np.asarray(longitude, dtype=float)
    if lat.ndim != 1 or lon.ndim != 1:
        raise ValueError("latitude and longitude must be one-dimensional")
    if lat.size < 2 or lon.size < 2:
        raise ValueError("latitude and longitude must contain at least two points")

    dlat = np.gradient(np.deg2rad(lat))
    dlon = np.gradient(np.deg2rad(lon))
    dy = EARTH_RADIUS_M * dlat
    cos_lat = np.cos(np.deg2rad(lat))
    cos_lat = np.where(np.abs(cos_lat) <= POLAR_COSINE_TOLERANCE, np.nan, cos_lat)
    dx = EARTH_RADIUS_M * cos_lat[:, None] * dlon[None, :]
    return dy[:, None], dx


def gradient_on_latlon(field, latitude, longitude) -> tuple[np.ndarray, np.ndarray]:
    """Return d(field)/dy and d(field)/dx on a regular lat/lon grid."""

    values = np.asarray(field, dtype=float)
    if values.ndim != 2:
        raise ValueError("field must be a two-dimensional latitude/longitude array")

    dy, dx = _spacing_m(latitude, longitude)
    if values.shape != dx.shape:
        raise ValueError(
            "field shape must match latitude/longitude lengths: "
            f"{values.shape} != {dx.shape}"
        )

    d_dindex_y = np.gradient(values, axis=0)
    d_dindex_x = np.gradient(values, axis=1)
    with np.errstate(divide="ignore", invalid="ignore"):
        return d_dindex_y / dy, d_dindex_x / dx


def relative_vorticity(u_wind, v_wind, latitude, longitude) -> np.ndarray:
    """Compute relative vorticity, zeta = dv/dx - du/dy, in s^-1."""

    du_dy, _ = gradient_on_latlon(u_wind, latitude, longitude)
    _, dv_dx = gradient_on_latlon(v_wind, latitude, longitude)
    return dv_dx - du_dy


def _matching_field(name: str, field, expected_shape: tuple[int, int]) -> np.ndarray:
    values = np.asarray(field, dtype=float)
    if values.shape != expected_shape:
        raise ValueError(f"{name} shape must match scalar field shape: {values.shape} != {expected_shape}")
    return values


def horizontal_advection(scalar, u_wind, v_wind, latitude, longitude) -> np.ndarray:
    """Compute horizontal advection, -(u dS/dx + v dS/dy)."""

    scalar_values = np.asarray(scalar, dtype=float)
    dscalar_dy, dscalar_dx = gradient_on_latlon(scalar, latitude, longitude)
    u_values = _matching_field("u_wind", u_wind, scalar_values.shape)
    v_values = _matching_field("v_wind", v_wind, scalar_values.shape)
    return -(u_values * dscalar_dx + v_values * dscalar_dy)


def moisture_flux_divergence(
    specific_humidity,
    u_wind,
    v_wind,
    latitude,
    longitude,
) -> np.ndarray:
    """Compute horizontal divergence of specific-humidity flux."""

    q_values = np.asarray(specific_humidity, dtype=float)
    if q_values.ndim != 2:
        raise ValueError("specific_humidity must be a two-dimensional latitude/longitude array")
    u_values = _matching_field("u_wind", u_wind, q_values.shape)
    v_values = _matching_field("v_wind", v_wind, q_values.shape)
    _, dqu_dx = gradient_on_latlon(q_values * u_values, latitude, longitude)
    dqv_dy, _ = gradient_on_latlon(q_values * v_values, latitude, longitude)
    return dqu_dx + dqv_dy
