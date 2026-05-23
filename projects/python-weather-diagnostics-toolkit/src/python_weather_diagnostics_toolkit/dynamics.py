"""Dynamic diagnostics for regular latitude/longitude weather fields."""

from __future__ import annotations

import numpy as np

EARTH_RADIUS_M = 6_371_000.0
STANDARD_GRAVITY = 9.80665
DRY_AIR_GAS_CONSTANT = 287.05
SPECIFIC_HEAT_DRY_AIR = 1004.0
DRY_ADIABATIC_KAPPA = DRY_AIR_GAS_CONSTANT / SPECIFIC_HEAT_DRY_AIR
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

    return horizontal_advection_components(scalar, u_wind, v_wind, latitude, longitude)[
        "horizontal_advection"
    ]


def horizontal_advection_components(
    scalar,
    u_wind,
    v_wind,
    latitude,
    longitude,
) -> dict[str, np.ndarray]:
    """Compute zonal, meridional, and total horizontal advection."""

    scalar_values = np.asarray(scalar, dtype=float)
    dscalar_dy, dscalar_dx = gradient_on_latlon(scalar, latitude, longitude)
    u_values = _matching_field("u_wind", u_wind, scalar_values.shape)
    v_values = _matching_field("v_wind", v_wind, scalar_values.shape)
    zonal = -(u_values * dscalar_dx)
    meridional = -(v_values * dscalar_dy)
    return {
        "zonal_advection": zonal,
        "meridional_advection": meridional,
        "horizontal_advection": zonal + meridional,
    }


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


def temperature_tendency_terms(
    temperature,
    u_wind,
    v_wind,
    omega,
    pressure_hpa,
    latitude,
    longitude,
    *,
    pressure_axis: int = 0,
) -> dict[str, np.ndarray]:
    """Decompose dry pressure-coordinate temperature tendency terms."""

    temp = np.asarray(temperature, dtype=float)
    u_values = np.asarray(u_wind, dtype=float)
    v_values = np.asarray(v_wind, dtype=float)
    omega_values = np.asarray(omega, dtype=float)
    if temp.shape != u_values.shape or temp.shape != v_values.shape or temp.shape != omega_values.shape:
        raise ValueError("temperature, wind, and omega arrays must have matching shapes")
    if temp.ndim != 3:
        raise ValueError("temperature tendency terms require pressure, latitude, and longitude dimensions")

    pressure_pa = np.asarray(pressure_hpa, dtype=float) * 100.0
    if pressure_pa.ndim != 1:
        raise ValueError("pressure_hpa must be one-dimensional")
    if pressure_pa.size != temp.shape[pressure_axis]:
        raise ValueError("pressure_hpa length must match the selected pressure axis")
    if not np.isfinite(pressure_pa).all() or np.any(pressure_pa <= 0.0):
        raise ValueError("pressure_hpa must contain positive finite values")
    if np.any(np.isclose(np.diff(pressure_pa), 0.0)):
        raise ValueError("pressure_hpa must not contain duplicate adjacent levels")

    temp_moved = np.moveaxis(temp, pressure_axis, 0)
    u_moved = np.moveaxis(u_values, pressure_axis, 0)
    v_moved = np.moveaxis(v_values, pressure_axis, 0)
    omega_moved = np.moveaxis(omega_values, pressure_axis, 0)
    if temp_moved.shape[1:] != (np.asarray(latitude).size, np.asarray(longitude).size):
        raise ValueError("latitude and longitude lengths must match the horizontal field dimensions")

    zonal = np.empty_like(temp_moved)
    meridional = np.empty_like(temp_moved)
    horizontal = np.empty_like(temp_moved)
    for level_idx in range(temp_moved.shape[0]):
        components = horizontal_advection_components(
            temp_moved[level_idx],
            u_moved[level_idx],
            v_moved[level_idx],
            latitude,
            longitude,
        )
        zonal[level_idx] = components["zonal_advection"]
        meridional[level_idx] = components["meridional_advection"]
        horizontal[level_idx] = components["horizontal_advection"]

    dtemp_dp = np.gradient(temp_moved, pressure_pa, axis=0)
    vertical = -(omega_moved * dtemp_dp)
    pressure_shape = (pressure_pa.size,) + (1,) * (temp_moved.ndim - 1)
    adiabatic = DRY_ADIABATIC_KAPPA * temp_moved * omega_moved / pressure_pa.reshape(pressure_shape)
    dry_dynamic = horizontal + vertical + adiabatic

    def restore(values: np.ndarray) -> np.ndarray:
        return np.moveaxis(values, 0, pressure_axis)

    return {
        "zonal_advection": restore(zonal),
        "meridional_advection": restore(meridional),
        "horizontal_advection": restore(horizontal),
        "vertical_advection": restore(vertical),
        "adiabatic_compression": restore(adiabatic),
        "dry_dynamic_tendency": restore(dry_dynamic),
    }
