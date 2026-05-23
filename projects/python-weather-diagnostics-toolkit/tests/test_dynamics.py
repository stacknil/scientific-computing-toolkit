import numpy as np
import pytest

from python_weather_diagnostics_toolkit.dynamics import (
    DRY_ADIABATIC_KAPPA,
    gradient_on_latlon,
    horizontal_advection,
    horizontal_advection_components,
    moisture_flux_divergence,
    relative_vorticity,
    temperature_tendency_terms,
)


def test_constant_flow_has_zero_relative_vorticity():
    lat = np.linspace(30.0, 35.0, 5)
    lon = np.linspace(100.0, 105.0, 6)
    u = np.ones((lat.size, lon.size)) * 5.0
    v = np.ones_like(u) * -2.0

    vort = relative_vorticity(u, v, lat, lon)

    np.testing.assert_allclose(vort, 0.0, atol=1e-15)


def test_eastward_flow_advects_eastward_increasing_scalar_negatively():
    lat = np.linspace(30.0, 35.0, 5)
    lon = np.linspace(100.0, 105.0, 6)
    scalar = np.tile(lon, (lat.size, 1))
    u = np.ones_like(scalar) * 10.0
    v = np.zeros_like(scalar)

    adv = horizontal_advection(scalar, u, v, lat, lon)

    assert np.all(adv < 0.0)


def test_horizontal_advection_components_sum_to_total():
    lat = np.linspace(30.0, 35.0, 5)
    lon = np.linspace(100.0, 105.0, 6)
    scalar = np.tile(lon, (lat.size, 1))
    u = np.ones_like(scalar) * 10.0
    v = np.zeros_like(scalar)

    terms = horizontal_advection_components(scalar, u, v, lat, lon)

    np.testing.assert_allclose(
        terms["horizontal_advection"],
        terms["zonal_advection"] + terms["meridional_advection"],
    )
    np.testing.assert_allclose(terms["meridional_advection"], 0.0)


def test_zonal_gradient_masks_exact_pole_rows_without_infinity():
    lat = np.array([-90.0, -45.0, 0.0, 45.0, 90.0])
    lon = np.linspace(0.0, 3.0, 4)
    field = np.tile(lon, (lat.size, 1))

    _, d_dx = gradient_on_latlon(field, lat, lon)

    assert np.isnan(d_dx[0]).all()
    assert np.isnan(d_dx[-1]).all()
    assert np.isfinite(d_dx[1:-1]).all()


def test_horizontal_advection_rejects_mismatched_wind_shape():
    lat = np.linspace(30.0, 35.0, 5)
    lon = np.linspace(100.0, 105.0, 6)
    scalar = np.ones((lat.size, lon.size))
    u = np.ones((lat.size, lon.size - 1))
    v = np.ones_like(scalar)

    with pytest.raises(ValueError, match="u_wind shape"):
        horizontal_advection(scalar, u, v, lat, lon)


def test_uniform_moisture_flux_has_zero_divergence():
    lat = np.linspace(30.0, 35.0, 5)
    lon = np.linspace(100.0, 105.0, 6)
    q = np.ones((lat.size, lon.size)) * 0.01
    u = np.ones_like(q) * 5.0
    v = np.ones_like(q) * -2.0

    divergence = moisture_flux_divergence(q, u, v, lat, lon)

    np.testing.assert_allclose(divergence, 0.0, atol=1e-15)


def test_temperature_tendency_terms_include_adiabatic_compression():
    pressure = np.array([900.0, 850.0, 800.0])
    lat = np.linspace(30.0, 35.0, 5)
    lon = np.linspace(100.0, 105.0, 6)
    temperature = np.broadcast_to(
        280.0 + np.arange(pressure.size)[:, None, None] * 0.0 + lon[None, None, :] * 0.1,
        (pressure.size, lat.size, lon.size),
    ).copy()
    u = np.ones_like(temperature) * 10.0
    v = np.zeros_like(temperature)
    omega = np.ones_like(temperature) * 0.2

    terms = temperature_tendency_terms(temperature, u, v, omega, pressure, lat, lon)

    expected_adiabatic = (
        DRY_ADIABATIC_KAPPA
        * temperature
        * omega
        / (pressure[:, None, None] * 100.0)
    )
    assert np.all(terms["zonal_advection"] < 0.0)
    np.testing.assert_allclose(terms["meridional_advection"], 0.0)
    np.testing.assert_allclose(terms["vertical_advection"], 0.0, atol=1e-15)
    np.testing.assert_allclose(terms["adiabatic_compression"], expected_adiabatic)


def test_temperature_tendency_terms_reject_misaligned_pressure_axis():
    pressure = np.array([900.0, 850.0])
    lat = np.linspace(30.0, 35.0, 5)
    lon = np.linspace(100.0, 105.0, 6)
    field = np.ones((3, lat.size, lon.size))

    with pytest.raises(ValueError, match="pressure_hpa length"):
        temperature_tendency_terms(field, field, field, field, pressure, lat, lon)
