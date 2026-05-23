import numpy as np
import pytest

from python_weather_diagnostics_toolkit.dynamics import (
    gradient_on_latlon,
    horizontal_advection,
    moisture_flux_divergence,
    relative_vorticity,
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
