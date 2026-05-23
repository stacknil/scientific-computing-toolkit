import numpy as np

from python_weather_diagnostics_toolkit.dynamics import horizontal_advection, relative_vorticity


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
