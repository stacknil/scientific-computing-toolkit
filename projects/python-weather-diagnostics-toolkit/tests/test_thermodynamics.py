import numpy as np

from python_weather_diagnostics_toolkit.thermodynamics import (
    magnus_dewpoint_celsius,
    relative_humidity_from_dewpoint,
)


def test_magnus_dewpoint_roundtrip_relative_humidity():
    temperature = np.array([20.0, 25.0, 30.0])
    rh_percent = np.array([50.0, 65.0, 80.0])

    dewpoint = magnus_dewpoint_celsius(temperature, rh_percent)
    rh_back = relative_humidity_from_dewpoint(temperature, dewpoint)

    np.testing.assert_allclose(rh_back, rh_percent / 100.0, atol=1e-10)


def test_dewpoint_never_exceeds_temperature_for_unsaturated_air():
    temperature = np.array([10.0, 15.0, 20.0])
    dewpoint = magnus_dewpoint_celsius(temperature, 70.0)

    assert np.all(dewpoint <= temperature)
