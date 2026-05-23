"""Thermodynamic calculations used by the weather diagnostics mini-lab."""

from __future__ import annotations

import numpy as np


def _as_float_array(values) -> np.ndarray:
    return np.asarray(values, dtype=float)


def _rh_to_ratio(relative_humidity) -> np.ndarray:
    rh = _as_float_array(relative_humidity)
    ratio = np.where(rh > 1.5, rh / 100.0, rh)
    return np.clip(ratio, 1e-6, 1.0)


def magnus_dewpoint_celsius(
    temperature_celsius,
    relative_humidity,
    *,
    a: float = 17.625,
    b: float = 243.04,
) -> np.ndarray:
    """Estimate dewpoint temperature from temperature and relative humidity.

    Parameters
    ----------
    temperature_celsius:
        Air temperature in degrees Celsius.
    relative_humidity:
        Relative humidity as either 0-1 ratio or 0-100 percent.
    a, b:
        Magnus constants. The defaults are common over-water values.
    """

    temp = _as_float_array(temperature_celsius)
    rh_ratio = _rh_to_ratio(relative_humidity)
    gamma = np.log(rh_ratio) + (a * temp) / (b + temp)
    return (b * gamma) / (a - gamma)


def relative_humidity_from_dewpoint(
    temperature_celsius,
    dewpoint_celsius,
    *,
    a: float = 17.625,
    b: float = 243.04,
) -> np.ndarray:
    """Recover relative humidity ratio from temperature and dewpoint."""

    temp = _as_float_array(temperature_celsius)
    dewpoint = _as_float_array(dewpoint_celsius)
    saturation = np.exp((a * temp) / (b + temp))
    vapor = np.exp((a * dewpoint) / (b + dewpoint))
    return np.clip(vapor / saturation, 0.0, 1.0)


def kelvin_to_celsius(temperature_kelvin) -> np.ndarray:
    """Convert Kelvin values to degrees Celsius."""

    return _as_float_array(temperature_kelvin) - 273.15
