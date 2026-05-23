import numpy as np

from python_weather_diagnostics_toolkit.interpolation import idw_interpolate_station_to_grid


def test_idw_interpolation_preserves_exact_station_match():
    station_lon = np.array([100.0, 101.0])
    station_lat = np.array([30.0, 31.0])
    station_values = np.array([10.0, 20.0])

    grid = idw_interpolate_station_to_grid(
        station_lon,
        station_lat,
        station_values,
        np.array([100.0, 101.0]),
        np.array([30.0, 31.0]),
    )

    assert grid[0, 0] == 10.0
    assert grid[1, 1] == 20.0


def test_idw_interpolation_ignores_missing_station_values():
    station_lon = np.array([100.0, 101.0])
    station_lat = np.array([30.0, 30.0])
    station_values = np.array([np.nan, 4.0])

    grid = idw_interpolate_station_to_grid(
        station_lon,
        station_lat,
        station_values,
        np.array([100.0]),
        np.array([30.0]),
    )

    assert grid[0, 0] == 4.0


def test_idw_interpolation_respects_min_neighbors():
    grid = idw_interpolate_station_to_grid(
        np.array([100.0]),
        np.array([30.0]),
        np.array([4.0]),
        np.array([100.0]),
        np.array([30.0]),
        min_neighbors=2,
    )

    assert np.isnan(grid[0, 0])
