from __future__ import annotations

import numpy as np
import pandas as pd
import xarray as xr

from climate_diagnostics.preprocess import area_weighted_mean, build_precipitation_anomaly_dataset, subset_region


def test_subset_region_handles_descending_latitude() -> None:
    field = xr.DataArray(
        np.arange(3 * 4 * 5).reshape(3, 4, 5),
        dims=("time", "lat", "lon"),
        coords={
            "time": pd.date_range("2001-07-01", periods=3, freq="YS"),
            "lat": [45.0, 35.0, 25.0, 15.0],
            "lon": [100.0, 110.0, 120.0, 130.0, 140.0],
        },
    )

    result = subset_region(
        field,
        {
            "lon_min": 105.0,
            "lon_max": 135.0,
            "lat_min": 20.0,
            "lat_max": 40.0,
        },
    )

    assert result.lat.values.tolist() == [35.0, 25.0]
    assert result.lon.values.tolist() == [110.0, 120.0, 130.0]


def test_area_weighted_mean_preserves_time_dimension() -> None:
    field = xr.DataArray(
        np.ones((2, 2, 2)),
        dims=("time", "lat", "lon"),
        coords={"time": [0, 1], "lat": [20.0, 30.0], "lon": [110.0, 120.0]},
    )

    result = area_weighted_mean(field)

    assert result.dims == ("time",)
    np.testing.assert_allclose(result.values, [1.0, 1.0])


def test_build_precipitation_anomaly_dataset(tmp_path) -> None:
    path = tmp_path / "precipitation.nc"
    data = xr.Dataset(
        {
            "pre": xr.DataArray(
                np.array(
                    [
                        [[10.0, 20.0]],
                        [[30.0, 40.0]],
                    ]
                ),
                dims=("time", "lat", "lon"),
                coords={
                    "time": pd.to_datetime(["2001-07-01", "2002-07-01"]),
                    "lat": [30.0],
                    "lon": [120.0, 121.0],
                },
            )
        }
    )
    data.to_netcdf(path)

    result = build_precipitation_anomaly_dataset(
        {
            "paths": {"precipitation_file": str(path)},
            "variables": {"precipitation": "pre"},
            "analysis": {
                "month": 7,
                "climatology_period": [2001, 2002],
                "region": {
                    "lon_min": 119.0,
                    "lon_max": 122.0,
                    "lat_min": 29.0,
                    "lat_max": 31.0,
                },
            },
        }
    )

    assert set(result.data_vars) == {"precipitation_anomaly"}
    np.testing.assert_allclose(
        result["precipitation_anomaly"].values,
        [[[-10.0, -10.0]], [[10.0, 10.0]]],
    )
