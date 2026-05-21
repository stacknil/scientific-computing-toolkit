from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
import xarray as xr

from climate_diagnostics.eof import compute_eof, representative_years, standardized_pc


def _sample_field() -> xr.DataArray:
    time_signal = np.array([-2.0, -1.0, 1.0, 2.0])
    spatial_pattern = np.array([[1.0, 0.6], [-0.2, -0.8]])
    values = np.stack([value * spatial_pattern for value in time_signal])
    return xr.DataArray(
        values,
        dims=("time", "lat", "lon"),
        coords={
            "time": pd.date_range("2001-07-01", periods=4, freq="YS"),
            "lat": [25.0, 35.0],
            "lon": [115.0, 125.0],
        },
    )


def test_compute_eof_limits_modes_to_available_rank() -> None:
    result = compute_eof(_sample_field(), n_modes=10)

    assert result.patterns.sizes["mode"] == 4
    assert result.pcs.sizes == {"time": 4, "mode": 4}
    assert result.variance_fraction.sizes == {"mode": 4}
    np.testing.assert_allclose(float(result.variance_fraction.sum()), 1.0)


def test_compute_eof_rejects_empty_or_constant_fields() -> None:
    all_nan = xr.full_like(_sample_field(), np.nan)
    with pytest.raises(ValueError, match="at least one grid cell"):
        compute_eof(all_nan)

    constant = xr.full_like(_sample_field(), 1.0)
    with pytest.raises(ValueError, match="nonzero finite variance"):
        compute_eof(constant)


def test_representative_years_from_standardized_pc() -> None:
    pc = xr.DataArray(
        [-2.0, -0.5, 0.25, 1.5],
        dims=("time",),
        coords={"time": pd.to_datetime(["2001-07-01", "2002-07-01", "2003-07-01", "2004-07-01"])},
    )

    standardized = standardized_pc(pc)
    result = representative_years(standardized, threshold=0.9)

    assert result == {"positive": [2004], "negative": [2001]}
