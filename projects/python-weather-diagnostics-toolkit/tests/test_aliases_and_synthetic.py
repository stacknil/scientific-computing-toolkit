import xarray as xr

from python_weather_diagnostics_toolkit.aliases import get_data_array, standardize_coordinates
from python_weather_diagnostics_toolkit.synthetic import make_synthetic_weather_dataset


def test_standardize_coordinates_renames_common_aliases():
    ds = xr.Dataset(
        data_vars={"t2m": (("valid_time", "lat", "lon"), [[[1.0]]])},
        coords={"valid_time": [0], "lat": [40.0], "lon": [120.0]},
    )

    out = standardize_coordinates(ds)

    assert {"time", "latitude", "longitude"}.issubset(out.coords)


def test_get_data_array_accepts_known_variable_aliases():
    ds = xr.Dataset(data_vars={"2m_temperature": (("x",), [273.15])})

    da = get_data_array(ds, "t2m")

    assert float(da.values[0]) == 273.15


def test_get_data_array_accepts_specific_humidity_alias():
    ds = xr.Dataset(data_vars={"q": (("x",), [0.012])})

    da = get_data_array(ds, "specific_humidity")

    assert float(da.values[0]) == 0.012


def test_synthetic_dataset_is_tiny_and_labeled_synthetic():
    ds = make_synthetic_weather_dataset()

    assert ds.attrs["source"] == "synthetic"
    assert ds.t2m.shape == (6, 8)
