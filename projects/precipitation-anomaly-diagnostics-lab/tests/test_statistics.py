import unittest

import numpy as np
import pandas as pd
import xarray as xr

from climate_diagnostics.statistics import (
    autocorr_table,
    composite_difference,
    eof_svd,
    linear_trend_per_decade,
    ols_with_intercept,
    partial_corr_matrix,
    representative_years,
    standardized_anomaly,
)


class StatisticsTests(unittest.TestCase):
    def test_standardized_anomaly_masks_constant_grid_cells(self):
        da = xr.DataArray(
            np.array(
                [
                    [[1.0, 5.0], [2.0, 3.0]],
                    [[2.0, 5.0], [4.0, 3.0]],
                    [[3.0, 5.0], [6.0, 3.0]],
                ]
            ),
            dims=("time", "latitude", "longitude"),
            coords={
                "time": pd.date_range("2000-01-01", periods=3, freq="YS"),
                "latitude": [10.0, 20.0],
                "longitude": [100.0, 110.0],
            },
        )
        z = standardized_anomaly(da)

        self.assertTrue(np.isfinite(z.sel(latitude=10.0, longitude=100.0)).all())
        self.assertTrue(np.isnan(z.sel(latitude=10.0, longitude=110.0)).all())
        self.assertTrue(np.isnan(z.sel(latitude=20.0, longitude=110.0)).all())

    def test_representative_years_handles_constant_series(self):
        years = np.array([2000, 2001, 2002])
        out = representative_years(years, np.array([4.0, 4.0, 4.0]), count_each=2)

        self.assertEqual(set(out["category"]), {"low", "high", "near_normal"})
        self.assertTrue(np.isfinite(out["z_score"]).all())

    def test_partial_corr_rejects_too_few_rows(self):
        values = np.ones((3, 3))

        with self.assertRaises(ValueError):
            partial_corr_matrix(values, ["a", "b", "c"])

    def test_autocorr_rejects_lag_longer_than_series(self):
        with self.assertRaises(ValueError):
            autocorr_table(np.array([1.0, 2.0]), max_lag=2)

    def test_linear_trend_per_decade_known_slope(self):
        years = np.arange(2000, 2006)
        da = xr.DataArray(
            (2.0 * years)[:, None, None],
            dims=("time", "latitude", "longitude"),
            coords={
                "time": pd.to_datetime([f"{year}-01-01" for year in years]),
                "latitude": [30.0],
                "longitude": [120.0],
            },
        )

        trend, pval = linear_trend_per_decade(da, years)

        self.assertAlmostEqual(float(trend.values.squeeze()), 20.0, places=8)
        self.assertLess(float(pval.values.squeeze()), 1e-8)

    def test_eof_svd_shapes_and_variance_fraction(self):
        rng = np.random.default_rng(42)
        da = xr.DataArray(
            rng.normal(size=(6, 3, 4)),
            dims=("time", "latitude", "longitude"),
            coords={
                "time": pd.date_range("2000-01-01", periods=6, freq="YS"),
                "latitude": [10.0, 20.0, 30.0],
                "longitude": [100.0, 110.0, 120.0, 130.0],
            },
        )

        eofs, pcs, eigvals, varfrac = eof_svd(da, nmodes=2)

        self.assertEqual(eofs.shape, (2, 3, 4))
        self.assertEqual(pcs.shape, (6, 2))
        self.assertEqual(eigvals.shape[0], 6)
        self.assertAlmostEqual(float(varfrac.sum()), 1.0, places=10)

    def test_composite_difference_known_groups(self):
        years = np.array([2000, 2001, 2002, 2003])
        field = xr.DataArray(
            years[:, None, None].astype(float),
            dims=("time", "latitude", "longitude"),
            coords={
                "time": pd.to_datetime([f"{year}-01-01" for year in years]),
                "latitude": [30.0],
                "longitude": [120.0],
            },
        )

        first, second, diff, pval = composite_difference(field, years, [2002, 2003], [2000, 2001])

        self.assertAlmostEqual(float(first.values.squeeze()), 2002.5)
        self.assertAlmostEqual(float(second.values.squeeze()), 2000.5)
        self.assertAlmostEqual(float(diff.values.squeeze()), 2.0)
        self.assertTrue(np.isfinite(float(pval.values.squeeze())))

    def test_ols_with_intercept_recovers_exact_coefficients(self):
        x = np.arange(10, dtype=float)
        y = 3.0 + 2.0 * x

        result = ols_with_intercept(x, y)

        np.testing.assert_allclose(result["beta"], np.array([3.0, 2.0]), atol=1e-10)
        self.assertAlmostEqual(result["r2"], 1.0, places=10)


if __name__ == "__main__":
    unittest.main()
