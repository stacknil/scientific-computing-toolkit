import numpy as np
import pytest

from python_weather_diagnostics_toolkit.features import (
    area_mean,
    persistence_baseline,
    regression_metrics,
    residual_diagnostics,
    ridge_alpha_grid,
    ridge_regression_fit_predict,
)


def test_area_mean_preserves_constant_field():
    lat = np.array([30.0, 35.0, 40.0])
    field = np.ones((2, lat.size, 4)) * 7.0

    mean = area_mean(field, lat)

    np.testing.assert_allclose(mean, np.array([7.0, 7.0]))


def test_area_mean_returns_nan_for_all_missing_region():
    lat = np.array([30.0, 35.0, 40.0])
    field = np.full((lat.size, 4), np.nan)

    mean = area_mean(field, lat)

    assert np.isnan(mean)


def test_ridge_baseline_returns_predictions_and_metrics():
    x = np.column_stack([np.arange(20.0), np.arange(20.0) * 0.5])
    y = 2.0 + x[:, 0] * 0.3 - x[:, 1] * 0.1

    result = ridge_regression_fit_predict(x, y, train_fraction=0.75, alpha=0.01)
    metrics = regression_metrics(result["y_test"], result["y_pred"])

    assert result["y_pred"].shape == result["y_test"].shape
    assert metrics["rmse"] < 0.05


def test_ridge_alpha_grid_returns_sorted_metric_table():
    x = np.column_stack([np.arange(30.0), np.sin(np.arange(30.0))])
    y = 1.0 + x[:, 0] * 0.2 + x[:, 1] * 0.5

    table = ridge_alpha_grid(x, y, [10.0, 0.0, 1.0], train_fraction=0.7)

    assert set(["alpha", "rmse", "mae", "bias", "correlation"]).issubset(table.columns)
    assert table["rmse"].is_monotonic_increasing
    assert sorted(table["alpha"].tolist()) == [0.0, 1.0, 10.0]


def test_ridge_baseline_rejects_non_finite_training_values():
    x = np.column_stack([np.arange(20.0), np.arange(20.0) * 0.5])
    y = np.arange(20.0)
    x[3, 0] = np.inf

    with pytest.raises(ValueError, match="finite"):
        ridge_regression_fit_predict(x, y)


def test_regression_metrics_reject_empty_inputs():
    with pytest.raises(ValueError, match="at least one sample"):
        regression_metrics(np.array([]), np.array([]))


def test_ridge_alpha_grid_rejects_negative_alpha():
    x = np.column_stack([np.arange(20.0), np.arange(20.0) * 0.5])
    y = np.arange(20.0)

    with pytest.raises(ValueError, match="non-negative"):
        ridge_alpha_grid(x, y, [1.0, -0.1])


def test_persistence_baseline_aligns_future_truth_with_current_prediction():
    series = np.array([10.0, 12.0, 15.0, 14.0])

    baseline = persistence_baseline(series, lead_steps=1)

    np.testing.assert_allclose(baseline["y_true"], np.array([12.0, 15.0, 14.0]))
    np.testing.assert_allclose(baseline["y_pred"], np.array([10.0, 12.0, 15.0]))


def test_residual_diagnostics_summarize_error_shape():
    summary = residual_diagnostics(np.array([1.0, 2.0, 3.0]), np.array([1.5, 1.5, 3.0]))

    assert summary["max_abs_residual"] == 0.5
    assert summary["overprediction_fraction"] == 1 / 3
    assert summary["underprediction_fraction"] == 1 / 3
