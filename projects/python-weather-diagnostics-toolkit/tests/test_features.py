import numpy as np

from python_weather_diagnostics_toolkit.features import (
    area_mean,
    regression_metrics,
    ridge_regression_fit_predict,
)


def test_area_mean_preserves_constant_field():
    lat = np.array([30.0, 35.0, 40.0])
    field = np.ones((2, lat.size, 4)) * 7.0

    mean = area_mean(field, lat)

    np.testing.assert_allclose(mean, np.array([7.0, 7.0]))


def test_ridge_baseline_returns_predictions_and_metrics():
    x = np.column_stack([np.arange(20.0), np.arange(20.0) * 0.5])
    y = 2.0 + x[:, 0] * 0.3 - x[:, 1] * 0.1

    result = ridge_regression_fit_predict(x, y, train_fraction=0.75, alpha=0.01)
    metrics = regression_metrics(result["y_test"], result["y_pred"])

    assert result["y_pred"].shape == result["y_test"].shape
    assert metrics["rmse"] < 0.05
