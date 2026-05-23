import numpy as np
import pytest

from python_weather_diagnostics_toolkit.climate import (
    anomaly,
    composite_mean,
    pearson_correlation_field,
    standardized_anomaly,
)


def test_anomaly_and_standardized_anomaly_use_supplied_baseline():
    values = np.array([12.0, 15.0, 18.0])
    mean = np.array([10.0, 10.0, 10.0])
    spread = np.array([2.0, 0.0, 4.0])

    np.testing.assert_allclose(anomaly(values, mean), np.array([2.0, 5.0, 8.0]))
    standardized = standardized_anomaly(values, mean, spread)

    assert standardized[0] == 1.0
    assert np.isnan(standardized[1])
    assert standardized[2] == 2.0


def test_composite_mean_selects_event_samples():
    values = np.array(
        [
            [1.0, 2.0],
            [3.0, 4.0],
            [5.0, 6.0],
        ]
    )
    mask = np.array([True, False, True])

    composite = composite_mean(values, mask, axis=0)

    np.testing.assert_allclose(composite, np.array([3.0, 4.0]))


def test_composite_mean_rejects_misaligned_mask():
    with pytest.raises(ValueError, match="mask length"):
        composite_mean(np.ones((3, 2)), np.array([True, False]))


def test_pearson_correlation_field_handles_grid_points():
    index = np.array([1.0, 2.0, 3.0, 4.0])
    field = np.stack(
        [
            np.array([[1.0, 4.0], [2.0, 5.0]]),
            np.array([[2.0, 3.0], [4.0, 5.0]]),
            np.array([[3.0, 2.0], [6.0, 5.0]]),
            np.array([[4.0, 1.0], [8.0, 5.0]]),
        ]
    )

    corr = pearson_correlation_field(index, field)

    np.testing.assert_allclose(corr[0, 0], 1.0)
    np.testing.assert_allclose(corr[0, 1], -1.0)
    assert np.isnan(corr[1, 1])
