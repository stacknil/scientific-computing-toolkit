import numpy as np
import pytest

from python_weather_diagnostics_toolkit.precipitation import (
    cumulative_to_increment,
    cumulative_to_rate,
    event_total,
    mark_missing_sentinel,
    threshold_exceedance,
)


def test_mark_missing_sentinel_replaces_only_missing_code():
    values = np.array([0.0, -32766.0, 12.5])

    cleaned = mark_missing_sentinel(values)

    assert cleaned[0] == 0.0
    assert np.isnan(cleaned[1])
    assert cleaned[2] == 12.5


def test_cumulative_to_rate_returns_step_mm_per_day_values():
    accumulated = np.array([0.0, 2.0, 5.0])

    rate = cumulative_to_rate(accumulated, step_hours=6)

    np.testing.assert_allclose(rate, np.array([0.0, 8.0, 12.0]))


def test_cumulative_to_increment_rejects_decreasing_series():
    with pytest.raises(ValueError, match="non-decreasing"):
        cumulative_to_increment(np.array([0.0, 4.0, 3.0]))


def test_event_total_preserves_all_missing_grid_points():
    precipitation = np.array(
        [
            [1.0, np.nan],
            [2.0, np.nan],
        ]
    )

    total = event_total(precipitation, axis=0)

    np.testing.assert_allclose(total[0], 3.0)
    assert np.isnan(total[1])


def test_threshold_exceedance_ignores_missing_values():
    values = np.array([49.0, 50.0, np.nan])

    mask = threshold_exceedance(values, threshold=50.0)

    np.testing.assert_array_equal(mask, np.array([False, True, False]))
