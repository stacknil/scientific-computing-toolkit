import numpy as np
import pandas as pd
import pytest

from python_weather_diagnostics_toolkit.ensemble import ensemble_summary


def test_single_member_ensemble_has_zero_spread():
    df = pd.DataFrame({"member_01": [0.2, 0.8]}, index=[1, 2])

    summary = ensemble_summary(df)

    np.testing.assert_allclose(summary["spread"].to_numpy(), np.array([0.0, 0.0]))
    np.testing.assert_allclose(summary["warm_probability"].to_numpy(), np.array([0.0, 1.0]))


def test_ensemble_summary_rejects_non_finite_values():
    df = pd.DataFrame({"member_01": [0.2, np.nan]}, index=[1, 2])

    with pytest.raises(ValueError, match="finite"):
        ensemble_summary(df)
