"""Feature extraction and deterministic baseline models for weather fields."""

from __future__ import annotations

import numpy as np
import pandas as pd


def latitude_weights(latitude) -> np.ndarray:
    """Return non-negative cosine latitude weights."""

    weights = np.cos(np.deg2rad(np.asarray(latitude, dtype=float)))
    return np.clip(weights, 0.0, None)


def area_mean(field, latitude) -> np.ndarray:
    """Area-weight a field over its final two latitude/longitude dimensions."""

    values = np.asarray(field, dtype=float)
    if values.ndim < 2:
        raise ValueError("field must have at least latitude and longitude dimensions")
    weights = latitude_weights(latitude)
    if values.shape[-2] != weights.size:
        raise ValueError("latitude length must match the second-to-last field dimension")
    reshape = (1,) * (values.ndim - 2) + (weights.size, 1)
    weights_2d = weights.reshape(reshape)
    numerator = np.nansum(values * weights_2d, axis=(-2, -1))
    denominator = np.nansum(np.isfinite(values) * weights_2d, axis=(-2, -1))
    with np.errstate(divide="ignore", invalid="ignore"):
        mean = numerator / denominator
    return np.where(denominator > 0.0, mean, np.nan)


def build_forecast_frame(
    time_index,
    z500,
    t850,
    t2m,
    *,
    lead_steps: int = 24,
) -> pd.DataFrame:
    """Build a simple time-ordered forecast table from region-mean features."""

    if lead_steps <= 0:
        raise ValueError("lead_steps must be positive")
    df = pd.DataFrame(
        {
            "z500": np.asarray(z500, dtype=float),
            "t850": np.asarray(t850, dtype=float),
            "t2m_current": np.asarray(t2m, dtype=float),
        },
        index=pd.Index(time_index, name="time"),
    )
    df["target_t2m_next"] = df["t2m_current"].shift(-lead_steps)
    return df.dropna()


def ridge_regression_fit_predict(
    features,
    target,
    *,
    train_fraction: float = 0.8,
    alpha: float = 1.0,
) -> dict[str, np.ndarray | float]:
    """Fit a deterministic ridge baseline with time-ordered train/test split."""

    x = np.asarray(features, dtype=float)
    y = np.asarray(target, dtype=float)
    if x.ndim != 2:
        raise ValueError("features must be a two-dimensional array")
    if y.ndim != 1 or y.size != x.shape[0]:
        raise ValueError("target must be one-dimensional and aligned with features")
    if not np.isfinite(x).all() or not np.isfinite(y).all():
        raise ValueError("features and target must contain only finite values")
    if not 0.0 < train_fraction < 1.0:
        raise ValueError("train_fraction must be between 0 and 1")
    if alpha < 0.0:
        raise ValueError("alpha must be non-negative")

    split = int(x.shape[0] * train_fraction)
    if split <= 0 or split >= x.shape[0]:
        raise ValueError("train_fraction leaves an empty train or test partition")

    x_train, x_test = x[:split], x[split:]
    y_train, y_test = y[:split], y[split:]

    mean = x_train.mean(axis=0)
    scale = x_train.std(axis=0)
    scale = np.where(np.isclose(scale, 0.0), 1.0, scale)
    x_train_scaled = (x_train - mean) / scale
    x_test_scaled = (x_test - mean) / scale

    design = np.column_stack([np.ones(x_train_scaled.shape[0]), x_train_scaled])
    penalty = np.eye(design.shape[1]) * alpha
    penalty[0, 0] = 0.0
    coef = np.linalg.solve(design.T @ design + penalty, design.T @ y_train)

    test_design = np.column_stack([np.ones(x_test_scaled.shape[0]), x_test_scaled])
    y_pred = test_design @ coef
    return {
        "coefficients": coef,
        "feature_mean": mean,
        "feature_scale": scale,
        "y_test": y_test,
        "y_pred": y_pred,
        "split_index": float(split),
    }


def ridge_alpha_grid(
    features,
    target,
    alphas,
    *,
    train_fraction: float = 0.7,
) -> pd.DataFrame:
    """Evaluate ridge alpha values with the same time-ordered split."""

    alpha_values = np.asarray(list(alphas), dtype=float)
    if alpha_values.ndim != 1 or alpha_values.size == 0:
        raise ValueError("alphas must contain at least one value")
    if not np.isfinite(alpha_values).all() or np.any(alpha_values < 0.0):
        raise ValueError("alphas must be finite non-negative values")

    rows = []
    for alpha in alpha_values:
        result = ridge_regression_fit_predict(
            features,
            target,
            train_fraction=train_fraction,
            alpha=float(alpha),
        )
        metrics = regression_metrics(result["y_test"], result["y_pred"])
        rows.append(
            {
                "alpha": float(alpha),
                "split_index": result["split_index"],
                **metrics,
            }
        )
    return pd.DataFrame(rows).sort_values(["rmse", "alpha"]).reset_index(drop=True)


def regression_metrics(y_true, y_pred) -> dict[str, float]:
    """Return RMSE, MAE, bias, and Pearson correlation."""

    true = np.asarray(y_true, dtype=float)
    pred = np.asarray(y_pred, dtype=float)
    if true.shape != pred.shape:
        raise ValueError("y_true and y_pred must have matching shapes")
    if true.size == 0:
        raise ValueError("metrics require at least one sample")
    if not np.isfinite(true).all() or not np.isfinite(pred).all():
        raise ValueError("metrics require finite values")

    err = pred - true
    if true.size < 2 or np.allclose(true.std(), 0.0) or np.allclose(pred.std(), 0.0):
        corr = float("nan")
    else:
        corr = float(np.corrcoef(true, pred)[0, 1])
    return {
        "rmse": float(np.sqrt(np.mean(err**2))),
        "mae": float(np.mean(np.abs(err))),
        "bias": float(np.mean(err)),
        "correlation": corr,
    }
