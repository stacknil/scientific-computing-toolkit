"""Small climate-statistics helpers used by reviewer-safe examples."""

from __future__ import annotations

import numpy as np


def anomaly(values, climatology) -> np.ndarray:
    """Return departures from a provided climatological baseline."""

    return np.asarray(values, dtype=float) - np.asarray(climatology, dtype=float)


def standardized_anomaly(values, climatology_mean, climatology_std) -> np.ndarray:
    """Return standardized anomalies while masking zero-spread baselines."""

    departures = anomaly(values, climatology_mean)
    spread = np.asarray(climatology_std, dtype=float)
    with np.errstate(divide="ignore", invalid="ignore"):
        standardized = departures / spread
    return np.where(spread > 0.0, standardized, np.nan)


def composite_mean(values, mask, *, axis: int = 0, min_count: int = 1) -> np.ndarray:
    """Average samples selected by a boolean event mask."""

    array = np.asarray(values, dtype=float)
    selector = np.asarray(mask, dtype=bool)
    if selector.ndim != 1:
        raise ValueError("mask must be one-dimensional")
    moved = np.moveaxis(array, axis, 0)
    if moved.shape[0] != selector.size:
        raise ValueError("mask length must match the selected sample axis")
    if min_count <= 0:
        raise ValueError("min_count must be positive")

    selected = moved[selector]
    if selected.shape[0] < min_count:
        return np.full(moved.shape[1:], np.nan, dtype=float)
    return np.nanmean(selected, axis=0)


def pearson_correlation_field(index, field, *, min_count: int = 3) -> np.ndarray:
    """Correlate a one-dimensional index with every grid point in a field."""

    x = np.asarray(index, dtype=float)
    y = np.asarray(field, dtype=float)
    if x.ndim != 1:
        raise ValueError("index must be one-dimensional")
    if y.ndim < 1 or y.shape[0] != x.size:
        raise ValueError("field first dimension must align with index")
    if min_count < 2:
        raise ValueError("min_count must be at least 2")

    y2 = y.reshape((x.size, -1))
    x2 = x[:, None]
    valid = np.isfinite(x2) & np.isfinite(y2)
    count = valid.sum(axis=0)
    safe_count = np.where(count > 0, count, 1)
    x_mean = np.sum(np.where(valid, x2, 0.0), axis=0) / safe_count
    y_mean = np.sum(np.where(valid, y2, 0.0), axis=0) / safe_count
    x_centered = np.where(valid, x2 - x_mean, 0.0)
    y_centered = np.where(valid, y2 - y_mean, 0.0)
    numerator = np.sum(x_centered * y_centered, axis=0)
    x_var = np.sum(x_centered**2, axis=0)
    y_var = np.sum(y_centered**2, axis=0)
    with np.errstate(divide="ignore", invalid="ignore"):
        corr = numerator / np.sqrt(x_var * y_var)
    corr = np.where((count >= min_count) & (x_var > 0.0) & (y_var > 0.0), corr, np.nan)
    return corr.reshape(y.shape[1:])
