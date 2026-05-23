"""Precipitation helpers for public-safe station and gridded workflows."""

from __future__ import annotations

import numpy as np


def mark_missing_sentinel(values, *, sentinel: float = -32766.0) -> np.ndarray:
    """Replace a numeric missing-value sentinel with NaN."""

    array = np.asarray(values, dtype=float)
    return np.where(np.isclose(array, sentinel), np.nan, array)


def cumulative_to_increment(
    accumulated,
    *,
    axis: int = -1,
    negative_tolerance: float = 1e-9,
) -> np.ndarray:
    """Convert non-decreasing accumulated precipitation to per-step amounts."""

    values = np.asarray(accumulated, dtype=float)
    if values.size == 0:
        raise ValueError("accumulated precipitation must not be empty")
    moved = np.moveaxis(values, axis, -1)
    if moved.shape[-1] == 0:
        raise ValueError("accumulated precipitation axis must not be empty")

    increments = np.empty_like(moved)
    increments[..., 0] = moved[..., 0]
    increments[..., 1:] = np.diff(moved, axis=-1)
    finite_negative = np.isfinite(increments) & (increments < -negative_tolerance)
    if finite_negative.any():
        raise ValueError("accumulated precipitation must be non-decreasing along axis")
    increments = np.where(np.isfinite(increments) & (increments < 0.0), 0.0, increments)
    return np.moveaxis(increments, -1, axis)


def increment_to_rate(increment, *, step_hours: float) -> np.ndarray:
    """Convert per-step precipitation amounts to mm/day-equivalent rates."""

    if step_hours <= 0.0:
        raise ValueError("step_hours must be positive")
    return np.asarray(increment, dtype=float) * (24.0 / step_hours)


def cumulative_to_rate(
    accumulated,
    *,
    step_hours: float,
    axis: int = -1,
    negative_tolerance: float = 1e-9,
) -> np.ndarray:
    """Convert accumulated precipitation to mm/day-equivalent step rates."""

    increment = cumulative_to_increment(
        accumulated,
        axis=axis,
        negative_tolerance=negative_tolerance,
    )
    return increment_to_rate(increment, step_hours=step_hours)


def event_total(precipitation, *, axis=0, min_count: int = 1) -> np.ndarray:
    """Sum precipitation over an event axis while preserving all-missing regions."""

    if min_count <= 0:
        raise ValueError("min_count must be positive")
    values = np.asarray(precipitation, dtype=float)
    valid_count = np.sum(np.isfinite(values), axis=axis)
    total = np.nansum(values, axis=axis)
    return np.where(valid_count >= min_count, total, np.nan)


def threshold_exceedance(values, *, threshold: float) -> np.ndarray:
    """Return a boolean mask where finite values meet or exceed a threshold."""

    array = np.asarray(values, dtype=float)
    return np.isfinite(array) & (array >= threshold)
