from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import xarray as xr


@dataclass
class EOFResult:
    patterns: xr.DataArray
    pcs: xr.DataArray
    variance_fraction: xr.DataArray


def latitude_weights(lat: xr.DataArray) -> xr.DataArray:
    """Return sqrt(cos(lat)) EOF area weights."""
    return xr.DataArray(np.sqrt(np.cos(np.deg2rad(lat))), coords={"lat": lat}, dims="lat")


def _stack_valid_grid(field: xr.DataArray) -> tuple[xr.DataArray, xr.DataArray]:
    stacked = field.stack(space=("lat", "lon"))
    valid = stacked.notnull().all("time")
    return stacked.where(valid, drop=True), valid


def compute_eof(field: xr.DataArray, n_modes: int = 10) -> EOFResult:
    """Compute EOF modes with SVD.

    The input must have dimensions `time`, `lat`, and `lon`.
    """
    if n_modes < 1:
        raise ValueError("n_modes must be at least 1.")
    weights = latitude_weights(field.lat)
    weighted = field * weights
    stacked, valid = _stack_valid_grid(weighted)
    if stacked.sizes["space"] == 0:
        raise ValueError("EOF analysis requires at least one grid cell without missing values.")
    matrix = stacked.transpose("time", "space").values
    matrix = matrix - np.nanmean(matrix, axis=0, keepdims=True)
    mode_count = min(n_modes, *matrix.shape)

    u, singular_values, vt = np.linalg.svd(matrix, full_matrices=False)
    pcs = u[:, :mode_count] * singular_values[:mode_count]
    eigenvalues = singular_values**2 / max(matrix.shape[0] - 1, 1)
    total_variance = eigenvalues.sum()
    if not np.isfinite(total_variance) or total_variance <= 0:
        raise ValueError("EOF analysis requires nonzero finite variance.")
    variance_fraction = eigenvalues[:mode_count] / total_variance

    modes = np.arange(1, mode_count + 1)
    pattern_values = np.full((mode_count, valid.sizes["space"]), np.nan)
    pattern_values[:, valid.values] = vt[:mode_count, :]
    patterns = xr.DataArray(
        pattern_values,
        dims=("mode", "space"),
        coords={"mode": modes, "space": valid.space},
    ).unstack("space")

    pcs_da = xr.DataArray(
        pcs,
        dims=("time", "mode"),
        coords={"time": field.time, "mode": modes},
        name="pc",
    )
    vf_da = xr.DataArray(
        variance_fraction,
        dims=("mode",),
        coords={"mode": modes},
        name="variance_fraction",
    )
    return EOFResult(patterns=patterns, pcs=pcs_da, variance_fraction=vf_da)


def standardized_pc(pc: xr.DataArray) -> xr.DataArray:
    """Return a standardized principal component time series."""
    return (pc - pc.mean("time")) / pc.std("time")


def representative_years(pc: xr.DataArray, threshold: float = 0.9) -> dict[str, list[int]]:
    """Select positive and negative representative years from a standardized PC."""
    standardized = standardized_pc(pc)
    years = standardized["time.year"].values
    values = standardized.values
    return {
        "positive": [int(year) for year, value in zip(years, values) if value >= threshold],
        "negative": [int(year) for year, value in zip(years, values) if value <= -threshold],
    }


def monte_carlo_variance_threshold(
    field: xr.DataArray,
    n_modes: int = 10,
    iterations: int = 1000,
    quantile: float = 0.95,
    seed: int | None = None,
) -> np.ndarray:
    """Estimate EOF variance thresholds by shuffling time at each grid point."""
    rng = np.random.default_rng(seed)
    stacked, _ = _stack_valid_grid(field)
    matrix = stacked.transpose("time", "space").values
    samples = np.empty((iterations, n_modes), dtype=float)
    for i in range(iterations):
        shuffled = matrix.copy()
        for j in range(shuffled.shape[1]):
            rng.shuffle(shuffled[:, j])
        _, singular_values, _ = np.linalg.svd(shuffled - shuffled.mean(axis=0, keepdims=True), full_matrices=False)
        eigenvalues = singular_values**2 / max(shuffled.shape[0] - 1, 1)
        samples[i, :] = eigenvalues[:n_modes] / eigenvalues.sum()
    return np.quantile(samples, quantile, axis=0)
