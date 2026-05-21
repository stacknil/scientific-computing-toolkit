from __future__ import annotations

import itertools
from typing import Sequence

import numpy as np
import pandas as pd
import xarray as xr
from scipy import stats


def standardized_anomaly(da: xr.DataArray, dim: str = "time", ddof: int = 0) -> xr.DataArray:
    """Gridpoint-wise standardized anomaly."""
    mean = da.mean(dim, skipna=True)
    std = da.std(dim, skipna=True, ddof=ddof)
    std = std.where(np.isfinite(std) & (std > 0))
    return (da - mean) / std


def representative_years(years: np.ndarray, values: np.ndarray, count_each: int = 5) -> pd.DataFrame:
    """Select low, high, and near-normal representative years from a series."""
    values = np.asarray(values, dtype=float)
    years = np.asarray(years, dtype=int)
    if count_each < 1:
        raise ValueError("count_each must be at least 1.")
    mask = np.isfinite(values)
    values = values[mask]
    years = years[mask]
    if values.size == 0:
        return pd.DataFrame(columns=["category", "rank", "year", "value", "z_score"])

    std = values.std(ddof=0)
    if not np.isfinite(std) or std == 0:
        z = np.zeros_like(values, dtype=float)
    else:
        z = (values - values.mean()) / std
    order_low = np.argsort(z)[:count_each]
    order_high = np.argsort(z)[-count_each:][::-1]
    order_near = np.argsort(np.abs(z))[:count_each]

    rows = []
    for category, order in (("low", order_low), ("high", order_high), ("near_normal", order_near)):
        for rank, idx in enumerate(order, start=1):
            rows.append(
                {
                    "category": category,
                    "rank": rank,
                    "year": int(years[idx]),
                    "value": float(values[idx]),
                    "z_score": float(z[idx]),
                }
            )
    return pd.DataFrame(rows)


def pearsonr_grid(field: xr.DataArray, index: xr.DataArray, dim: str = "time") -> tuple[xr.DataArray, xr.DataArray, xr.DataArray]:
    """Pearson correlation and p-value between a field and a 1D index."""
    mask = np.isfinite(field) & np.isfinite(index)
    n = mask.sum(dim)
    x = field.where(mask)
    y = index.where(mask)

    x_mean = x.sum(dim) / n
    y_mean = y.sum(dim) / n
    x_anom = x - x_mean
    y_anom = y - y_mean
    num = (x_anom * y_anom).sum(dim)
    den = np.sqrt((x_anom**2).sum(dim) * (y_anom**2).sum(dim))
    r = num / den
    df = n - 2
    tstat = r * np.sqrt(df / (1.0 - r**2))
    p = xr.apply_ufunc(
        lambda t, d: 2.0 * stats.t.sf(np.abs(t), d),
        tstat,
        df,
        vectorize=True,
        output_dtypes=[float],
    )
    valid = (n >= 3) & np.isfinite(r) & np.isfinite(p) & (den > 0)
    return r.where(valid), p.where(valid), n.where(valid)


def partial_corr_matrix(values: np.ndarray, columns: Sequence[str]) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Partial correlation for each pair of columns given all remaining columns."""
    x = np.asarray(values, dtype=float)
    if x.ndim != 2 or x.shape[1] < 3:
        raise ValueError("Partial correlation requires a 2D array with at least 3 columns.")
    if len(columns) != x.shape[1]:
        raise ValueError("Number of column names must match the number of data columns.")
    x = x[np.isfinite(x).all(axis=1)]
    df = x.shape[0] - x.shape[1]
    if df <= 0:
        raise ValueError("Partial correlation requires more complete rows than variables.")
    corr = np.corrcoef(x, rowvar=False)
    precision = np.linalg.pinv(corr)
    pcorr = np.eye(x.shape[1], dtype=float)
    pvals = np.zeros_like(pcorr)
    for i in range(x.shape[1]):
        for j in range(i + 1, x.shape[1]):
            denom = np.sqrt(precision[i, i] * precision[j, j])
            r = float(np.clip(-precision[i, j] / denom, -0.999999999, 0.999999999))
            tstat = r * np.sqrt(df / (1.0 - r * r))
            p = float(2.0 * stats.t.sf(abs(tstat), df))
            pcorr[i, j] = pcorr[j, i] = r
            pvals[i, j] = pvals[j, i] = p
    return pd.DataFrame(pcorr, index=columns, columns=columns), pd.DataFrame(pvals, index=columns, columns=columns)


def autocorr_table(x: np.ndarray, max_lag: int) -> pd.DataFrame:
    """Autocorrelation table for lags 1..max_lag."""
    rows = []
    arr = np.asarray(x, dtype=float)
    if max_lag < 1:
        raise ValueError("max_lag must be at least 1.")
    if arr.size <= max_lag:
        raise ValueError("Series length must be greater than max_lag.")
    for lag in range(1, max_lag + 1):
        r, p = stats.pearsonr(arr[lag:], arr[:-lag])
        rows.append({"lag": lag, "r": float(r), "p": float(p), "n": int(arr.size - lag)})
    return pd.DataFrame(rows)


def crosscorr_table(x: np.ndarray, y: np.ndarray, max_lag: int) -> pd.DataFrame:
    """Cross-correlation table using Corr(X_t, Y_{t+lag})."""
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    if x.size != y.size:
        raise ValueError("Cross-correlation inputs must have the same length.")
    if max_lag < 0:
        raise ValueError("max_lag must be non-negative.")
    if x.size <= max_lag:
        raise ValueError("Series length must be greater than max_lag.")
    rows = []
    for lag in range(-max_lag, max_lag + 1):
        if lag == 0:
            xs, ys = x, y
        elif lag > 0:
            xs, ys = x[:-lag], y[lag:]
        else:
            k = -lag
            xs, ys = x[k:], y[:-k]
        r, p = stats.pearsonr(xs, ys)
        rows.append({"lag": lag, "r": float(r), "p": float(p), "n": int(xs.size)})
    return pd.DataFrame(rows)


def linear_trend_per_decade(da: xr.DataArray, years: np.ndarray) -> tuple[xr.DataArray, xr.DataArray]:
    """Linear trend per decade and p-value for each grid point."""
    years_da = xr.DataArray(np.asarray(years, dtype=float), dims=("time",), coords={"time": da["time"]})

    def _fit(y: np.ndarray, x: np.ndarray) -> tuple[float, float]:
        mask = np.isfinite(y) & np.isfinite(x)
        if mask.sum() < 3:
            return np.nan, np.nan
        res = stats.linregress(x[mask], y[mask])
        return float(res.slope * 10.0), float(res.pvalue)

    trend, pval = xr.apply_ufunc(
        _fit,
        da,
        years_da,
        input_core_dims=[["time"], ["time"]],
        output_core_dims=[[], []],
        vectorize=True,
        output_dtypes=[float, float],
    )
    return trend, pval


def north_error(eigvals: np.ndarray, n: int) -> np.ndarray:
    """North rule-of-thumb eigenvalue sampling error."""
    return np.asarray(eigvals, dtype=float) * np.sqrt(2.0 / float(n))


def eof_svd(field: xr.DataArray, nmodes: int, weight_lat: bool = True) -> tuple[xr.DataArray, xr.DataArray, np.ndarray, np.ndarray]:
    """EOF decomposition with optional square-root cosine-latitude weighting."""
    if nmodes < 1:
        raise ValueError("nmodes must be at least 1.")
    x = field.stack(space=("latitude", "longitude")).transpose("time", "space").dropna("space", how="all")
    weights = np.sqrt(np.cos(np.deg2rad(x["latitude"]))) if weight_lat else xr.ones_like(x["latitude"])
    xw = (x * weights).values.astype(float)
    valid = np.isfinite(xw).all(axis=0)
    xw = xw[:, valid]
    x_valid = x.isel(space=valid)
    weights_valid = weights.isel(space=valid)
    xw = xw - xw.mean(axis=0, keepdims=True)
    n_time = xw.shape[0]
    if n_time < 3:
        raise ValueError("EOF analysis requires at least 3 time steps.")
    max_modes = min(xw.shape)
    if nmodes > max_modes:
        raise ValueError(f"Requested {nmodes} EOF modes, but only {max_modes} modes are available.")

    u, s, vt = np.linalg.svd(xw, full_matrices=False)
    eigvals = (s**2) / (n_time - 1)
    varfrac = eigvals / eigvals.sum()
    modes = np.arange(1, nmodes + 1)
    pcs = xr.DataArray(u[:, :nmodes] * s[:nmodes], dims=("time", "mode"), coords={"time": field["time"], "mode": modes})
    eof_space = xr.DataArray(vt[:nmodes, :], dims=("mode", "space"), coords={"mode": modes, "space": x_valid["space"]})
    eofs = (eof_space / weights_valid).unstack("space")

    for k in range(nmodes):
        mean_value = float(eofs.isel(mode=k).mean(skipna=True))
        if np.isfinite(mean_value) and mean_value < 0:
            eofs[k, :, :] = -eofs[k, :, :]
            pcs[:, k] = -pcs[:, k]
    return eofs, pcs, eigvals, varfrac


def ols_with_intercept(x: np.ndarray, y: np.ndarray) -> dict[str, np.ndarray | float | int]:
    """Ordinary least squares with an intercept and basic coefficient tests."""
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    if x.ndim == 1:
        x = x[:, None]
    mask = np.isfinite(y) & np.isfinite(x).all(axis=1)
    x = x[mask]
    y = y[mask]
    n = y.size
    xd = np.column_stack([np.ones(n), x])
    p = x.shape[1]
    df = n - p - 1
    if df <= 0:
        raise ValueError("OLS requires more complete observations than parameters.")
    beta, *_ = np.linalg.lstsq(xd, y, rcond=None)
    fitted = xd @ beta
    resid = y - fitted
    sse = float(np.sum(resid**2))
    sst = float(np.sum((y - y.mean()) ** 2))
    r2 = 1.0 - sse / sst if sst > 0 else np.nan
    mse = sse / df
    cov = mse * np.linalg.inv(xd.T @ xd)
    se = np.sqrt(np.diag(cov))
    tvals = beta / se
    pvals = 2.0 * stats.t.sf(np.abs(tvals), df)
    return {"beta": beta, "se": se, "t": tvals, "p": pvals, "r2": float(r2), "df": int(df), "resid": resid, "fitted": fitted}


def composite_difference(
    field: xr.DataArray,
    years: np.ndarray,
    group_a: Sequence[int],
    group_b: Sequence[int],
) -> tuple[xr.DataArray, xr.DataArray, xr.DataArray, xr.DataArray]:
    """Composite means, difference, and Welch p-value for two year groups."""
    years = np.asarray(years, dtype=int)
    a_mask = np.isin(years, np.asarray(group_a, dtype=int))
    b_mask = np.isin(years, np.asarray(group_b, dtype=int))
    if a_mask.sum() < 2 or b_mask.sum() < 2:
        raise ValueError("Composite analysis requires at least two years in each group.")
    a = field.sel(time=field["time"].where(xr.DataArray(a_mask, dims=("time",), coords={"time": field["time"]}), drop=True))
    b = field.sel(time=field["time"].where(xr.DataArray(b_mask, dims=("time",), coords={"time": field["time"]}), drop=True))
    diff = a.mean("time", skipna=True) - b.mean("time", skipna=True)

    def _welch(x: np.ndarray, y: np.ndarray) -> float:
        mask_x = np.isfinite(x)
        mask_y = np.isfinite(y)
        if mask_x.sum() < 2 or mask_y.sum() < 2:
            return np.nan
        return float(stats.ttest_ind(x[mask_x], y[mask_y], equal_var=False).pvalue)

    a_test = a.rename({"time": "sample_a"})
    b_test = b.rename({"time": "sample_b"})
    pval = xr.apply_ufunc(
        _welch,
        a_test,
        b_test,
        input_core_dims=[["sample_a"], ["sample_b"]],
        output_core_dims=[[]],
        vectorize=True,
        output_dtypes=[float],
    )
    return a.mean("time", skipna=True), b.mean("time", skipna=True), diff, pval


def pair_names(columns: Sequence[str]) -> list[tuple[str, str]]:
    """Return unique column-name pairs."""
    return list(itertools.combinations(columns, 2))
