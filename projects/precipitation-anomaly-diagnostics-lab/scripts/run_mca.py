#!/usr/bin/env python3
from __future__ import annotations

import argparse

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import xarray as xr

from _bootstrap import bootstrap

bootstrap()

from climate_diagnostics.config import cfg_get, load_config, output_dir, resolve_path
from climate_diagnostics.grids import align_by_year, select_years, subset_box, years_from_time
from climate_diagnostics.io import open_field
from climate_diagnostics.plotting import save_field_map
from climate_diagnostics.statistics import standardized_anomaly


def main() -> None:
    parser = argparse.ArgumentParser(description="Maximum covariance analysis between precipitation and SST fields.")
    parser.add_argument("--config", default="configs/example.yaml", help="YAML config path.")
    args = parser.parse_args()

    cfg = load_config(args.config)
    out = output_dir(cfg, args.config, "mca")
    pre = open_field(resolve_path(cfg, args.config, "paths.precipitation"), cfg_get(cfg, "variables.precipitation", "pre"))
    sst = open_field(resolve_path(cfg, args.config, "paths.sst"), cfg_get(cfg, "variables.sst", "sst"))
    pre = subset_box(pre, cfg_get(cfg, "regions.eastern_domain", {}))
    pre = select_years(pre, cfg_get(cfg, "periods.analysis_start"), cfg_get(cfg, "periods.mca_end"))
    sst = select_years(sst, cfg_get(cfg, "periods.analysis_start"), cfg_get(cfg, "periods.mca_end"))

    common = np.intersect1d(years_from_time(pre), years_from_time(sst))
    pre = align_by_year(pre, common)
    sst = align_by_year(sst, common)
    years = years_from_time(pre)

    pre_z = standardized_anomaly(pre, "time", ddof=1)
    sst_z = standardized_anomaly(sst, "time", ddof=1)
    pre_vec = pre_z.stack(space=("latitude", "longitude")).dropna("space")
    sst_vec = sst_z.stack(space=("latitude", "longitude")).dropna("space")
    x = pre_vec.transpose("time", "space").values
    y = sst_vec.transpose("time", "space").values
    x = x - x.mean(axis=0, keepdims=True)
    y = y - y.mean(axis=0, keepdims=True)

    cov = (x.T @ y) / (x.shape[0] - 1)
    u, singular, vt = np.linalg.svd(cov, full_matrices=False)
    frac = singular**2 / np.sum(singular**2)
    modes = int(cfg_get(cfg, "diagnostics.mca_modes", 2))
    scores_pre = x @ u[:, :modes]
    scores_sst = y @ vt.T[:, :modes]

    rows = []
    for idx in range(modes):
        mode = idx + 1
        pre_score = scores_pre[:, idx]
        sst_score = scores_sst[:, idx]
        pre_map = corr_map(pre_z, sst_score)
        sst_map = corr_map(sst_z, pre_score)
        save_field_map(pre_map, out / f"mca_precip_heterogeneous_mode_{mode}.png", f"MCA precip heterogeneous correlation mode {mode}", "Correlation r", cmap="RdBu_r", symmetric=True)
        save_field_map(sst_map, out / f"mca_sst_heterogeneous_mode_{mode}.png", f"MCA SST heterogeneous correlation mode {mode}", "Correlation r", cmap="RdBu_r", symmetric=True)
        save_scores(years, pre_score, sst_score, out / f"mca_scores_mode_{mode}.png", mode)
        rows.append({"mode": mode, "singular_value": float(singular[idx]), "squared_covariance_fraction": float(frac[idx]), "score_correlation": float(np.corrcoef(pre_score, sst_score)[0, 1])})

    pd.DataFrame(rows).to_csv(out / "mca_summary.csv", index=False)
    print(f"Wrote MCA diagnostics to {out}")


def corr_map(field: xr.DataArray, score: np.ndarray) -> xr.DataArray:
    score_da = xr.DataArray(score, dims=("time",), coords={"time": field["time"]})
    score_da = (score_da - score_da.mean("time")) / score_da.std("time", ddof=1)
    return xr.corr(field, score_da, dim="time")


def save_scores(years: np.ndarray, left: np.ndarray, right: np.ndarray, out_path, mode: int) -> None:
    left = (left - left.mean()) / left.std(ddof=1)
    right = (right - right.mean()) / right.std(ddof=1)
    fig, ax = plt.subplots(figsize=(8.5, 3.6))
    ax.plot(years, left, marker="o", markersize=2, label="Precip score")
    ax.plot(years, right, marker="o", markersize=2, label="SST score")
    ax.axhline(0.0, linewidth=0.8, color="black")
    ax.set_xlabel("Year")
    ax.set_ylabel("z-score")
    ax.set_title(f"MCA score time series mode {mode}")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=200)
    plt.close(fig)


if __name__ == "__main__":
    main()
