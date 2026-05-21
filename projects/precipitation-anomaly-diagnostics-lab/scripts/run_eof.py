#!/usr/bin/env python3
from __future__ import annotations

import argparse

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from _bootstrap import bootstrap

bootstrap()

from climate_diagnostics.config import cfg_get, load_config, output_dir, resolve_path
from climate_diagnostics.grids import select_years, subset_box, years_from_time
from climate_diagnostics.io import open_field
from climate_diagnostics.plotting import save_field_map, save_line_plot
from climate_diagnostics.statistics import eof_svd, north_error, standardized_anomaly


def main() -> None:
    parser = argparse.ArgumentParser(description="EOF and principal-component diagnostics for precipitation anomalies.")
    parser.add_argument("--config", default="configs/example.yaml", help="YAML config path.")
    args = parser.parse_args()

    cfg = load_config(args.config)
    out = output_dir(cfg, args.config, "eof")
    precip = open_field(resolve_path(cfg, args.config, "paths.precipitation"), cfg_get(cfg, "variables.precipitation", "pre"))
    precip = select_years(precip, cfg_get(cfg, "periods.analysis_start"), cfg_get(cfg, "periods.analysis_end"))
    precip = subset_box(precip, cfg_get(cfg, "regions.eastern_domain", {}))
    z = standardized_anomaly(precip, dim="time", ddof=0)

    nmodes = int(cfg_get(cfg, "diagnostics.eof_modes", 3))
    eofs, pcs, eigvals, varfrac = eof_svd(z, nmodes=nmodes, weight_lat=True)
    years = years_from_time(z)
    north = north_error(eigvals, n=z.sizes["time"])

    rows = []
    for i in range(nmodes):
        mode = int(eofs["mode"].values[i])
        save_field_map(eofs.isel(mode=i), out / f"eof_mode_{mode}.png", f"EOF mode {mode}", "Loading", cmap="RdBu_r", symmetric=True)
        pc = pcs.isel(mode=i)
        pc_std = (pc - pc.mean("time")) / pc.std("time", ddof=0)
        pc_df = pd.DataFrame({"year": years, "pc": pc.values, "pc_standardized": pc_std.values})
        pc_df.to_csv(out / f"pc_mode_{mode}.csv", index=False)
        save_line_plot(pc_df, "year", "pc_standardized", out / f"pc_mode_{mode}.png", f"PC mode {mode}", "z-score", zero_line=True)
        rows.append({"mode": mode, "variance_fraction": float(varfrac[i]), "variance_percent": float(varfrac[i] * 100.0), "eigenvalue": float(eigvals[i]), "north_error": float(north[i])})

    summary = pd.DataFrame(rows)
    summary.to_csv(out / "eof_summary.csv", index=False)
    save_scree(eigvals, north, out / "eof_scree_north.png")
    print(f"Wrote EOF diagnostics to {out}")


def save_scree(eigvals: np.ndarray, north: np.ndarray, out_path) -> None:
    count = min(10, eigvals.size)
    fig, ax = plt.subplots(figsize=(7.5, 4.0))
    ax.errorbar(np.arange(1, count + 1), eigvals[:count], yerr=north[:count], fmt="o")
    ax.set_xlabel("Mode")
    ax.set_ylabel("Eigenvalue")
    ax.set_title("EOF eigenvalues with North error bars")
    fig.tight_layout()
    fig.savefig(out_path, dpi=200)
    plt.close(fig)


if __name__ == "__main__":
    main()
