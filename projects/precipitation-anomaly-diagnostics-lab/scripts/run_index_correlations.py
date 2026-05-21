#!/usr/bin/env python3
from __future__ import annotations

import argparse

import numpy as np
import pandas as pd
import xarray as xr

from _bootstrap import bootstrap

bootstrap()

from climate_diagnostics.config import cfg_get, load_config, output_dir, resolve_path
from climate_diagnostics.grids import align_by_year, select_years, years_from_time
from climate_diagnostics.io import open_field, read_year_table
from climate_diagnostics.plotting import save_field_map
from climate_diagnostics.statistics import pearsonr_grid


def main() -> None:
    parser = argparse.ArgumentParser(description="Gridpoint precipitation correlation against climate indices.")
    parser.add_argument("--config", default="configs/example.yaml", help="YAML config path.")
    args = parser.parse_args()

    cfg = load_config(args.config)
    out = output_dir(cfg, args.config, "index_correlations")
    precip = open_field(resolve_path(cfg, args.config, "paths.precipitation"), cfg_get(cfg, "variables.precipitation", "pre"))
    precip = select_years(precip, cfg_get(cfg, "periods.analysis_start"), cfg_get(cfg, "periods.analysis_end"))

    index_table = read_year_table(resolve_path(cfg, args.config, "paths.climate_index"), cfg_get(cfg, "indices.year_column", "year"))
    columns = cfg_get(cfg, "indices.columns", [])
    if not columns:
        columns = [c for c in index_table.columns if c != "year"]
    missing = [c for c in columns if c not in index_table.columns]
    if missing:
        raise ValueError(f"Missing index columns: {missing}")

    common_years = np.intersect1d(years_from_time(precip), index_table["year"].to_numpy(dtype=int))
    precip_aligned = align_by_year(precip, common_years)
    aligned_years = years_from_time(precip_aligned)
    index_by_year = index_table.set_index("year").reindex(aligned_years)

    summary_rows = []
    for col in columns:
        idx = xr.DataArray(index_by_year[col].to_numpy(dtype=float), dims=("time",), coords={"time": precip_aligned["time"]})
        r, p, n = pearsonr_grid(precip_aligned, idx)
        save_field_map(r, out / f"corr_precip_{col}.png", f"Precipitation correlation with {col}", "Pearson r", cmap="RdBu_r", symmetric=True)
        save_field_map(p < 0.05, out / f"corr_precip_{col}_p_lt_005.png", f"Correlation p < 0.05 for {col}", "Significant grid cells", cmap="Greys")
        summary_rows.append(
            {
                "index": col,
                "years": int(np.nanmax(n.values)),
                "mean_abs_r": float(np.nanmean(np.abs(r.values))),
                "significant_fraction_p_lt_005": float(np.nanmean((p.values < 0.05) & np.isfinite(p.values))),
            }
        )

    pd.DataFrame(summary_rows).to_csv(out / "correlation_summary.csv", index=False)
    print(f"Wrote index-correlation diagnostics to {out}")


if __name__ == "__main__":
    main()
