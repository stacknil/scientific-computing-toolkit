#!/usr/bin/env python3
from __future__ import annotations

import argparse

import numpy as np
import pandas as pd

from _bootstrap import bootstrap

bootstrap()

from climate_diagnostics.config import cfg_get, load_config, output_dir, resolve_path
from climate_diagnostics.grids import area_mean, align_by_year, select_years, subset_box, years_from_time
from climate_diagnostics.io import open_field, read_year_table
from climate_diagnostics.statistics import ols_with_intercept


def main() -> None:
    parser = argparse.ArgumentParser(description="Regional precipitation regression against a climate index.")
    parser.add_argument("--config", default="configs/example.yaml", help="YAML config path.")
    parser.add_argument("--index", default=None, help="Index column to use. Defaults to the first configured index.")
    args = parser.parse_args()

    cfg = load_config(args.config)
    out = output_dir(cfg, args.config, "regression")
    precip = open_field(resolve_path(cfg, args.config, "paths.precipitation"), cfg_get(cfg, "variables.precipitation", "pre"))
    precip = select_years(precip, cfg_get(cfg, "periods.analysis_start"), cfg_get(cfg, "periods.analysis_end"))
    regional = area_mean(subset_box(precip, cfg_get(cfg, "regions.regional_mean_box", {})))
    index_table = read_year_table(resolve_path(cfg, args.config, "paths.climate_index"), cfg_get(cfg, "indices.year_column", "year"))
    configured = cfg_get(cfg, "indices.columns", [])
    index_col = args.index or (configured[0] if configured else next(c for c in index_table.columns if c != "year"))

    common_years = np.intersect1d(years_from_time(regional), index_table["year"].to_numpy(dtype=int))
    regional = align_by_year(regional, common_years)
    years = years_from_time(regional)
    x = index_table.set_index("year").reindex(years)[index_col].to_numpy(dtype=float)
    y = regional.values.astype(float)
    model = ols_with_intercept(x, y)

    coef = pd.DataFrame(
        {
            "term": ["intercept", index_col],
            "coef": model["beta"],
            "std_error": model["se"],
            "t": model["t"],
            "p": model["p"],
        }
    )
    coef.to_csv(out / "regression_coefficients.csv", index=False)
    pd.DataFrame({"year": years, index_col: x, "regional_precipitation": y, "fitted": model["fitted"], "residual": model["resid"]}).to_csv(out / "regression_series.csv", index=False)
    with (out / "regression_summary.txt").open("w", encoding="utf-8") as fh:
        fh.write(f"Model: regional_precipitation = beta0 + beta1 * {index_col}\n")
        fh.write(f"R2: {model['r2']:.6f}\n")
        fh.write(f"Residual df: {model['df']}\n")
    print(f"Wrote regression diagnostics to {out}")


if __name__ == "__main__":
    main()
