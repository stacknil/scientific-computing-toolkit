#!/usr/bin/env python3
from __future__ import annotations

import argparse

import numpy as np
import pandas as pd

from _bootstrap import bootstrap

bootstrap()

from climate_diagnostics.config import cfg_get, load_config, output_dir, resolve_path
from climate_diagnostics.grids import area_mean, select_years, subset_box, years_from_time
from climate_diagnostics.io import open_field
from climate_diagnostics.plotting import save_field_map, save_line_plot, save_two_line_plot
from climate_diagnostics.statistics import linear_trend_per_decade


def main() -> None:
    parser = argparse.ArgumentParser(description="Linear trend and regional cumulative anomaly diagnostics.")
    parser.add_argument("--config", default="configs/example.yaml", help="YAML config path.")
    args = parser.parse_args()

    cfg = load_config(args.config)
    out = output_dir(cfg, args.config, "trend")
    precip = open_field(resolve_path(cfg, args.config, "paths.precipitation"), cfg_get(cfg, "variables.precipitation", "pre"))
    precip = select_years(precip, cfg_get(cfg, "periods.analysis_start"), cfg_get(cfg, "periods.analysis_end"))
    years = years_from_time(precip)

    trend, pval = linear_trend_per_decade(precip, years)
    save_field_map(trend, out / "precip_trend_per_decade.png", "Linear precipitation trend", "Trend per decade", cmap="RdBu_r", symmetric=True, stipple=pval < 0.05)

    regional = area_mean(subset_box(precip, cfg_get(cfg, "regions.regional_mean_box", {})))
    values = regional.values.astype(float)
    table = pd.DataFrame({"year": years_from_time(regional), "precipitation": values})
    table["anomaly"] = table["precipitation"] - float(np.nanmean(values))
    table["moving_average_11yr"] = table["precipitation"].rolling(11, center=True).mean()
    table["cumulative_anomaly"] = table["anomaly"].cumsum()
    table.to_csv(out / "regional_trend_series.csv", index=False)
    save_two_line_plot(table, "year", "precipitation", "moving_average_11yr", out / "regional_precipitation_ma11.png", "Regional precipitation and 11-year moving average", "Precipitation")
    save_line_plot(table, "year", "cumulative_anomaly", out / "regional_cumulative_anomaly.png", "Regional cumulative precipitation anomaly", "Cumulative anomaly", zero_line=True)

    print(f"Wrote trend diagnostics to {out}")


if __name__ == "__main__":
    main()
