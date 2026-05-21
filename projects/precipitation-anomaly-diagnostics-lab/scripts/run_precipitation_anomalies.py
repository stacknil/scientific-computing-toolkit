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
from climate_diagnostics.statistics import representative_years, standardized_anomaly


def main() -> None:
    parser = argparse.ArgumentParser(description="Precipitation climatology, anomaly, and regional series diagnostics.")
    parser.add_argument("--config", default="configs/example.yaml", help="YAML config path.")
    args = parser.parse_args()

    cfg = load_config(args.config)
    out = output_dir(cfg, args.config, "precipitation")
    precip_path = resolve_path(cfg, args.config, "paths.precipitation")
    var_name = cfg_get(cfg, "variables.precipitation", "pre")

    field = open_field(precip_path, var_name)
    field = select_years(field, cfg_get(cfg, "periods.analysis_start"), cfg_get(cfg, "periods.analysis_end"))
    clim_field = select_years(field, cfg_get(cfg, "periods.climatology_start"), cfg_get(cfg, "periods.climatology_end"))

    climatology = clim_field.mean("time", skipna=True)
    std = clim_field.std("time", skipna=True, ddof=0)

    target_year = int(cfg_get(cfg, "periods.target_year"))
    years = years_from_time(field)
    target_idx = np.where(years == target_year)[0]
    if target_idx.size == 0:
        raise ValueError(f"Target year {target_year} not found in precipitation data.")
    target = field.isel(time=int(target_idx[0]))
    anomaly = target - climatology
    anomaly_percent = xr_where_nonzero(climatology, anomaly / climatology * 100.0)

    save_field_map(climatology, out / "precip_climatology.png", "Precipitation climatology", "Precipitation")
    save_field_map(std, out / "precip_standard_deviation.png", "Precipitation standard deviation", "Precipitation")
    save_field_map(anomaly, out / f"precip_anomaly_{target_year}.png", f"Precipitation anomaly {target_year}", "Anomaly", cmap="RdBu_r", symmetric=True)
    save_field_map(anomaly_percent, out / f"precip_anomaly_percent_{target_year}.png", f"Precipitation anomaly percent {target_year}", "Anomaly percent", cmap="RdBu_r", symmetric=True)

    region_box = cfg_get(cfg, "regions.regional_mean_box", {})
    regional = area_mean(subset_box(field, region_box))
    regional_years = years_from_time(regional)
    values = regional.values.astype(float)
    z = standardized_anomaly(regional, dim="time").values.astype(float)
    table = pd.DataFrame({"year": regional_years, "precipitation": values, "standardized_anomaly": z})
    table["anomaly"] = table["precipitation"] - float(np.nanmean(values))
    table["moving_average_11yr"] = table["precipitation"].rolling(11, center=True).mean()
    table["cumulative_anomaly"] = table["anomaly"].cumsum()
    table.to_csv(out / "regional_precipitation_series.csv", index=False)

    reps = representative_years(regional_years, values)
    reps.to_csv(out / "representative_years.csv", index=False)

    save_line_plot(table, "year", "standardized_anomaly", out / "regional_standardized_anomaly.png", "Regional standardized precipitation anomaly", "z-score", zero_line=True)
    save_two_line_plot(table, "year", "precipitation", "moving_average_11yr", out / "regional_precipitation_ma11.png", "Regional precipitation and 11-year moving average", "Precipitation")
    save_line_plot(table, "year", "cumulative_anomaly", out / "regional_cumulative_anomaly.png", "Regional cumulative precipitation anomaly", "Cumulative anomaly", zero_line=True)

    print(f"Wrote precipitation diagnostics to {out}")


def xr_where_nonzero(base, value):
    import xarray as xr

    return xr.where(np.isfinite(base) & (base != 0), value, np.nan)


if __name__ == "__main__":
    main()
