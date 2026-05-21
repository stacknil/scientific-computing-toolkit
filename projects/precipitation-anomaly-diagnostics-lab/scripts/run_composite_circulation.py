#!/usr/bin/env python3
from __future__ import annotations

import argparse

from _bootstrap import bootstrap

bootstrap()

from climate_diagnostics.config import cfg_get, load_config, output_dir, resolve_path
from climate_diagnostics.grids import select_years, years_from_time
from climate_diagnostics.io import open_field
from climate_diagnostics.plotting import save_field_map
from climate_diagnostics.statistics import composite_difference


def main() -> None:
    parser = argparse.ArgumentParser(description="Composite circulation diagnostics for configured representative-year groups.")
    parser.add_argument("--config", default="configs/example.yaml", help="YAML config path.")
    args = parser.parse_args()

    cfg = load_config(args.config)
    out = output_dir(cfg, args.config, "composites")
    field = open_field(resolve_path(cfg, args.config, "paths.circulation_500hpa"), cfg_get(cfg, "variables.circulation", "hgt"))
    if "level" in field.dims:
        field = field.sel(level=500, method="nearest")
    if "plev" in field.dims:
        field = field.sel(plev=50000, method="nearest")

    field = select_years(field, cfg_get(cfg, "periods.analysis_start"), cfg_get(cfg, "periods.analysis_end"))
    years = years_from_time(field)
    positive_years = cfg_get(cfg, "composites.positive_years", [])
    negative_years = cfg_get(cfg, "composites.negative_years", [])
    alpha = float(cfg_get(cfg, "composites.alpha", 0.05))
    if not positive_years or not negative_years:
        raise ValueError("Configure composites.positive_years and composites.negative_years before running composites.")

    positive, negative, diff, pval = composite_difference(field, years, positive_years, negative_years)
    save_field_map(positive, out / "composite_positive_years.png", "Composite: positive-year group", "Field value")
    save_field_map(negative, out / "composite_negative_years.png", "Composite: negative-year group", "Field value")
    save_field_map(diff, out / "composite_difference_positive_minus_negative.png", "Composite difference", "Difference", cmap="RdBu_r", symmetric=True, stipple=pval < alpha)
    print(f"Wrote composite diagnostics to {out}")


if __name__ == "__main__":
    main()
