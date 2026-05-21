#!/usr/bin/env python3
from __future__ import annotations

import argparse

import pandas as pd

from _bootstrap import bootstrap

bootstrap()

from climate_diagnostics.config import cfg_get, load_config, output_dir, resolve_path
from climate_diagnostics.io import read_year_table
from climate_diagnostics.plotting import save_line_plot
from climate_diagnostics.statistics import autocorr_table, crosscorr_table, pair_names, partial_corr_matrix


def main() -> None:
    parser = argparse.ArgumentParser(description="Partial, auto-, and cross-correlation diagnostics for climate indices.")
    parser.add_argument("--config", default="configs/example.yaml", help="YAML config path.")
    args = parser.parse_args()

    cfg = load_config(args.config)
    out = output_dir(cfg, args.config, "lag_diagnostics")
    table = read_year_table(resolve_path(cfg, args.config, "paths.climate_index"), cfg_get(cfg, "indices.year_column", "year"))
    columns = cfg_get(cfg, "indices.columns", [c for c in table.columns if c != "year"])
    max_lag = int(cfg_get(cfg, "diagnostics.max_lag", 5))

    values = table[columns].to_numpy(dtype=float)
    pcorr, pcorr_p = partial_corr_matrix(values, columns)
    pcorr.to_csv(out / "partial_correlation_r.csv")
    pcorr_p.to_csv(out / "partial_correlation_p.csv")

    acf_rows = []
    for col in columns:
        acf = autocorr_table(table[col].to_numpy(dtype=float), max_lag)
        acf.insert(0, "index", col)
        acf_rows.append(acf)
        save_line_plot(acf, "lag", "r", out / f"autocorrelation_{col}.png", f"Autocorrelation: {col}", "Pearson r", zero_line=True)
    pd.concat(acf_rows, ignore_index=True).to_csv(out / "autocorrelation.csv", index=False)

    ccf_rows = []
    for left, right in pair_names(columns):
        ccf = crosscorr_table(table[left].to_numpy(dtype=float), table[right].to_numpy(dtype=float), max_lag)
        ccf.insert(0, "left_index", left)
        ccf.insert(1, "right_index", right)
        ccf_rows.append(ccf)
        save_line_plot(ccf, "lag", "r", out / f"crosscorrelation_{left}_{right}.png", f"Cross-correlation: {left} vs {right}", "Pearson r", zero_line=True)
    pd.concat(ccf_rows, ignore_index=True).to_csv(out / "crosscorrelation.csv", index=False)

    print(f"Wrote lag diagnostics to {out}")


if __name__ == "__main__":
    main()
