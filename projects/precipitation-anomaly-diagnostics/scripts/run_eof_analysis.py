from __future__ import annotations

import argparse

import pandas as pd
import xarray as xr

from climate_diagnostics.config import ensure_output_dir, load_config
from climate_diagnostics.eof import compute_eof, representative_years, standardized_pc


def main() -> None:
    parser = argparse.ArgumentParser(description="Run EOF analysis on a precipitation anomaly dataset.")
    parser.add_argument("--config", required=True, help="Path to a YAML configuration file.")
    parser.add_argument("--input", default=None, help="Optional anomaly NetCDF path.")
    args = parser.parse_args()

    config = load_config(args.config)
    output_dir = ensure_output_dir(config)
    eof_config = config["analysis"]["eof"]
    anomaly_path = args.input or output_dir / "precipitation_anomaly.nc"
    dataset = xr.open_dataset(anomaly_path)
    field = next(iter(dataset.data_vars.values()))

    result = compute_eof(field, n_modes=int(eof_config["n_modes"]))
    result.patterns.to_netcdf(output_dir / "eof_patterns.nc")
    result.pcs.to_netcdf(output_dir / "eof_pcs.nc")

    variance = result.variance_fraction.to_series().reset_index()
    variance["variance_percent"] = variance["variance_fraction"] * 100.0
    variance.to_csv(output_dir / "eof_variance.csv", index=False)

    pc1 = standardized_pc(result.pcs.sel(mode=1))
    years = representative_years(pc1, threshold=float(eof_config["typical_year_threshold"]))
    pd.DataFrame(
        [{"phase": phase, "years": ",".join(map(str, values))} for phase, values in years.items()]
    ).to_csv(output_dir / "representative_years.csv", index=False)


if __name__ == "__main__":
    main()
