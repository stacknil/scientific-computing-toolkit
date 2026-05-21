from __future__ import annotations

import argparse

import xarray as xr

from climate_diagnostics.composite import composite_anomaly
from climate_diagnostics.config import ensure_output_dir, load_config


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a simple composite anomaly analysis.")
    parser.add_argument("--config", required=True, help="Path to a YAML configuration file.")
    parser.add_argument("--field", required=True, help="Input field NetCDF path.")
    parser.add_argument("--variable", required=True, help="Variable name to composite.")
    parser.add_argument("--years", required=True, help="Comma-separated representative years.")
    parser.add_argument("--name", default="composite_anomaly", help="Output file stem.")
    args = parser.parse_args()

    config = load_config(args.config)
    output_dir = ensure_output_dir(config)
    dataset = xr.open_dataset(args.field)
    field = dataset[args.variable]
    years = [int(value) for value in args.years.split(",") if value.strip()]
    climatology = field.mean("time", skipna=True)
    result = composite_anomaly(field, years, climatology)
    result.to_dataset(name=args.variable).to_netcdf(output_dir / f"{args.name}.nc")


if __name__ == "__main__":
    main()
