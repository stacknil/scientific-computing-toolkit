from __future__ import annotations

import argparse

from climate_diagnostics.config import ensure_output_dir, load_config
from climate_diagnostics.preprocess import build_precipitation_anomaly_dataset


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a regional precipitation anomaly dataset.")
    parser.add_argument("--config", required=True, help="Path to a YAML configuration file.")
    args = parser.parse_args()

    config = load_config(args.config)
    output_dir = ensure_output_dir(config)
    dataset = build_precipitation_anomaly_dataset(config)
    dataset.to_netcdf(output_dir / "precipitation_anomaly.nc")


if __name__ == "__main__":
    main()
