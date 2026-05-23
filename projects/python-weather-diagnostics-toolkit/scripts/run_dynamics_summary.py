#!/usr/bin/env python3
"""Run a synthetic dynamic-diagnostics summary."""

from __future__ import annotations

import argparse
import json

import numpy as np

from python_weather_diagnostics_toolkit.dynamics import horizontal_advection, relative_vorticity
from python_weather_diagnostics_toolkit.synthetic import make_synthetic_weather_dataset


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pressure-level", type=int, default=850)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    ds = make_synthetic_weather_dataset()
    layer = ds.sel(pressure_level=args.pressure_level)
    lat = ds.latitude.values
    lon = ds.longitude.values
    vort = relative_vorticity(layer.u.values, layer.v.values, lat, lon)
    adv = horizontal_advection(layer.temperature.values, layer.u.values, layer.v.values, lat, lon)
    payload = {
        "pressure_level_hpa": args.pressure_level,
        "max_abs_vorticity_s-1": float(np.nanmax(np.abs(vort))),
        "mean_temperature_advection_k_s-1": float(np.nanmean(adv)),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
