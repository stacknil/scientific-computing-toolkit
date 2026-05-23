#!/usr/bin/env python3
"""Run a synthetic dewpoint calculation check."""

from __future__ import annotations

import argparse
import json

import numpy as np

from python_weather_diagnostics_toolkit.thermodynamics import (
    magnus_dewpoint_celsius,
    relative_humidity_from_dewpoint,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--temperature-c", type=float, default=22.0)
    parser.add_argument("--relative-humidity", type=float, default=68.0)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    dewpoint = magnus_dewpoint_celsius(args.temperature_c, args.relative_humidity)
    rh_back = relative_humidity_from_dewpoint(args.temperature_c, dewpoint)
    payload = {
        "temperature_c": args.temperature_c,
        "relative_humidity_input": args.relative_humidity,
        "dewpoint_c": float(np.asarray(dewpoint)),
        "roundtrip_relative_humidity_ratio": float(np.asarray(rh_back)),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
