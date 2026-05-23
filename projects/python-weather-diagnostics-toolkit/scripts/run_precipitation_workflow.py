#!/usr/bin/env python3
"""Run a synthetic station and precipitation workflow summary."""

from __future__ import annotations

import argparse
import json

import numpy as np

from python_weather_diagnostics_toolkit.interpolation import idw_interpolate_station_to_grid
from python_weather_diagnostics_toolkit.precipitation import (
    cumulative_to_rate,
    event_total,
    mark_missing_sentinel,
    threshold_exceedance,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threshold-mm", type=float, default=50.0)
    parser.add_argument("--step-hours", type=float, default=6.0)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    station_lon = np.array([100.0, 101.0, 102.0, 103.0])
    station_lat = np.array([30.0, 31.0, 30.5, 31.5])
    station_values = mark_missing_sentinel(np.array([12.0, -32766.0, 28.0, 34.0]))
    grid = idw_interpolate_station_to_grid(
        station_lon,
        station_lat,
        station_values,
        np.array([100.0, 101.0, 102.0]),
        np.array([30.0, 31.0]),
        min_neighbors=2,
    )
    accumulated = np.array(
        [
            [[0.0, 4.0, 10.0], [0.0, 8.0, 15.0]],
            [[1.0, 3.0, 9.0], [2.0, 6.0, 14.0]],
        ]
    )
    rate = cumulative_to_rate(accumulated, step_hours=args.step_hours, axis=-1)
    total = event_total(rate, axis=-1)
    payload = {
        "finite_interpolated_grid_points": int(np.isfinite(grid).sum()),
        "max_rate_mm_day": float(np.nanmax(rate)),
        "max_event_total_mm_day_equivalent": float(np.nanmax(total)),
        "threshold_grid_points": int(threshold_exceedance(total, threshold=args.threshold_mm).sum()),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
