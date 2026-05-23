#!/usr/bin/env python3
"""Run a synthetic climate-statistics summary."""

from __future__ import annotations

import argparse
import json

import numpy as np

from python_weather_diagnostics_toolkit.climate import (
    anomaly,
    composite_mean,
    pearson_correlation_field,
    standardized_anomaly,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-threshold", type=float, default=1.0)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    index = np.array([-1.0, -0.2, 0.4, 1.2, 1.6])
    baseline_mean = np.array([10.0, 10.0, 10.0])
    baseline_std = np.array([2.0, 2.5, 5.0])
    current = np.array([12.0, 8.0, 15.0])
    field = np.stack(
        [
            np.array([[0.0, 4.0], [1.0, 3.0]]),
            np.array([[1.0, 3.0], [2.0, 3.0]]),
            np.array([[2.0, 2.0], [3.0, 3.0]]),
            np.array([[3.0, 1.0], [4.0, 3.0]]),
            np.array([[4.0, 0.0], [5.0, 3.0]]),
        ]
    )
    event_mask = index >= args.event_threshold
    corr = pearson_correlation_field(index, field)
    payload = {
        "anomaly": anomaly(current, baseline_mean).round(3).tolist(),
        "standardized_anomaly": standardized_anomaly(
            current,
            baseline_mean,
            baseline_std,
        ).round(3).tolist(),
        "event_sample_count": int(event_mask.sum()),
        "composite_mean_max": float(np.nanmax(composite_mean(field, event_mask))),
        "max_abs_correlation": float(np.nanmax(np.abs(corr))),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
