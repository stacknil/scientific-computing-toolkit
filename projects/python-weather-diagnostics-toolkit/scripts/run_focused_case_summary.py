#!/usr/bin/env python3
"""Run a synthetic focused-case diagnostics summary."""

from __future__ import annotations

import argparse
import json

import numpy as np

from python_weather_diagnostics_toolkit.dynamics import temperature_tendency_terms
from python_weather_diagnostics_toolkit.features import (
    area_mean,
    persistence_baseline,
    regression_metrics,
    residual_diagnostics,
    ridge_alpha_grid,
    ridge_regression_fit_predict,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=48)
    parser.add_argument("--train-fraction", type=float, default=0.7)
    return parser


def _synthetic_tendency_payload() -> dict[str, float]:
    pressure = np.array([900.0, 850.0, 800.0])
    lat = np.linspace(30.0, 42.0, 6)
    lon = np.linspace(105.0, 125.0, 8)
    lon2d, lat2d = np.meshgrid(lon, lat)
    temperature = np.empty((pressure.size, lat.size, lon.size), dtype=float)
    u = np.empty_like(temperature)
    v = np.empty_like(temperature)
    omega = np.empty_like(temperature)
    for idx, level in enumerate(pressure):
        temperature[idx] = (
            282.0
            - 0.008 * (1000.0 - level)
            - 0.25 * (lat2d - 30.0)
            + 0.04 * (lon2d - 105.0)
        )
        u[idx] = 10.0 + 0.02 * (level - 850.0)
        v[idx] = -6.0 - 0.15 * (lat2d - 36.0)
        omega[idx] = 0.18 + 0.01 * idx

    terms = temperature_tendency_terms(temperature, u, v, omega, pressure, lat, lon)
    level_idx = int(np.where(pressure == 850.0)[0][0])
    payload = {}
    for name in (
        "zonal_advection",
        "meridional_advection",
        "vertical_advection",
        "adiabatic_compression",
        "dry_dynamic_tendency",
    ):
        payload[f"area_mean_{name}_k_s-1"] = float(area_mean(terms[name][level_idx], lat))
    return payload


def _synthetic_model_payload(samples: int, train_fraction: float) -> dict[str, float]:
    if samples < 12:
        raise ValueError("samples must be at least 12")
    t = np.arange(samples, dtype=float)
    z500 = 5600.0 + 30.0 * np.sin(t / 7.0)
    t850 = 268.0 - 0.08 * t + 1.5 * np.cos(t / 5.0)
    tendency_proxy = -0.02 * np.maximum(t - samples * 0.35, 0.0)
    t2m = (
        273.0
        + 0.04 * (z500 - z500.mean())
        + 0.8 * (t850 - t850.mean())
        + 15.0 * tendency_proxy
    )
    target = np.roll(t2m, -1)[:-1]
    features = np.column_stack([z500[:-1], t850[:-1], tendency_proxy[:-1], t2m[:-1]])
    alpha_table = ridge_alpha_grid(
        features,
        target,
        [0.0, 0.1, 1.0, 10.0],
        train_fraction=train_fraction,
    )
    best_alpha = float(alpha_table.iloc[0]["alpha"])
    model = ridge_regression_fit_predict(
        features,
        target,
        train_fraction=train_fraction,
        alpha=best_alpha,
    )
    metrics = regression_metrics(model["y_test"], model["y_pred"])
    residuals = residual_diagnostics(model["y_test"], model["y_pred"])
    split = int(features.shape[0] * train_fraction)
    persistence = persistence_baseline(t2m[split:], lead_steps=1)
    persistence_metrics = regression_metrics(persistence["y_true"], persistence["y_pred"])
    return {
        "best_alpha": best_alpha,
        "model_rmse": metrics["rmse"],
        "model_bias": metrics["bias"],
        "model_correlation": metrics["correlation"],
        "persistence_rmse": persistence_metrics["rmse"],
        "rmse_skill_vs_persistence": 1.0 - metrics["rmse"] / persistence_metrics["rmse"],
        "max_abs_residual": residuals["max_abs_residual"],
        "overprediction_fraction": residuals["overprediction_fraction"],
    }


def main() -> None:
    args = build_parser().parse_args()
    payload = {
        "temperature_tendency": _synthetic_tendency_payload(),
        "ridge_baseline": _synthetic_model_payload(args.samples, args.train_fraction),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
