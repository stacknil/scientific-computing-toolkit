"""Synthetic ensemble utilities for reviewer-safe examples."""

from __future__ import annotations

import numpy as np
import pandas as pd


def make_synthetic_nino_ensemble(
    *,
    n_models: int = 20,
    n_leads: int = 24,
    seed: int = 42,
) -> pd.DataFrame:
    """Create a deterministic synthetic Nino 3.4 ensemble plume table."""

    if n_models <= 0 or n_leads <= 0:
        raise ValueError("n_models and n_leads must be positive")

    rng = np.random.default_rng(seed)
    lead = np.arange(1, n_leads + 1)
    base = np.cos(np.linspace(0.0, np.pi, n_leads)) * 1.5
    values: dict[str, np.ndarray] = {}
    for idx in range(n_models):
        bias = rng.uniform(-0.3, 0.3)
        noise = rng.normal(0.0, 0.1 + 0.05 * lead)
        values[f"model_{idx + 1:02d}"] = base + bias + noise

    df = pd.DataFrame(values, index=lead)
    df.index.name = "lead_month"
    return df


def ensemble_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Summarize an ensemble by lead month."""

    if df.empty or df.shape[1] == 0:
        raise ValueError("ensemble summary requires at least one member and one lead")

    values = df.astype(float)
    if not np.isfinite(values.to_numpy()).all():
        raise ValueError("ensemble summary requires finite member values")

    summary = pd.DataFrame(index=df.index)
    summary["mean"] = values.mean(axis=1)
    summary["spread"] = values.std(axis=1, ddof=0)
    summary["p10"] = values.quantile(0.10, axis=1)
    summary["p90"] = values.quantile(0.90, axis=1)
    summary["warm_probability"] = (values >= 0.5).mean(axis=1)
    summary["cold_probability"] = (values <= -0.5).mean(axis=1)
    return summary
