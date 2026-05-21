#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
FIG_DIR = ROOT / "assets" / "synthetic-figures"
EXAMPLE_DIR = ROOT / "examples"


def synthetic_fields() -> dict[str, np.ndarray]:
    rng = np.random.default_rng(20260521)
    years = np.arange(1961, 2023)
    lat = np.linspace(18, 52, 35)
    lon = np.linspace(75, 135, 49)
    lon2d, lat2d = np.meshgrid(lon, lat)

    spatial_mode = (
        1.2 * np.exp(-(((lon2d - 112) / 13) ** 2 + ((lat2d - 30) / 8) ** 2))
        - 0.7 * np.exp(-(((lon2d - 95) / 15) ** 2 + ((lat2d - 42) / 9) ** 2))
        + 0.3 * np.sin(np.deg2rad(lon2d - 90)) * np.cos(np.deg2rad(lat2d))
    )
    trend = (years - years.mean()) / np.ptp(years)
    oscillation = np.sin(np.linspace(0, 5 * np.pi, years.size))
    regional_index = 0.55 * trend + 0.75 * oscillation + rng.normal(0, 0.28, years.size)
    anomaly_cube = regional_index[:, None, None] * spatial_mode[None, :, :] + rng.normal(
        0, 0.35, (years.size, lat.size, lon.size)
    )

    target_anomaly = anomaly_cube[-1]
    composite_positive = anomaly_cube[regional_index.argsort()[-8:]].mean(axis=0)
    composite_negative = anomaly_cube[regional_index.argsort()[:8]].mean(axis=0)
    composite_difference = composite_positive - composite_negative

    eof_variance = np.array([0.34, 0.19, 0.12, 0.08, 0.06, 0.04])
    mca_left = (regional_index - regional_index.mean()) / regional_index.std(ddof=0)
    mca_right = 0.72 * mca_left + rng.normal(0, 0.45, years.size)
    mca_right = (mca_right - mca_right.mean()) / mca_right.std(ddof=0)

    return {
        "years": years,
        "lat": lat,
        "lon": lon,
        "target_anomaly": target_anomaly,
        "regional_index": regional_index,
        "composite_difference": composite_difference,
        "eof_variance": eof_variance,
        "mca_left": mca_left,
        "mca_right": mca_right,
    }


def save_map(lon: np.ndarray, lat: np.ndarray, field: np.ndarray, path: Path, title: str, label: str) -> None:
    vmax = float(np.nanpercentile(np.abs(field), 98))
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    mesh = ax.pcolormesh(lon, lat, field, shading="auto", cmap="RdBu_r", vmin=-vmax, vmax=vmax)
    cb = fig.colorbar(mesh, ax=ax)
    cb.set_label(label)
    ax.set_xlabel("Longitude")
    ax.set_ylabel("Latitude")
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def save_regional_series(years: np.ndarray, index: np.ndarray, path: Path) -> None:
    z = (index - index.mean()) / index.std(ddof=0)
    ma = pd.Series(z).rolling(9, center=True).mean().to_numpy()
    fig, ax = plt.subplots(figsize=(8.0, 3.8))
    ax.bar(years, z, width=0.8, color=np.where(z >= 0, "#2f6f9f", "#b24c3d"), alpha=0.75)
    ax.plot(years, ma, color="black", linewidth=1.8, label="9-year moving average")
    ax.axhline(0, color="black", linewidth=0.8)
    ax.set_xlabel("Year")
    ax.set_ylabel("Standardized anomaly")
    ax.set_title("Synthetic regional precipitation anomaly index")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def save_eof_variance(variance: np.ndarray, path: Path) -> None:
    modes = np.arange(1, variance.size + 1)
    north = variance * np.sqrt(2 / 62)
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    ax.bar(modes, variance * 100, color="#587a5a", alpha=0.85)
    ax.errorbar(modes, variance * 100, yerr=north * 100, fmt="none", ecolor="black", capsize=4)
    ax.set_xlabel("EOF mode")
    ax.set_ylabel("Variance fraction (%)")
    ax.set_title("Synthetic EOF variance summary with North-style error bars")
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def save_mca_scores(years: np.ndarray, left: np.ndarray, right: np.ndarray, path: Path) -> float:
    corr = float(np.corrcoef(left, right)[0, 1])
    fig, ax = plt.subplots(figsize=(8.0, 3.8))
    ax.plot(years, left, label="Precipitation score", color="#2f6f9f", linewidth=1.8)
    ax.plot(years, right, label="SST score", color="#b24c3d", linewidth=1.4)
    ax.axhline(0, color="black", linewidth=0.8)
    ax.set_xlabel("Year")
    ax.set_ylabel("z-score")
    ax.set_title(f"Synthetic MCA paired scores (r = {corr:.2f})")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)
    return corr


def main() -> None:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    EXAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    fields = synthetic_fields()

    save_map(
        fields["lon"],
        fields["lat"],
        fields["target_anomaly"],
        FIG_DIR / "synthetic-precipitation-anomaly-map.png",
        "Synthetic target-year precipitation anomaly",
        "Standardized anomaly units",
    )
    save_regional_series(
        fields["years"],
        fields["regional_index"],
        FIG_DIR / "synthetic-regional-anomaly-series.png",
    )
    save_eof_variance(fields["eof_variance"], FIG_DIR / "synthetic-eof-variance-summary.png")
    save_map(
        fields["lon"],
        fields["lat"],
        fields["composite_difference"],
        FIG_DIR / "synthetic-composite-difference-map.png",
        "Synthetic composite difference: high minus low years",
        "Standardized anomaly units",
    )
    mca_corr = save_mca_scores(
        fields["years"],
        fields["mca_left"],
        fields["mca_right"],
        FIG_DIR / "synthetic-mca-score-series.png",
    )

    z = (fields["regional_index"] - fields["regional_index"].mean()) / fields["regional_index"].std(ddof=0)
    summary = pd.DataFrame(
        {
            "metric": [
                "target_year",
                "target_regional_z",
                "eof1_variance_fraction",
                "eof2_variance_fraction",
                "mca_score_correlation",
            ],
            "value": [
                int(fields["years"][-1]),
                float(z[-1]),
                float(fields["eof_variance"][0]),
                float(fields["eof_variance"][1]),
                mca_corr,
            ],
        }
    )
    summary.to_csv(EXAMPLE_DIR / "synthetic_demo_summary.csv", index=False)
    print(f"Wrote figures to {FIG_DIR}")
    print(f"Wrote summary to {EXAMPLE_DIR / 'synthetic_demo_summary.csv'}")


if __name__ == "__main__":
    main()
