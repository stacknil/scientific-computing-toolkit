from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def plot_regional_series(summary_csv: str | Path, output: str | Path) -> None:
    """Plot regional precipitation and anomaly percentage from a summary CSV."""
    data = pd.read_csv(summary_csv)
    fig, axes = plt.subplots(2, 1, figsize=(11, 7), sharex=True)
    axes[0].plot(data["year"], data["precip_mm"], marker="o", lw=1.4)
    axes[0].axhline(data["climatology_mm"].iloc[0], ls="--", color="0.4")
    axes[0].set_ylabel("Precipitation (mm)")
    axes[0].set_title("Regional July precipitation")
    colors = ["#c63d3d" if value >= 0 else "#2f78b7" for value in data["anomaly_percent"]]
    axes[1].bar(data["year"], data["anomaly_percent"], color=colors)
    axes[1].axhline(0, color="0.2", lw=1)
    axes[1].set_ylabel("Anomaly (%)")
    axes[1].set_xlabel("Year")
    fig.tight_layout()
    fig.savefig(output, dpi=160, bbox_inches="tight", metadata={})
    plt.close(fig)
