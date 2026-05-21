from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import xarray as xr


def save_field_map(
    da: xr.DataArray,
    out_path: str | Path,
    title: str,
    colorbar_label: str,
    cmap: str = "viridis",
    symmetric: bool = False,
    stipple: xr.DataArray | None = None,
) -> None:
    """Save a simple latitude/longitude pcolormesh map."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    values = da.values
    kwargs = {}
    if symmetric:
        vmax = float(np.nanpercentile(np.abs(values), 98))
        vmax = max(vmax, 1.0e-12)
        kwargs.update(vmin=-vmax, vmax=vmax)

    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    mesh = ax.pcolormesh(da["longitude"], da["latitude"], values, shading="auto", cmap=cmap, **kwargs)
    cb = fig.colorbar(mesh, ax=ax)
    cb.set_label(colorbar_label)
    ax.set_xlabel("Longitude")
    ax.set_ylabel("Latitude")
    ax.set_title(title)

    if stipple is not None:
        sig = stipple.values.astype(bool) & np.isfinite(values)
        if np.any(sig):
            yy, xx = np.where(sig)
            lon = np.asarray(da["longitude"].values)
            lat = np.asarray(da["latitude"].values)
            ax.scatter(lon[xx], lat[yy], s=3, marker=".", linewidths=0, color="black", alpha=0.55)

    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)


def save_line_plot(df: pd.DataFrame, x: str, y: str, out_path: str | Path, title: str, ylabel: str, zero_line: bool = False) -> None:
    """Save a single-series line plot."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8.5, 3.8))
    ax.plot(df[x], df[y], marker="o", linewidth=1.2)
    if zero_line:
        ax.axhline(0.0, linewidth=0.8, color="black")
    ax.set_xlabel(x)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)


def save_two_line_plot(df: pd.DataFrame, x: str, y1: str, y2: str, out_path: str | Path, title: str, ylabel: str) -> None:
    """Save a two-series line plot."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8.5, 3.8))
    ax.plot(df[x], df[y1], marker="o", linewidth=1.0, label=y1)
    ax.plot(df[x], df[y2], linewidth=1.8, label=y2)
    ax.set_xlabel(x)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
