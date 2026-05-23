#!/usr/bin/env python3
"""Generate a reviewer-safe synthetic ensemble summary CSV."""

from __future__ import annotations

import argparse
from pathlib import Path

from python_weather_diagnostics_toolkit.ensemble import (
    ensemble_summary,
    make_synthetic_nino_ensemble,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("outputs/synthetic_ensemble_summary.csv"))
    parser.add_argument("--models", type=int, default=20)
    parser.add_argument("--leads", type=int, default=24)
    parser.add_argument("--seed", type=int, default=42)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    df = make_synthetic_nino_ensemble(
        n_models=args.models,
        n_leads=args.leads,
        seed=args.seed,
    )
    summary = ensemble_summary(df)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    summary.to_csv(args.out)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
