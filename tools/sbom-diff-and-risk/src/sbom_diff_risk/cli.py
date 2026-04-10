from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .diffing import diff_components
from .models import CompareReport, ReportComponents, ReportMetadata, ReportSummary
from .normalize import SUPPORTED_FORMATS, normalize_input
from .report_json import render_report_json
from .report_md import render_report_markdown
from .risk import evaluate_risks, summarize_risks


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom-diff-risk",
        description="Local, deterministic SBOM diff and heuristic risk reporting.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    compare = subparsers.add_parser(
        "compare",
        help="Compare two dependency inputs and write JSON and/or Markdown reports.",
    )
    compare.add_argument("--before", type=Path, required=True, help="Path to the before input.")
    compare.add_argument("--after", type=Path, required=True, help="Path to the after input.")
    compare.add_argument(
        "--format",
        choices=("auto", *SUPPORTED_FORMATS),
        default="auto",
        help="Shorthand for setting both input formats at once.",
    )
    compare.add_argument(
        "--before-format",
        choices=SUPPORTED_FORMATS,
        default=None,
        help="Explicit format for the before input.",
    )
    compare.add_argument(
        "--after-format",
        choices=SUPPORTED_FORMATS,
        default=None,
        help="Explicit format for the after input.",
    )
    compare.add_argument("--out-json", type=Path, default=None, help="Write a JSON report to this path.")
    compare.add_argument("--out-md", type=Path, default=None, help="Write a Markdown report to this path.")
    compare.add_argument("--strict", action="store_true", help="Treat scaffold notes as errors.")
    compare.add_argument(
        "--enrich-pypi",
        action="store_true",
        help="Reserved for future PyPI metadata enrichment. Not implemented in v0.1 scaffolding.",
    )
    compare.add_argument(
        "--source-allowlist",
        default="pypi.org,files.pythonhosted.org,github.com",
        help="Comma-separated source host allowlist for provenance heuristics.",
    )
    compare.set_defaults(handler=run_compare)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (FileNotFoundError, NotImplementedError, ValueError) as exc:
        parser.print_usage(sys.stderr)
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return 2


def run_compare(args: argparse.Namespace) -> int:
    if args.enrich_pypi:
        raise NotImplementedError("--enrich-pypi is reserved for a later network-enabled release.")

    if args.out_json is None and args.out_md is None:
        raise ValueError("at least one of --out-json or --out-md must be provided")

    before_path: Path = args.before
    after_path: Path = args.after
    if not before_path.is_file():
        raise FileNotFoundError(f"before input does not exist: {before_path}")
    if not after_path.is_file():
        raise FileNotFoundError(f"after input does not exist: {after_path}")

    before_declared = _resolve_declared_format(args.format, args.before_format)
    after_declared = _resolve_declared_format(args.format, args.after_format)
    before_format, before_components, before_notes = normalize_input(before_path, before_declared)
    after_format, after_components, after_notes = normalize_input(after_path, after_declared)

    added, removed, changed = diff_components(before_components, after_components)
    allowlist = [entry.strip() for entry in args.source_allowlist.split(",") if entry.strip()]
    risks = evaluate_risks(added, changed, allowlist=allowlist)

    notes = [
        "This tool uses heuristic risk classification.",
        "No network enrichment was performed.",
        *before_notes,
        *after_notes,
    ]

    report = CompareReport(
        summary=ReportSummary(
            added=len(added),
            removed=len(removed),
            changed=len(changed),
            risk_counts=summarize_risks(risks),
        ),
        components=ReportComponents(added=added, removed=removed, changed=changed),
        risks=risks,
        metadata=ReportMetadata(
            before_format=before_format,
            after_format=after_format,
            generated_at=None,
            strict=args.strict,
            stub=False,
        ),
        notes=notes,
    )

    if args.strict and (before_notes or after_notes):
        raise ValueError("strict mode failed because normalization produced warnings.")

    if args.out_json is not None:
        _write_text(args.out_json, render_report_json(report))
    if args.out_md is not None:
        _write_text(args.out_md, render_report_markdown(report))

    return 0


def _resolve_declared_format(global_format: str, explicit_format: str | None) -> str | None:
    if explicit_format:
        return explicit_format
    if global_format == "auto":
        return None
    return global_format


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
