from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .diffing import diff_components
from .errors import ParseError, PolicyError
from .models import CompareReport, ReportComponents, ReportMetadata, ReportSummary
from .normalize import SUPPORTED_FORMATS, normalize_input_with_options
from .policy_evaluator import evaluate_policy
from .policy_parser import build_policy
from .presentation import effective_policy_evaluation, summarize_violations_by_rule
from .report_json import render_report_json
from .report_md import render_report_markdown
from .report_sarif import render_report_sarif_output
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
        description="Compare two local dependency inputs and emit deterministic reports.",
        epilog="Exit codes: 0 = success/no blocking violations, 1 = blocking policy violations, 2 = usage/parse/runtime error.",
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
    compare.add_argument(
        "--pyproject-group",
        default=None,
        help="Select a PEP 735 [dependency-groups] group when a compared input is pyproject.toml.",
    )
    compare.add_argument("--out-json", type=Path, default=None, help="Write a JSON report to this path.")
    compare.add_argument("--out-md", type=Path, default=None, help="Write a Markdown report to this path.")
    compare.add_argument(
        "--out-sarif",
        type=Path,
        default=None,
        help="Write a SARIF 2.1.0 subset report for GitHub-compatible code scanning ingestion.",
    )
    compare.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="Apply a YAML policy v1 file. Blocking violations return exit code 1.",
    )
    compare.add_argument(
        "--fail-on",
        default=None,
        help="Comma-separated rule ids to treat as blocking, merged with any --policy block_on values.",
    )
    compare.add_argument(
        "--warn-on",
        default=None,
        help="Comma-separated rule ids to treat as warnings, merged with any --policy warn_on values.",
    )
    compare.add_argument(
        "--strict",
        action="store_true",
        help="Fail with exit code 2 if normalization emits warnings or conservative parser notes.",
    )
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
    except (FileNotFoundError, NotImplementedError, ParseError, PolicyError, ValueError) as exc:
        parser.print_usage(sys.stderr)
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        print(f"{parser.prog}: command failed with exit code 2 before report completion.", file=sys.stderr)
        return 2


def run_compare(args: argparse.Namespace) -> int:
    pyproject_group = getattr(args, "pyproject_group", None)

    if args.enrich_pypi:
        raise NotImplementedError("--enrich-pypi is reserved for a later network-enabled release.")

    if args.out_json is None and args.out_md is None and args.out_sarif is None:
        raise ValueError("at least one of --out-json, --out-md, or --out-sarif must be provided")

    before_path: Path = args.before
    after_path: Path = args.after
    if not before_path.is_file():
        raise FileNotFoundError(f"before input does not exist: {before_path}")
    if not after_path.is_file():
        raise FileNotFoundError(f"after input does not exist: {after_path}")

    before_declared = _resolve_declared_format(args.format, args.before_format)
    after_declared = _resolve_declared_format(args.format, args.after_format)
    before_format, before_components, before_notes = normalize_input_with_options(
        before_path,
        declared_format=before_declared,
        pyproject_group=pyproject_group,
    )
    after_format, after_components, after_notes = normalize_input_with_options(
        after_path,
        declared_format=after_declared,
        pyproject_group=pyproject_group,
    )
    if pyproject_group and before_format != "pyproject-toml" and after_format != "pyproject-toml":
        raise ValueError("--pyproject-group requires at least one pyproject.toml input.")
    policy, policy_path = build_policy(policy_path=args.policy, fail_on=args.fail_on, warn_on=args.warn_on)

    added, removed, changed = diff_components(before_components, after_components)
    allowlist = [entry.strip() for entry in args.source_allowlist.split(",") if entry.strip()]
    risks = evaluate_risks(added, changed, allowlist=allowlist)
    policy_evaluation = evaluate_policy(
        policy,
        policy_path=policy_path,
        added=added,
        changed=changed,
        findings=risks,
    )

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
            policy_evaluation=policy_evaluation,
        ),
        notes=notes,
    )

    if args.strict and (before_notes or after_notes):
        raise ValueError(_format_strict_failure(before_notes, after_notes))

    if args.out_json is not None:
        _write_text(args.out_json, render_report_json(report))
    if args.out_md is not None:
        _write_text(args.out_md, render_report_markdown(report))
    if args.out_sarif is not None:
        sarif_output = render_report_sarif_output(
            report,
            before_path=before_path,
            after_path=after_path,
            base_dir=Path.cwd(),
        )
        _write_text(args.out_sarif, sarif_output.content)
        if sarif_output.metadata.warning_message:
            print(f"sbom-diff-risk: warning: {sarif_output.metadata.warning_message}", file=sys.stderr)

    if policy_evaluation.exit_code == 1:
        print(_format_policy_failure_summary(policy_evaluation), file=sys.stderr)

    return policy_evaluation.exit_code


def _resolve_declared_format(global_format: str, explicit_format: str | None) -> str | None:
    if explicit_format:
        return explicit_format
    if global_format == "auto":
        return None
    return global_format


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _format_strict_failure(before_notes: list[str], after_notes: list[str]) -> str:
    notes = [*before_notes, *after_notes]
    if not notes:
        return "strict mode failed because normalization produced warnings."
    return f"strict mode failed because normalization produced {len(notes)} warning(s): {notes[0]}"


def _format_policy_failure_summary(policy_evaluation) -> str:
    resolved = effective_policy_evaluation(policy_evaluation)
    lines = [
        "sbom-diff-risk: blocking policy violations detected (exit code 1).",
        (
            f"sbom-diff-risk: policy source = {resolved.policy_path}"
            if resolved.policy_path
            else "sbom-diff-risk: policy source = CLI flags"
        ),
        f"sbom-diff-risk: blocking findings = {len(resolved.blocking_violations)}",
    ]
    for rule_id, count in summarize_violations_by_rule(resolved.blocking_violations):
        lines.append(f"sbom-diff-risk: {rule_id} = {count}")
    if resolved.warning_violations:
        lines.append(f"sbom-diff-risk: warnings = {len(resolved.warning_violations)}")
    if resolved.suppressed_violations:
        lines.append(f"sbom-diff-risk: suppressed = {len(resolved.suppressed_violations)}")
    lines.append("sbom-diff-risk: outputs were written; inspect the generated reports for full details.")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
