from __future__ import annotations

from pathlib import Path

from sbom_diff_risk.diffing import diff_components
from sbom_diff_risk.models import CompareReport, ReportComponents, ReportMetadata, ReportSummary
from sbom_diff_risk.normalize import normalize_input
from sbom_diff_risk.report_json import render_report_json
from sbom_diff_risk.report_md import render_report_markdown
from sbom_diff_risk.risk import evaluate_risks, summarize_risks


def test_report_json_matches_cyclonedx_golden() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json")

    rendered = render_report_json(report)
    expected = _read_example("sample-report.json")

    assert rendered == expected


def test_report_markdown_matches_cyclonedx_golden() -> None:
    report = _build_report("cdx_before.json", "cdx_after.json")

    rendered = render_report_markdown(report)
    expected = _read_example("sample-report.md")

    assert rendered == expected


def test_report_json_matches_requirements_golden() -> None:
    report = _build_report("requirements_before.txt", "requirements_after.txt")

    rendered = render_report_json(report)
    expected = _read_example("sample-requirements-report.json")

    assert rendered == expected


def test_report_markdown_matches_requirements_golden() -> None:
    report = _build_report("requirements_before.txt", "requirements_after.txt")

    rendered = render_report_markdown(report)
    expected = _read_example("sample-requirements-report.md")

    assert rendered == expected


def _build_report(before_name: str, after_name: str) -> CompareReport:
    examples = Path(__file__).resolve().parents[1] / "examples"
    before_path = examples / before_name
    after_path = examples / after_name

    before_format, before_components, before_notes = normalize_input(before_path)
    after_format, after_components, after_notes = normalize_input(after_path)

    added, removed, changed = diff_components(before_components, after_components)
    risks = evaluate_risks(added, changed, allowlist=["pypi.org", "files.pythonhosted.org", "github.com"])
    notes = [
        "This tool uses heuristic risk classification.",
        "No network enrichment was performed.",
        *before_notes,
        *after_notes,
    ]

    return CompareReport(
        summary=ReportSummary(
            added=len(added),
            removed=len(removed),
            changed=len(changed),
            risk_counts=summarize_risks(risks),
        ),
        components=ReportComponents(
            added=added,
            removed=removed,
            changed=changed,
        ),
        risks=risks,
        metadata=ReportMetadata(
            before_format=before_format,
            after_format=after_format,
            generated_at=None,
            strict=False,
            stub=False,
        ),
        notes=notes,
    )


def _read_example(name: str) -> str:
    examples = Path(__file__).resolve().parents[1] / "examples"
    return (examples / name).read_text(encoding="utf-8")
