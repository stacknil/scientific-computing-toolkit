from __future__ import annotations

from .diffing import component_key
from .models import CompareReport


def render_report_markdown(report: CompareReport) -> str:
    lines = [
        "# sbom-diff-and-risk report",
        "",
        "## Summary",
        f"- Before format: {report.metadata.before_format}",
        f"- After format: {report.metadata.after_format}",
        f"- Added: {report.summary.added}",
        f"- Removed: {report.summary.removed}",
        f"- Version changes: {report.summary.changed}",
        "",
        "## Risk buckets",
    ]

    for bucket, count in report.summary.risk_counts.items():
        lines.append(f"- {bucket}: {count}")

    lines.extend(
        [
            "",
            "## Added components",
            "| name | version | ecosystem | risk buckets |",
            "|------|---------|-----------|--------------|",
        ]
    )
    if report.components.added:
        for component in report.components.added:
            lines.append(
                f"| {component.name} | {component.version or ''} | {component.ecosystem} | "
                f"{_risk_labels_for_component(report, component)} |"
            )
    else:
        lines.append("| _none_ |  |  |  |")

    lines.extend(
        [
            "",
            "## Removed components",
            "| name | version | ecosystem |",
            "|------|---------|-----------|",
        ]
    )
    if report.components.removed:
        for component in report.components.removed:
            lines.append(f"| {component.name} | {component.version or ''} | {component.ecosystem} |")
    else:
        lines.append("| _none_ |  |  |")

    lines.extend(
        [
            "",
            "## Version changes",
            "| name | before | after | classification | risk buckets |",
            "|------|--------|-------|----------------|--------------|",
        ]
    )
    if report.components.changed:
        for change in report.components.changed:
            lines.append(
                f"| {change.after.name} | {change.before.version or ''} | "
                f"{change.after.version or ''} | {change.classification} | "
                f"{_risk_labels_for_component(report, change.after)} |"
            )
    else:
        lines.append("| _none_ |  |  |  |  |")

    lines.extend(
        [
            "",
            "## Risk findings",
            "| bucket | component | version | rationale |",
            "|--------|-----------|---------|-----------|",
        ]
    )
    if report.risks:
        for finding in report.risks:
            lines.append(
                f"| {finding.bucket.value} | {finding.component.name} | {finding.component.version or ''} | "
                f"{_escape_table_text(finding.rationale)} |"
            )
    else:
        lines.append("| _none_ |  |  |  |")

    lines.extend(["", "## Notes"])
    if report.notes:
        lines.extend(f"- {note}" for note in report.notes)
    else:
        lines.append("- No additional notes.")

    lines.append("")
    return "\n".join(lines)


def _risk_labels_for_component(report: CompareReport, component) -> str:
    labels: list[str] = []
    key = component_key(component)
    for finding in report.risks:
        if finding.component_key == key:
            labels.append(finding.bucket.value)
    if not labels:
        return ""
    return ", ".join(labels)


def _escape_table_text(value: str) -> str:
    return value.replace("|", "\\|")
