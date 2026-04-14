from __future__ import annotations

from .diffing import component_key
from .models import CompareReport
from .presentation import effective_policy_evaluation


def render_report_markdown(report: CompareReport) -> str:
    policy_evaluation = effective_policy_evaluation(report.metadata.policy_evaluation)
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
            "## Policy summary",
            f"- Applied: {'yes' if policy_evaluation.applied else 'no'}",
            f"- Policy path: {policy_evaluation.policy_path or 'none'}",
            f"- Exit code: {policy_evaluation.exit_code}",
            f"- Blocking findings: {len(policy_evaluation.blocking_violations)}",
            f"- Warnings: {len(policy_evaluation.warning_violations)}",
            f"- Suppressed findings: {len(policy_evaluation.suppressed_violations)}",
        ]
    )

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

    lines.extend(
        [
            "",
            "## Blocking violations",
            "| rule id | component | level | message |",
            "|---------|-----------|-------|---------|",
        ]
    )
    if policy_evaluation.blocking_violations:
        for violation in policy_evaluation.blocking_violations:
            lines.append(
                f"| {violation.rule_id} | {violation.component_name or ''} | {violation.level.value if violation.level else ''} | "
                f"{_escape_table_text(violation.message)} |"
            )
    else:
        lines.append("| _none_ |  |  |  |")

    lines.extend(
        [
            "",
            "## Warnings",
            "| rule id | component | level | message |",
            "|---------|-----------|-------|---------|",
        ]
    )
    if policy_evaluation.warning_violations:
        for violation in policy_evaluation.warning_violations:
            lines.append(
                f"| {violation.rule_id} | {violation.component_name or ''} | {violation.level.value if violation.level else ''} | "
                f"{_escape_table_text(violation.message)} |"
            )
    else:
        lines.append("| _none_ |  |  |  |")

    if policy_evaluation.suppressed_violations:
        lines.extend(
            [
                "",
                "## Suppressions",
                "| rule id | component | level | reason | message |",
                "|---------|-----------|-------|--------|---------|",
            ]
        )
        for violation in policy_evaluation.suppressed_violations:
            lines.append(
                f"| {violation.rule_id} | {violation.component_name or ''} | "
                f"{violation.level.value if violation.level else 'n/a'} | "
                f"{violation.suppression_reason or ''} | {_escape_table_text(violation.message)} |"
            )

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
