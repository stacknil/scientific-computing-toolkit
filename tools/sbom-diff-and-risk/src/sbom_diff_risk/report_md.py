from __future__ import annotations

from .diffing import component_key
from .models import CompareReport
from .presentation import (
    build_trust_signal_report_sections,
    effective_policy_evaluation,
    provenance_policy_summary,
    provenance_policy_violations,
    scorecard_policy_violations,
)


def render_report_markdown(report: CompareReport) -> str:
    policy_evaluation = effective_policy_evaluation(report.metadata.policy_evaluation)
    trust_signal_sections = build_trust_signal_report_sections(report)
    provenance_impacts = provenance_policy_violations(report.metadata.policy_evaluation)
    provenance_policy = provenance_policy_summary(report.metadata.policy_evaluation)
    scorecard_impacts = scorecard_policy_violations(report.metadata.policy_evaluation)
    provenance_summary = trust_signal_sections["provenance_summary"]
    attestation_summary = trust_signal_sections["attestation_summary"]
    scorecard_summary = trust_signal_sections["scorecard_summary"]
    enrichment_metadata = trust_signal_sections["enrichment_metadata"]
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
            "## Provenance summary",
            f"- Enrichment mode: {enrichment_metadata['mode']}",
            f"- Network access performed: {'yes' if enrichment_metadata['pypi_network_access_performed'] else 'no'}",
            f"- Candidate components for enrichment: {enrichment_metadata['candidate_components']}",
            f"- Supported components for enrichment: {enrichment_metadata['supported_components']}",
            f"- Observed provenance status counts: {_format_status_counts(enrichment_metadata['status_counts'])}",
            f"- Components in scope: {provenance_summary['components_in_scope']}",
            f"- PyPI components in scope: {provenance_summary['pypi_components_in_scope']}",
            f"- PyPI components without provenance records: {provenance_summary['pypi_components_without_provenance']}",
            f"- Components with provenance evidence: {provenance_summary['components_with_provenance']}",
            f"- Components with attestations: {provenance_summary['components_with_attestations']}",
            f"- Components with attestation gaps: {provenance_summary['components_with_attestation_gaps']}",
            f"- Components with enrichment errors: {provenance_summary['components_with_enrichment_errors']}",
            f"- Unsupported components: {provenance_summary['unsupported_components']}",
            "",
            "## Attestation gaps",
            "| component | version | statuses |",
            "|-----------|---------|----------|",
        ]
    )
    if attestation_summary["packages_with_attestation_gaps"]:
        for package in attestation_summary["packages_with_attestation_gaps"]:
            lines.append(
                f"| {package['name']} | {package['version'] or ''} | "
                f"{_escape_table_text(', '.join(package['statuses']))} |"
            )
    else:
        lines.append("| _none_ |  |  |")

    lines.extend(
        [
            "",
            "## Policy impact for provenance-related rules",
        ]
    )
    if provenance_policy is not None:
        lines.extend(
            [
                f"- Configured provenance policy: {'yes' if provenance_policy['configured'] else 'no'}",
                (
                    "- Require attestations for new packages: yes"
                    if provenance_policy["requirements"]["require_attestations_for_new_packages"]
                    else "- Require attestations for new packages: no"
                ),
                (
                    "- Require provenance for suspicious sources: yes"
                    if provenance_policy["requirements"]["require_provenance_for_suspicious_sources"]
                    else "- Require provenance for suspicious sources: no"
                ),
                (
                    f"- Allow unattested packages: {', '.join(provenance_policy['requirements']['allow_unattested_packages'])}"
                    if provenance_policy["requirements"]["allow_unattested_packages"]
                    else "- Allow unattested packages: none"
                ),
                (
                    f"- Allowed provenance publishers: {', '.join(provenance_policy['requirements']['allow_provenance_publishers'])}"
                    if provenance_policy["requirements"]["allow_provenance_publishers"]
                    else "- Allowed provenance publishers: none"
                ),
                (
                    f"- Provenance policy decisions: blocking={provenance_policy['counts']['blocking']}, "
                    f"warning={provenance_policy['counts']['warning']}, "
                    f"suppressed={provenance_policy['counts']['suppressed']}"
                ),
            ]
        )
    lines.extend(
        [
            "| rule id | component | level | message |",
            "|---------|-----------|-------|---------|",
        ]
    )
    provenance_violations = [*provenance_impacts["blocking"], *provenance_impacts["warning"]]
    if provenance_violations:
        for violation in provenance_violations:
            lines.append(
                f"| {violation.rule_id} | {violation.component_name or ''} | "
                f"{violation.level.value if violation.level else ''} | {_escape_table_text(violation.message)} |"
            )
    else:
        lines.append("| _none_ |  |  |  |")

    lines.extend(["", "## Trust signal notes"])
    if trust_signal_sections["trust_signal_notes"]:
        lines.extend(f"- {note}" for note in trust_signal_sections["trust_signal_notes"])
    else:
        lines.append("- No additional trust signal notes.")

    lines.extend(
        [
            "",
            "## Scorecard summary",
            f"- Enrichment enabled: {'yes' if scorecard_summary['enabled'] else 'no'}",
            f"- Network access performed: {'yes' if enrichment_metadata['scorecard_network_access_performed'] else 'no'}",
            f"- Candidate components for Scorecard enrichment: {scorecard_summary['candidate_components']}",
            f"- Components with supported repository mappings: {scorecard_summary['supported_components']}",
            f"- Components with mapped repositories: {scorecard_summary['components_with_mapped_repositories']}",
            f"- Components with available Scorecards: {scorecard_summary['components_with_scorecards']}",
            f"- Scorecard unavailable: {scorecard_summary['scorecard_unavailable']}",
            f"- Repository unmapped: {scorecard_summary['repository_unmapped']}",
            f"- Components with enrichment errors: {scorecard_summary['components_with_enrichment_errors']}",
            f"- Observed Scorecard status counts: {_format_status_counts(enrichment_metadata['scorecard_status_counts'])}",
            "",
            "## Scorecard results",
            "| component | version | repository | score | status |",
            "|-----------|---------|------------|-------|--------|",
        ]
    )
    if scorecard_summary["results"]:
        for result in scorecard_summary["results"]:
            score = "" if result["score"] is None else f"{result['score']:.1f}"
            lines.append(
                f"| {result['name']} | {result['version'] or ''} | {result['repository'] or ''} | "
                f"{score} | {_escape_table_text(result['status'] or '')} |"
            )
    else:
        lines.append("| _none_ |  |  |  |  |")

    lines.extend(
        [
            "",
            "## Policy impact for Scorecard-related rules",
            "| rule id | component | level | message |",
            "|---------|-----------|-------|---------|",
        ]
    )
    scorecard_violations = [*scorecard_impacts["blocking"], *scorecard_impacts["warning"]]
    if scorecard_violations:
        for violation in scorecard_violations:
            lines.append(
                f"| {violation.rule_id} | {violation.component_name or ''} | "
                f"{violation.level.value if violation.level else ''} | {_escape_table_text(violation.message)} |"
            )
    else:
        lines.append("| _none_ |  |  |  |")

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


def _format_status_counts(status_counts: dict[str, int]) -> str:
    if not status_counts:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in status_counts.items())
