from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .models import CompareReport, RiskBucket, RiskFinding
from .policy_models import PolicyViolation
from .presentation import effective_policy_evaluation, rule_catalog_to_dict

DEFAULT_SARIF_RESULT_LIMIT = 5000
SARIF_PRIORITIZATION_DESCRIPTION = (
    "error results first, then warning, then note; direct mapped findings before policy-only checks; "
    "stable rule priority and component key tie-breakers."
)

_SARIF_SUPPORTED_RISK_BUCKETS = {
    RiskBucket.SUSPICIOUS_SOURCE,
    RiskBucket.UNKNOWN_LICENSE,
    RiskBucket.MAJOR_UPGRADE,
}
_SARIF_POLICY_ONLY_RULE_IDS = {"allow_sources", "max_added_packages"}
_LEVEL_PRIORITY = {"error": 0, "warning": 1, "note": 2}
_RULE_PRIORITY = {
    "sdr.suspicious_source": 0,
    "sdr.unknown_license": 1,
    "sdr.major_upgrade": 2,
    "sdr.policy_violation.allow_sources": 3,
    "sdr.policy_violation.max_added_packages": 4,
}


@dataclass(slots=True, frozen=True)
class SarifRenderMetadata:
    result_limit: int
    total_candidate_results: int
    emitted_results: int
    omitted_results: int
    truncated: bool
    prioritization: str = SARIF_PRIORITIZATION_DESCRIPTION

    @property
    def warning_message(self) -> str | None:
        if not self.truncated:
            return None
        return (
            "SARIF results were truncated deterministically for GitHub-oriented compatibility: "
            f"emitted {self.emitted_results} of {self.total_candidate_results} candidate results "
            f"(limit {self.result_limit})."
        )


@dataclass(slots=True, frozen=True)
class SarifRenderOutput:
    content: str
    metadata: SarifRenderMetadata


def render_report_sarif(
    report: CompareReport,
    *,
    before_path: Path,
    after_path: Path,
    base_dir: Path | None = None,
    result_limit: int | None = None,
) -> str:
    return render_report_sarif_output(
        report,
        before_path=before_path,
        after_path=after_path,
        base_dir=base_dir,
        result_limit=result_limit,
    ).content


def render_report_sarif_output(
    report: CompareReport,
    *,
    before_path: Path,
    after_path: Path,
    base_dir: Path | None = None,
    result_limit: int | None = None,
) -> SarifRenderOutput:
    if result_limit is None:
        result_limit = DEFAULT_SARIF_RESULT_LIMIT
    if result_limit <= 0:
        raise ValueError("result_limit must be a positive integer.")

    resolved_base_dir = base_dir.resolve() if base_dir is not None else None
    policy_evaluation = effective_policy_evaluation(report.metadata.policy_evaluation)
    blocking_map = _blocking_violation_map(policy_evaluation.blocking_violations)
    emitted_blocking_keys: set[tuple[str, str | None]] = set()

    candidate_results: list[dict[str, Any]] = []

    for finding in report.risks:
        if finding.bucket not in _SARIF_SUPPORTED_RISK_BUCKETS:
            continue

        policy_rule_id = _policy_rule_id_for_bucket(finding.bucket)
        blocking_violation = blocking_map.get((policy_rule_id, finding.component_key))
        result = _risk_finding_to_result(
            finding,
            after_path=after_path,
            base_dir=resolved_base_dir,
            blocking_violation=blocking_violation,
        )
        candidate_results.append(result)
        if blocking_violation is not None:
            emitted_blocking_keys.add((policy_rule_id, finding.component_key))

    for violation in policy_evaluation.blocking_violations:
        lookup_key = (violation.rule_id, violation.component_key)
        if lookup_key in emitted_blocking_keys:
            continue

        sarif_rule_id = sarif_rule_id_for_policy_violation(violation.rule_id)
        if sarif_rule_id is None:
            continue

        result = _policy_violation_to_result(
            violation,
            after_path=after_path,
            base_dir=resolved_base_dir,
        )
        candidate_results.append(result)

    candidate_results.sort(key=_result_sort_key)
    results = candidate_results[:result_limit]
    metadata = SarifRenderMetadata(
        result_limit=result_limit,
        total_candidate_results=len(candidate_results),
        emitted_results=len(results),
        omitted_results=max(0, len(candidate_results) - len(results)),
        truncated=len(candidate_results) > result_limit,
    )
    used_rule_ids = {result["ruleId"] for result in results}

    rules = [_sarif_rule_metadata(rule_id) for rule_id in sorted(used_rule_ids)]
    sarif_document: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sbom-diff-risk",
                        "fullName": "sbom-diff-risk",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "artifacts": [
                    {
                        "location": _artifact_location(before_path, resolved_base_dir),
                    },
                    {
                        "location": _artifact_location(after_path, resolved_base_dir),
                    },
                ],
                "properties": {
                    "sbom_diff_risk": _guardrail_metadata_to_dict(metadata),
                },
                "results": results,
            }
        ],
    }

    if resolved_base_dir is not None:
        sarif_document["runs"][0]["originalUriBaseIds"] = {
            "%SRCROOT%": {
                "uri": _directory_uri(resolved_base_dir),
            }
        }

    return SarifRenderOutput(
        content=json.dumps(sarif_document, indent=2) + "\n",
        metadata=metadata,
    )


def sarif_rule_id_for_risk_bucket(bucket: RiskBucket) -> str | None:
    if bucket not in _SARIF_SUPPORTED_RISK_BUCKETS:
        return None
    return f"sdr.{bucket.value}"


def sarif_rule_id_for_policy_violation(rule_id: str) -> str | None:
    if rule_id not in _SARIF_POLICY_ONLY_RULE_IDS:
        return None
    return f"sdr.policy_violation.{rule_id}"


def _risk_finding_to_result(
    finding: RiskFinding,
    *,
    after_path: Path,
    base_dir: Path | None,
    blocking_violation: PolicyViolation | None,
) -> dict[str, Any]:
    rule_id = sarif_rule_id_for_risk_bucket(finding.bucket)
    assert rule_id is not None

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _risk_result_level(finding.bucket, blocking_violation),
        "message": {
            "text": _risk_result_message(finding, blocking_violation),
        },
        "locations": [_file_location(after_path, base_dir)],
        "partialFingerprints": {
            "ruleId": rule_id,
            "componentKey": finding.component_key,
        },
        "properties": {
            "component_key": finding.component_key,
            "component_name": finding.component.name,
            "finding_bucket": finding.bucket.value,
            "policy_blocking": blocking_violation is not None,
            "result_kind": "risk_finding",
        },
    }
    if blocking_violation is not None:
        result["properties"]["blocking_rule_id"] = blocking_violation.rule_id
    return result


def _policy_violation_to_result(
    violation: PolicyViolation,
    *,
    after_path: Path,
    base_dir: Path | None,
) -> dict[str, Any]:
    rule_id = sarif_rule_id_for_policy_violation(violation.rule_id)
    assert rule_id is not None

    return {
        "ruleId": rule_id,
        "level": "error",
        "message": {
            "text": _policy_result_message(violation),
        },
        "locations": [_file_location(after_path, base_dir)],
        "partialFingerprints": {
            "ruleId": rule_id,
            "componentKey": violation.component_key or "global-policy-check",
        },
        "properties": {
            "policy_rule_id": violation.rule_id,
            "component_key": violation.component_key,
            "component_name": violation.component_name,
            "result_kind": "policy_violation",
        },
    }


def _risk_result_level(bucket: RiskBucket, blocking_violation: PolicyViolation | None) -> str:
    if blocking_violation is not None:
        return "error"
    if bucket is RiskBucket.MAJOR_UPGRADE:
        return "note"
    return "warning"


def _risk_result_message(finding: RiskFinding, blocking_violation: PolicyViolation | None) -> str:
    component_label = _component_label(finding.component.name, finding.component.version)
    if finding.bucket is RiskBucket.UNKNOWN_LICENSE:
        base_message = f"{component_label} has missing or unknown license metadata."
    elif finding.bucket is RiskBucket.SUSPICIOUS_SOURCE:
        base_message = f"{component_label} has suspicious or incomplete source provenance."
    elif finding.bucket is RiskBucket.MAJOR_UPGRADE:
        base_message = finding.rationale
    else:
        base_message = finding.rationale

    if blocking_violation is None:
        return base_message
    return f"Blocked by policy: {base_message}"


def _policy_result_message(violation: PolicyViolation) -> str:
    if violation.rule_id == "max_added_packages":
        return violation.message
    if violation.rule_id == "allow_sources" and violation.component_name:
        component_label = _component_label(violation.component_name, None)
        return f"{component_label}: {violation.message}"
    return violation.message


def _component_label(name: str, version: str | None) -> str:
    if version:
        return f"{name} {version}"
    return name


def _blocking_violation_map(violations: list[PolicyViolation]) -> dict[tuple[str, str | None], PolicyViolation]:
    return {
        (violation.rule_id, violation.component_key): violation
        for violation in violations
    }


def _policy_rule_id_for_bucket(bucket: RiskBucket) -> str:
    return bucket.value


def _file_location(path: Path, base_dir: Path | None) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": _artifact_location(path, base_dir),
            "region": {
                "startLine": 1,
            },
        }
    }


def _artifact_location(path: Path, base_dir: Path | None) -> dict[str, str]:
    resolved = path.resolve()
    if base_dir is not None:
        try:
            relative = resolved.relative_to(base_dir)
        except ValueError:
            pass
        else:
            return {
                "uri": relative.as_posix(),
                "uriBaseId": "%SRCROOT%",
            }
    return {
        "uri": resolved.as_uri(),
    }


def _directory_uri(path: Path) -> str:
    uri = path.resolve().as_uri()
    return uri if uri.endswith("/") else f"{uri}/"


def _guardrail_metadata_to_dict(metadata: SarifRenderMetadata) -> dict[str, Any]:
    return {
        "result_limit": metadata.result_limit,
        "total_candidate_results": metadata.total_candidate_results,
        "emitted_results": metadata.emitted_results,
        "omitted_results": metadata.omitted_results,
        "truncated": metadata.truncated,
        "prioritization": metadata.prioritization,
        "warning": metadata.warning_message,
    }


def _result_sort_key(result: dict[str, Any]) -> tuple[int, int, int, str, str, str]:
    properties = result.get("properties", {})
    if not isinstance(properties, dict):
        properties = {}

    result_kind = properties.get("result_kind")
    if result_kind == "risk_finding":
        kind_rank = 0
    elif properties.get("component_key"):
        kind_rank = 1
    else:
        kind_rank = 2

    return (
        _LEVEL_PRIORITY.get(str(result.get("level", "warning")), 99),
        kind_rank,
        _RULE_PRIORITY.get(str(result.get("ruleId")), 99),
        str(properties.get("component_key") or ""),
        str(properties.get("component_name") or ""),
        str(result.get("ruleId") or ""),
    )


def _sarif_rule_metadata(rule_id: str) -> dict[str, Any]:
    catalog = rule_catalog_to_dict()
    if rule_id.startswith("sdr.policy_violation."):
        policy_rule_id = rule_id.removeprefix("sdr.policy_violation.")
        description = catalog.get(policy_rule_id, {}).get("description", "Blocking policy violation.")
        return {
            "id": rule_id,
            "name": f"policy_violation.{policy_rule_id}",
            "shortDescription": {
                "text": f"Blocking policy violation: {policy_rule_id}",
            },
            "fullDescription": {
                "text": description,
            },
            "defaultConfiguration": {
                "level": "error",
            },
            "properties": {
                "tags": ["supply-chain", "policy"],
            },
        }

    base_rule_id = rule_id.removeprefix("sdr.")
    description = catalog.get(base_rule_id, {}).get("description", base_rule_id)
    return {
        "id": rule_id,
        "name": base_rule_id,
        "shortDescription": {
            "text": description,
        },
        "fullDescription": {
            "text": description,
        },
        "defaultConfiguration": {
            "level": "note" if base_rule_id == "major_upgrade" else "warning",
        },
        "properties": {
            "tags": ["supply-chain", "sbom"],
        },
    }
