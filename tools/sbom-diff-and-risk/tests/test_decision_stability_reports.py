"""Consumer consistency checks; cross-output agreement is not an independent policy oracle."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from sbom_diff_risk import cli

from test_decision_stability import observe_case, render_bundle
from test_decision_stability_oracle import (
    CASES,
    KEY,
    expected_row,
    require,
    validate_case,
)


@pytest.mark.parametrize(
    "actual,expected", [(True, 1), (False, 0), ({"value": [True]}, {"value": [1]})]
)
def test_oracle_distinguishes_boolean_from_numeric_evidence(actual, expected):
    from test_decision_stability_oracle import OracleMismatch

    with pytest.raises(OracleMismatch):
        require("typed-evidence", actual, expected)


@pytest.mark.parametrize(
    "field",
    ["decision_reason", "observed_value", "matched_threshold", "markdown_message"],
)
def test_serialized_microcase_rejects_coherent_corruption(field, tmp_path, monkeypatch):
    from test_decision_stability_oracle import CASE_BY_ID, OracleMismatch

    original_render = render_bundle

    def corrupted_render(report):
        bundle = original_render(report)
        row = bundle["report"]["blocking_findings"][0]
        if field == "markdown_message":
            assert row["message"] in bundle["markdown"]
            bundle["markdown"] = bundle["markdown"].replace(
                row["message"], "Incorrect decision explanation"
            )
        else:
            # Corrupt every mirrored occurrence, so agreement alone cannot detect it.
            def corrupt(value):
                if isinstance(value, dict):
                    if field in value:
                        value[field] = "incorrect evidence"
                    for child in value.values():
                        corrupt(child)
                elif isinstance(value, list):
                    for child in value:
                        corrupt(child)

            for key in ("report", "policy"):
                corrupt(bundle[key])
        return bundle

    monkeypatch.setattr(__import__(__name__), "render_bundle", corrupted_render)
    with pytest.raises(OracleMismatch):
        test_microcase_reports_agree_with_independent_expectation(
            CASE_BY_ID["M08"], tmp_path
        )


SARIF_EXPECTED = {
    "M01": [],
    "M02": [],
    "M03": [("sdr.new_package", "error", KEY)],
    "M04": [("sdr.new_package", "warning", KEY)],
    "M06": [],
    "M07": [],
    "M08": [("sdr.policy_violation.max_added_packages", "error", None)],
    "M11": [("sdr.policy_violation.max_added_packages", "warning", None)],
    "M14": [("sdr.policy_violation.allow_sources", "error", KEY)],
    "M17": [],
    "M18": [],
    "M19": [],
    "M20": [("sdr.policy_violation.missing_attestation", "error", KEY)],
    "M22": [("sdr.policy_violation.unverified_provenance", "error", KEY)],
    "M27": [("sdr.policy_violation.provenance_required", "error", KEY)],
    "M28": [("sdr.policy_violation.provenance_required", "error", KEY)],
    "M31": [("sdr.policy_violation.provenance_required", "warning", KEY)],
    "M37": [("sdr.policy_violation.provenance_required", "error", KEY)],
    "M41": [("sdr.policy_violation.provenance_required", "error", KEY)],
    "M42": [],
    "M43": [("sdr.policy_violation.scorecard_below_threshold", "error", KEY)],
    "M44": [],
    "M47": [("sdr.policy_violation.scorecard_below_threshold", "warning", KEY)],
    "M48": [],
    "M49": [],
    "M58": [],
}


def validate_bundle(
    bundle,
    exit_code,
    *,
    expected_confidence=None,
    sarif_expected=None,
    expected_rows=None,
):
    full, summary, policy, markdown, sarif = (
        bundle[key] for key in ("report", "summary", "policy", "markdown", "sarif")
    )
    require("report-schema", full["report_schema"], "sbom-diff-risk.report.v1")
    require("policy-schema", policy["policy_schema"], "sbom-diff-risk.policy.v1")
    require("summary-sidecar", summary, full["summary"])
    evaluation = full["policy_evaluation"]
    for key in (
        "policy_evaluation",
        "blocking_findings",
        "warning_findings",
        "suppressed_findings",
        "rule_catalog",
    ):
        require("policy-sidecar", policy[key], full[key])
    require("metadata-evaluation", full["metadata"]["policy_evaluation"], evaluation)
    require("exit-blocking", exit_code, 1 if full["blocking_findings"] else 0)
    require("exit-report", evaluation["exit_code"], exit_code)
    counts = {}
    serialized_rows = []
    for group, section, title in (
        ("blocking", "blocking_findings", "Blocking violations"),
        ("warning", "warning_findings", "Warnings"),
        ("suppressed", "suppressed_findings", "Suppressions"),
    ):
        rows = full[section]
        counts[group] = len(rows)
        require("evaluation-rows", evaluation[f"{group}_violations"], rows)
        for row in rows:
            serialized_rows.append(
                {
                    "group": group,
                    "rule": row["rule_id"],
                    "level": row["level"],
                    "reason": row["decision_reason"],
                    "source": row["severity_source"],
                    "observed": row["observed_value"],
                    "threshold": row["matched_threshold"],
                    "key": row["component_key"],
                    "name": row["component_name"],
                    "bucket": row["finding_bucket"],
                    "confidence": row["confidence_level"],
                    "suppression": row["suppression_reason"],
                    "policy_rule": row["policy_rule"],
                }
            )
            require("matched-rule", row["matched_rule_id"], row["rule_id"])
            require(
                "exact-evidence",
                row["exact_evidence"],
                {
                    "component_key": row["component_key"],
                    "finding_bucket": row["finding_bucket"],
                    "matched_threshold": row["matched_threshold"],
                    "observed_value": row["observed_value"],
                },
            )
            require("decision-reason-present", bool(row["decision_reason"]), True)
            section_text = markdown.split(f"## {title}\n", 1)[1].split("\n## ", 1)[0]
            level = row["level"] or "n/a"
            prefix = f"| {row['rule_id']} | {row['component_name'] or ''} | {level} |"
            require("markdown-row", prefix in section_text, True)
            message = row["message"].replace("|", "\\|").replace("\n", " ")
            tail = (
                f" {row['suppression_reason'] or ''} |" if group == "suppressed" else ""
            )
            require(
                "markdown-message", f"{prefix}{tail} {message} |" in section_text, True
            )
            if group == "suppressed":
                require(
                    "suppression-reason", row["suppression_reason"], "ignored_by_policy"
                )
                require(
                    "markdown-suppression", "ignored_by_policy" in section_text, True
                )
    if expected_rows is not None:
        sort_key = lambda row: (
            row["group"],
            row["rule"],
            row["key"] or "",
            row["name"] or "",
        )
        require(
            "serialized-independent-evidence",
            sorted(serialized_rows, key=sort_key),
            sorted((expected_row(row) for row in expected_rows), key=sort_key),
        )
    require(
        "totals",
        evaluation["totals"],
        {**counts, "ignored_checks": counts["suppressed"]},
    )
    if evaluation["applied"]:
        expected_summary = {
            "status": "fail"
            if counts["blocking"]
            else "warn"
            if counts["warning"]
            else "pass",
            **counts,
        }
        require("policy-summary", summary["policy"], expected_summary)
        require("sidecar-policy-summary", policy["summary"]["policy"], expected_summary)
    else:
        require("unapplied-summary", "policy" in summary, False)
        require("unapplied-sidecar", "summary" in policy, False)
    confidence = full["evidence_confidence"]
    require("confidence-summary", summary["evidence_confidence"], confidence)
    require("confidence-metadata", full["metadata"]["evidence_confidence"], confidence)
    if expected_confidence is not None:
        require("confidence-authority", confidence, expected_confidence)
    for text in (
        f"- Exit code: {exit_code}",
        f"- Blocking findings: {counts['blocking']}",
        f"- Warnings: {counts['warning']}",
        f"- Suppressed findings: {counts['suppressed']}",
        f"- Evidence confidence: {confidence}",
    ):
        require("markdown-summary", text in markdown, True)
    require(
        "heuristic-authority",
        "This tool uses heuristic risk classification." in full["notes"],
        True,
    )
    require("no-security-verdict", full.get("package_safety_verdict"), None)
    require("sarif-schema", sarif["version"], "2.1.0")
    results = sarif["runs"][0]["results"]
    if sarif_expected is not None:
        require(
            "sarif-subset",
            sorted(
                (row["ruleId"], row["level"], row["properties"].get("component_key"))
                for row in results
            ),
            sorted(sarif_expected),
        )
    for row in results:
        props = row["properties"]
        if "policy_rule_id" in props:
            candidates = [
                item
                for item in (*full["blocking_findings"], *full["warning_findings"])
                if item["rule_id"] == props["policy_rule_id"]
                and item["component_key"] == props["component_key"]
            ]
            require("sarif-policy-identity", bool(candidates), True)
            require(
                "sarif-policy-level",
                row["level"],
                "error" if candidates[0]["level"] == "block" else "warning",
            )


def consumer_decision(bundle, exit_code):
    """Demonstration consumer classification, not an added native exit status."""
    if exit_code == 2 or not bundle["policy"]["policy_evaluation"]["applied"]:
        return "needs-review"
    validate_bundle(bundle, exit_code)
    return bundle["summary"]["policy"]["status"]


@pytest.mark.parametrize(
    "case", [case for case in CASES if not case.invalid], ids=lambda case: case.id
)
def test_microcase_reports_agree_with_independent_expectation(case, tmp_path):
    actual, report = observe_case(case, tmp_path)
    validate_case(case, actual)
    confidence = (
        "scorecard_recorded"
        if case.score is not None and case.scope != "unchanged"
        else "provenance_recorded"
        if case.provenance != "none" and case.scope != "unchanged"
        else "policy_matched"
        if case.rows
        else "sbom_present"
    )
    bundle = render_bundle(report)
    validate_bundle(
        bundle,
        actual["exit_code"],
        expected_confidence=confidence,
        sarif_expected=SARIF_EXPECTED.get(case.id),
        expected_rows=case.rows,
    )
    require(
        "consumer-disclosure",
        consumer_decision(bundle, actual["exit_code"]),
        "needs-review"
        if case.expected_decision == "NOT_APPLIED"
        else case.expected_decision.lower(),
    )


def cdx_component(name="qualification-alpha", version="1.0.0", *, purl=None):
    return {
        "name": name,
        "version": version,
        "purl": purl or f"pkg:pypi/{name}@{version}",
        "licenses": [{"license": {"id": "MIT"}}],
        "externalReferences": [
            {"type": "vcs", "url": "https://github.com/example/qualification"}
        ],
    }


def run_cli(
    directory,
    before,
    after,
    policy=None,
    flags=(),
    *,
    whitespace=0,
    expected_provider_lookup=False,
):
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in (("before.json", before), ("after.json", after)):
        (directory / name).write_text(
            json.dumps(value, indent=whitespace or None, sort_keys=bool(whitespace)),
            encoding="utf-8",
        )
    argv = [
        "compare",
        "--before",
        str(directory / "before.json"),
        "--after",
        str(directory / "after.json"),
    ]
    if policy is not None:
        (directory / "policy.yml").write_text(yaml.safe_dump(policy), encoding="utf-8")
        argv.extend(["--policy", str(directory / "policy.yml")])
    argv.extend(flags)
    for flag, name in (
        ("--out-json", "report.json"),
        ("--summary-json", "summary.json"),
        ("--policy-json", "policy.json"),
        ("--out-md", "report.md"),
        ("--out-sarif", "report.sarif"),
    ):
        argv.extend([flag, str(directory / name)])
    code = cli.main(argv)
    if code == 2:
        require(
            "invalid-cli-no-report",
            any(
                (directory / name).exists()
                for name in (
                    "report.json",
                    "summary.json",
                    "policy.json",
                    "report.md",
                    "report.sarif",
                )
            ),
            False,
        )
        return code, None
    bundle = {
        key: json.loads((directory / name).read_text(encoding="utf-8"))
        for key, name in (
            ("report", "report.json"),
            ("summary", "summary.json"),
            ("policy", "policy.json"),
            ("sarif", "report.sarif"),
        )
    }
    bundle["markdown"] = (directory / "report.md").read_text(encoding="utf-8")
    validate_bundle(bundle, code)
    require(
        "provider-lookup-record",
        bundle["report"]["enrichment_metadata"]["network_access_performed"],
        expected_provider_lookup,
    )
    return code, bundle


CLI_CASES = (
    ("no-policy", None, (), "needs-review", 0),
    ("default", {"version": 1}, (), "pass", 0),
    ("warn", {"version": 1, "warn_on": ["new_package"]}, (), "warn", 0),
    ("block", {"version": 1, "block_on": ["new_package"]}, (), "fail", 1),
    (
        "ignore",
        {"version": 1, "block_on": ["new_package"], "ignore_rules": ["new_package"]},
        (),
        "pass",
        0,
    ),
    (
        "required",
        {"version": 2, "require_attestations_for_new_packages": True},
        (),
        "fail",
        1,
    ),
    (
        "unavailable",
        {"version": 2, "block_on": ["provenance_unavailable"]},
        (),
        "fail",
        1,
    ),
    ("sources", {"version": 1, "allow_sources": ["pypi.org"]}, (), "fail", 1),
    (
        "merged",
        {"version": 1, "warn_on": ["new_package"]},
        ("--fail-on", "new_package"),
        "fail",
        1,
    ),
    (
        "promoted-provenance",
        {"version": 1},
        ("--fail-on", "provenance_unavailable"),
        "fail",
        1,
    ),
    (
        "promoted-scorecard",
        {"version": 1},
        ("--warn-on", "scorecard_below_threshold"),
        "pass",
        0,
    ),
)


@pytest.mark.parametrize(
    "label,policy,flags,decision,exit_code",
    CLI_CASES,
    ids=[row[0] for row in CLI_CASES],
)
def test_actual_cli_and_consumer_decisions(
    tmp_path, label, policy, flags, decision, exit_code
):
    code, bundle = run_cli(
        tmp_path,
        {"bomFormat": "CycloneDX", "components": []},
        {"bomFormat": "CycloneDX", "components": [cdx_component()]},
        policy,
        flags,
    )
    require("cli-status", code, exit_code)
    require("consumer-status", consumer_decision(bundle, code), decision)
    if label == "promoted-provenance":
        require(
            "cli-promotion-v2",
            bundle["policy"]["policy_evaluation"]["effective_policy"]["version"],
            2,
        )
    if label == "promoted-scorecard":
        require(
            "cli-promotion-v3",
            bundle["policy"]["policy_evaluation"]["effective_policy"]["version"],
            3,
        )


def test_missing_consumer_policy_is_review_not_affirmative_safety(tmp_path):
    _, bundle = run_cli(
        tmp_path,
        {"bomFormat": "CycloneDX", "components": []},
        {"bomFormat": "CycloneDX", "components": [cdx_component()]},
    )
    require("consumer-no-policy", consumer_decision(bundle, 0), "needs-review")
    require(
        "consumer-runtime-error", consumer_decision(deepcopy(bundle), 2), "needs-review"
    )
    for name in ("pass", "warn", "fail", "needs-review"):
        example = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "examples"
                / "policy-decisions"
                / f"{name}.json"
            ).read_text(encoding="utf-8")
        )
        require(
            "consumer-example-authority",
            "not a dependency safety verdict"
            in example["reviewer_interpretation"]["non_claims"],
            True,
        )
