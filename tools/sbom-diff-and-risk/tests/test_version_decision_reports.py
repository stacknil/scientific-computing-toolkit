"""Public CLI controls for syntax admission, policy and restricted SARIF projection."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import socket

import pytest
from sbom_diff_risk import cli


@pytest.mark.parametrize("input_format", ["cyclonedx", "spdx"])
@pytest.mark.parametrize(
    "mode",
    ["none", "unmatched", "block-major", "warn-major", "block-unclassified", "warn-unclassified", "mixed", "ignored"],
)
def test_version_decisions_across_cli_projections(tmp_path, monkeypatch, input_format, mode):
    def reject_network(*args, **kwargs):
        pytest.fail("Default comparison attempted enrichment or a network connection")

    monkeypatch.setattr(socket.socket, "connect", reject_network)
    monkeypatch.setattr(socket, "create_connection", reject_network)
    monkeypatch.setattr(cli, "PyPIProvenanceEnricher", reject_network)
    monkeypatch.setattr(cli, "ScorecardEnricher", reject_network)
    monkeypatch.chdir(tmp_path)
    before_rows, after_rows = rows("before"), rows("after")
    for side, items in (("before", before_rows), ("after", after_rows)):
        write_sbom(Path(side + ".json"), input_format, items)
    major, unclassified = "major_upgrade", "version_change_unclassified"
    policy = {"version": 1, "block_on": [], "warn_on": [], "ignore_rules": []}
    if mode in {"block-major", "mixed", "ignored"}:
        policy["block_on"] = [major]
    if mode == "block-unclassified":
        policy["block_on"] = [unclassified]
    if mode == "warn-major":
        policy["warn_on"] = [major]
    if mode in {"warn-unclassified", "mixed"}:
        policy["warn_on"] = [unclassified]
    if mode == "ignored":
        policy["block_on"] = policy["ignore_rules"] = [major, unclassified]
    if mode == "unmatched":
        policy["block_on"] = ["suspicious_source"]
    Path("policy.yml").write_text(json.dumps(policy), encoding="utf-8")
    names = ("report.json", "summary.json", "policy.json", "report.md", "report.sarif")
    args = ["compare", "--before", "before.json", "--after", "after.json"]
    for flag, name in zip(("--out-json", "--summary-json", "--policy-json", "--out-md", "--out-sarif"), names):
        args.extend((flag, name))
    if mode != "none":
        args.extend(("--policy", "policy.yml"))
    blocking = 1 if mode in {"block-major", "mixed"} else 2 if mode == "block-unclassified" else 0
    warnings = 1 if mode == "warn-major" else 2 if mode in {"warn-unclassified", "mixed"} else 0
    suppressed = 3 if mode == "ignored" else 0
    assert cli.main(args) == int(blocking > 0)
    full = json.loads(Path("report.json").read_text(encoding="utf-8"))
    summary = json.loads(Path("summary.json").read_text(encoding="utf-8"))
    sidecar = json.loads(Path("policy.json").read_text(encoding="utf-8"))
    markdown = Path("report.md").read_text(encoding="utf-8")
    run = json.loads(Path("report.sarif").read_text(encoding="utf-8"))["runs"][0]
    assert full["report_schema"] == "sbom-diff-risk.report.v1"
    assert sidecar["policy_schema"] == "sbom-diff-risk.policy.v1"
    assert summary == full["summary"]
    assert (summary["added"], summary["removed"], summary["changed"]) == (1, 0, 4)
    counts = Counter(f["bucket"] for f in full["risks"])
    assert {k: v for k, v in summary["risk_counts"].items() if v} == dict(counts)
    assert counts == {major: 1, unclassified: 2, "new_package": 1, "unknown_license": 1, "not_evaluated": 5}
    expected_risks = [
        (major, "alpha"),
        (unclassified, "bravo"),
        (unclassified, "echo"),
        ("new_package", "new-lib"),
        ("unknown_license", "new-lib"),
    ]
    expected_risks += [("not_evaluated", name) for name in ("alpha", "bravo", "delta", "echo", "new-lib")]
    assert [(f["bucket"], f["component_key"]) for f in full["risks"]] == sorted(
        (bucket, "purl:pkg:pypi/" + name) for bucket, name in expected_risks
    )
    for section, count in (
        ("blocking_findings", blocking),
        ("warning_findings", warnings),
        ("suppressed_findings", suppressed),
    ):
        assert sidecar[section] == full[section]
        assert len(full[section]) == count
        expected_targets = []
        if section == "blocking_findings":
            expected_targets = [(major, "alpha")] if mode in {"block-major", "mixed"} else []
            if mode == "block-unclassified":
                expected_targets = [(unclassified, "bravo"), (unclassified, "echo")]
        elif section == "warning_findings":
            expected_targets = [(major, "alpha")] if mode == "warn-major" else []
            if mode in {"warn-unclassified", "mixed"}:
                expected_targets = [(unclassified, "bravo"), (unclassified, "echo")]
        elif mode == "ignored":
            expected_targets = [(major, "alpha"), (unclassified, "bravo"), (unclassified, "echo")]
        assert [(f["rule_id"], f["component_name"]) for f in full[section]] == expected_targets
        for f in full[section]:
            rule, key = f["rule_id"], f["component_key"]
            assert f["matched_rule_id"] == f["policy_rule"] == rule
            assert f["observed_value"] == f["finding_bucket"] == rule
            assert f["exact_evidence"] == {
                "component_key": key,
                "finding_bucket": rule,
                "matched_threshold": None,
                "observed_value": rule,
            }
            assert f["decision_reason"] == "risk_finding_matched_policy_rule"
            assert f["confidence_level"] == "policy_matched"
            assert f["severity_source"] == ("warn_on" if section == "warning_findings" else "block_on")
            assert f["level"] == ("warn" if section == "warning_findings" else "block")
            if section == "suppressed_findings":
                assert f["suppression_reason"] == "ignored_by_policy"
    assert sidecar["policy_evaluation"] == full["policy_evaluation"] == full["metadata"]["policy_evaluation"]
    assert sidecar["rule_catalog"] == full["rule_catalog"]
    if mode != "none":
        assert (
            sidecar["summary"]["policy"]
            == summary["policy"]
            == {
                "blocking": blocking,
                "warning": warnings,
                "suppressed": suppressed,
                "status": "fail" if blocking else "warn" if warnings else "pass",
            }
        )
    confidence = "policy_matched" if blocking + warnings + suppressed else "sbom_present"
    assert full["evidence_confidence"] == summary["evidence_confidence"] == confidence
    assert full["metadata"]["evidence_confidence"] == confidence
    assert full["metadata"]["enrichment"]["network_access_performed"] is False
    for bucket, count in counts.items():
        assert f"- {bucket}: {count}" in markdown
    assert f"- Exit code: {int(blocking > 0)}" in markdown
    assert f"- Evidence confidence: {confidence}" in markdown
    assert "| alpha |  |  | version_changed |" in markdown
    for change in full["components"]["changed"]:
        assert change["classification"] == "version_changed"
        for side in ("before", "after"):
            original_rows = before_rows if side == "before" else after_rows
            row = next(r for r in original_rows if r["name"] == change[side]["name"])
            assert change[side]["version"] == row.get("version")
            raw_key = "component" if input_format == "cyclonedx" else "package"
            document = json.loads(Path(side + ".json").read_text(encoding="utf-8"))
            items = document["components" if input_format == "cyclonedx" else "packages"]
            assert change[side]["evidence"][raw_key] == next(r for r in items if r["name"] == row["name"])
    results = run["results"]
    level = "error" if mode in {"block-major", "mixed"} else "warning" if mode == "warn-major" else "note"
    expected_order = [("sdr.major_upgrade", level), ("sdr.unknown_license", "warning")]
    if level != "error":
        expected_order.reverse()
    assert [(r["ruleId"], r["level"]) for r in results] == expected_order
    assert [r["properties"]["component_name"] for r in results] == (
        ["alpha", "new-lib"] if level == "error" else ["new-lib", "alpha"]
    )
    major_result = next(r for r in results if r["ruleId"] == "sdr.major_upgrade")
    assert major_result["properties"]["policy_matched"] is (mode in {"block-major", "warn-major", "mixed"})
    assert major_result["properties"]["policy_blocking"] is (level == "error")
    assert major_result["partialFingerprints"]["componentKey"] == "purl:pkg:pypi/alpha"
    assert len({(r["ruleId"], r["properties"]["component_key"]) for r in results}) == len(results)
    assert run["properties"]["sbom_diff_risk"]["truncated"] is False
    # Suppression removes policy escalation, not the independent major heuristic note.
    # Unclassified/not_evaluated are deliberately absent from the SARIF subset.
    first = {name: Path(name).read_bytes() for name in names}
    assert cli.main(args) == int(blocking > 0)
    assert first == {name: Path(name).read_bytes() for name in names}
    write_sbom(Path("before.json"), input_format, list(reversed(before_rows)))
    write_sbom(Path("after.json"), input_format, list(reversed(after_rows)))
    assert cli.main(args) == int(blocking > 0)
    assert first == {name: Path(name).read_bytes() for name in names}


def rows(side):
    after = side == "after"
    items = [
        {"name": "alpha", "purl": "pkg:pypi/alpha@" + ("2.0.0-rc.1+build.01" if after else "1.2.3")},
        {"name": "bravo", "purl": "pkg:pypi/bravo", "version": "2.0.0-01" if after else "1.2.3"},
        {"name": "delta", "purl": "pkg:pypi/delta", **({"version": "2.0.0"} if after else {})},
        {
            "name": "echo",
            "purl": "pkg:pypi/echo@" + ("2.0.0" if after else "3.0.0"),
            "version": "2.0.0" if after else "3.0.0",
        },
        {"name": "quiet", "purl": "pkg:pypi/quiet@1.2.3", "version": "1.2.3"},
    ]
    if after:
        items.append({"name": "new-lib", "purl": "pkg:pypi/new-lib@1.0.0"})
    return items


def write_sbom(path, input_format, items):
    if input_format == "cyclonedx":
        components = [
            {**r, **({"licenses": [{"license": {"id": "MIT"}}]} if r["name"] != "new-lib" else {})} for r in items
        ]
        payload = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}
    else:
        packages = [
            {
                "name": r["name"],
                "SPDXID": "SPDXRef-" + r["name"],
                "externalRefs": [{"referenceType": "purl", "referenceLocator": r["purl"]}],
                **({"versionInfo": r["version"]} if "version" in r else {}),
                **({"licenseConcluded": "MIT"} if r["name"] != "new-lib" else {}),
            }
            for r in items
        ]
        payload = {"spdxVersion": "SPDX-2.3", "packages": packages}
    path.write_text(json.dumps(payload), encoding="utf-8")
