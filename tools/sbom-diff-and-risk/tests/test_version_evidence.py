from __future__ import annotations

import json
from pathlib import Path

import pytest
from sbom_diff_risk import cli
from sbom_diff_risk.component_identity import canonicalize_component_identity
from sbom_diff_risk.diffing import diff_components
from sbom_diff_risk.errors import ComponentIdentityError
from sbom_diff_risk.normalize import normalize_input
from sbom_diff_risk.schema_versions import POLICY_SCHEMA_V1, REPORT_SCHEMA_V1


@pytest.mark.parametrize("input_format", ["cyclonedx-json", "spdx-json"])
@pytest.mark.parametrize("mode", ["none", "block", "warn", "ignore"])
@pytest.mark.parametrize(
    ("before_version", "after_version", "bucket"),
    [("1.2.3", "2.0.0", "major_upgrade"), ("release-a", "release-b", "version_change_unclassified")],
)
def test_purl_version_evidence_reaches_policy_and_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    input_format: str,
    mode: str,
    before_version: str,
    after_version: str,
    bucket: str,
) -> None:
    def reject_enrichment(*args, **kwargs):
        raise AssertionError("Version evidence must be evaluated offline.")

    monkeypatch.setattr(cli, "PyPIProvenanceEnricher", reject_enrichment)
    monkeypatch.setattr(cli, "ScorecardEnricher", reject_enrichment)
    inputs = [tmp_path / "before.json", tmp_path / "after.json"]
    for path, version in zip(inputs, (before_version, after_version)):
        _write_sbom(path, input_format, version)
    _, before, _ = normalize_input(inputs[0])
    _, after, _ = normalize_input(inputs[1])
    assert before[0].version is after[0].version is None
    assert canonicalize_component_identity(before[0]).version == before_version
    assert canonicalize_component_identity(after[0]).version == after_version
    assert diff_components(before, after)[2][0].classification == "version_changed"

    outputs = {name: tmp_path / name for name in ("report.json", "report.md", "summary.json", "policy.json")}
    args = [
        "compare",
        "--before",
        str(inputs[0]),
        "--after",
        str(inputs[1]),
        "--out-json",
        str(outputs["report.json"]),
        "--out-md",
        str(outputs["report.md"]),
        "--summary-json",
        str(outputs["summary.json"]),
        "--policy-json",
        str(outputs["policy.json"]),
    ]
    if mode in {"block", "warn"}:
        args.extend(["--fail-on" if mode == "block" else "--warn-on", bucket])
    elif mode == "ignore":
        policy = tmp_path / "policy.yml"
        policy.write_text(f"version: 1\nblock_on: [{bucket}]\nignore_rules: [{bucket}]\n", encoding="utf-8")
        args.extend(["--policy", str(policy)])

    exit_code = cli.main(args)
    report = json.loads(outputs["report.json"].read_text(encoding="utf-8"))
    markdown = outputs["report.md"].read_text(encoding="utf-8")
    sidecar = json.loads(outputs["policy.json"].read_text(encoding="utf-8"))

    assert exit_code == (1 if mode == "block" else 0)
    assert report["report_schema"] == REPORT_SCHEMA_V1
    assert report["summary"]["risk_counts"][bucket] == 1
    assert report["summary"]["risk_counts"]["not_evaluated"] == 1
    assert report["summary"]["changed"] == 1
    change = report["components"]["changed"][0]
    assert change["classification"] == "version_changed"
    evidence_key = "component" if input_format == "cyclonedx-json" else "package"
    container_key = "components" if input_format == "cyclonedx-json" else "packages"
    for side, path in zip(("before", "after"), inputs):
        assert change[side]["version"] is None
        assert change[side]["evidence"][evidence_key] == json.loads(path.read_text(encoding="utf-8"))[container_key][0]
    finding = next(item for item in report["risks"] if item["bucket"] == bucket)
    assert finding["component"]["version"] is None
    assert finding["component"]["purl"] == f"pkg:pypi/sample-lib@{after_version}"
    assert f"- {bucket}: 1" in markdown
    assert f"| {bucket} | sample-lib |  | {finding['rationale']} |" in markdown
    assert "| sample-lib |  |  | version_changed |" in markdown
    assert json.loads(outputs["summary.json"].read_text(encoding="utf-8")) == report["summary"]
    assert sidecar["policy_schema"] == POLICY_SCHEMA_V1
    assert sidecar["policy_evaluation"] == report["policy_evaluation"]
    for section in ("blocking_findings", "warning_findings", "suppressed_findings"):
        assert sidecar[section] == report[section]
    if mode == "none":
        assert report["evidence_confidence"] == "sbom_present"
        assert report["policy_evaluation"]["applied"] is False
    else:
        assert report["evidence_confidence"] == "policy_matched"
        section = {"block": "blocking_findings", "warn": "warning_findings", "ignore": "suppressed_findings"}[mode]
        assert [item["rule_id"] for item in report[section]] == [bucket]
        assert report[section][0]["observed_value"] == bucket
        assert report["summary"]["policy"] == {
            "status": {"block": "fail", "warn": "warn", "ignore": "pass"}[mode],
            "blocking": int(mode == "block"),
            "warning": int(mode == "warn"),
            "suppressed": int(mode == "ignore"),
        }
        assert f"| {bucket} | sample-lib | {'warn' if mode == 'warn' else 'block'} |" in markdown
    assert report["summary"]["evidence_confidence"] == report["evidence_confidence"]
    assert report["metadata"]["evidence_confidence"] == report["evidence_confidence"]
    assert f"- Evidence confidence: {report['evidence_confidence']}" in markdown
    assert report["metadata"]["enrichment"]["mode"] == "offline_default"
    assert report["metadata"]["enrichment"]["network_access_performed"] is False
    assert "- Network access performed: no" in markdown
    first_outputs = {name: path.read_bytes() for name, path in outputs.items()}
    assert cli.main(args) == exit_code
    assert first_outputs == {name: path.read_bytes() for name, path in outputs.items()}


@pytest.mark.parametrize("input_format", ["cyclonedx-json", "spdx-json"])
def test_conflicting_version_evidence_fails_before_reports(
    tmp_path: Path,
    input_format: str,
) -> None:
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    _write_sbom(before, input_format, "1.2.3", explicit_version="9.0.0")
    _write_sbom(after, input_format, "2.0.0")
    _, before_components, _ = normalize_input(before)
    _, after_components, _ = normalize_input(after)
    with pytest.raises(ComponentIdentityError, match="conflicting_metadata"):
        diff_components(before_components, after_components)
    report, markdown = tmp_path / "report.json", tmp_path / "report.md"

    assert (
        cli.main(
            [
                "compare",
                "--before",
                str(before),
                "--after",
                str(after),
                "--out-json",
                str(report),
                "--out-md",
                str(markdown),
            ]
        )
        == 2
    )
    assert not report.exists()
    assert not markdown.exists()


def _write_sbom(path: Path, input_format: str, version: str, *, explicit_version: str | None = None) -> None:
    purl = f"pkg:pypi/sample-lib@{version}"
    if input_format == "cyclonedx-json":
        component = {"name": "sample-lib", "purl": purl, "licenses": [{"license": {"id": "MIT"}}]}
        if explicit_version is not None:
            component["version"] = explicit_version
        payload = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [component]}
    else:
        component = {
            "name": "sample-lib",
            "SPDXID": "SPDXRef-sample-lib",
            "licenseConcluded": "MIT",
            "externalRefs": [{"referenceType": "purl", "referenceLocator": purl}],
        }
        if explicit_version is not None:
            component["versionInfo"] = explicit_version
        payload = {"spdxVersion": "SPDX-2.3", "packages": [component]}
    path.write_text(json.dumps(payload), encoding="utf-8")
