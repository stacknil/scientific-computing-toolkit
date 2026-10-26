"""Actual CLI and provider parsers with synthetic byte streams, never a live service."""

import io
import json
from copy import deepcopy
from dataclasses import dataclass
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from sbom_diff_risk import cli
from sbom_diff_risk.enrichment import PyPIProvenanceEnricher
from sbom_diff_risk.pypi_integrity_client import PyPIIntegrityClient
from sbom_diff_risk.scorecard_client import ScorecardClient
from sbom_diff_risk.scorecard_enrichment import ScorecardEnricher

from test_decision_stability_oracle import require
from test_decision_stability_reports import cdx_component, consumer_decision, run_cli


@dataclass(frozen=True)
class ProviderCase:
    id: str
    policy: dict
    pypi: str | None = None
    score: object = None
    mapping: str = "vcs"
    name: str = "qualification-alpha"
    decision: str = "PASS"
    rules: tuple[str, ...] = ()
    pypi_status: str | None = None
    score_status: str | None = None
    calls: tuple[int, int] = (0, 0)


PROVIDERS = (
    ProviderCase(
        "E01",
        {"version": 2, "block_on": ["missing_attestation"]},
        pypi="missing",
        decision="FAIL",
        rules=("missing_attestation",),
        pypi_status="attestation_unavailable",
        calls=(2, 0),
    ),
    ProviderCase(
        "E02",
        {"version": 2, "block_on": ["provenance_unavailable"]},
        pypi="error",
        decision="FAIL",
        rules=("provenance_unavailable",),
        pypi_status="enrichment_error",
        calls=(1, 0),
    ),
    ProviderCase(
        "E03",
        {"version": 2, "require_attestations_for_new_packages": True},
        pypi="missing",
        mapping="npm",
        pypi_status="unsupported_for_package",
    ),
    ProviderCase(
        "E04",
        {"version": 2, "block_on": ["provenance_unavailable"]},
        pypi="missing",
        mapping="versionless",
        decision="FAIL",
        rules=("provenance_unavailable",),
        pypi_status="unsupported_for_package",
    ),
    ProviderCase(
        "E05",
        {"version": 2, "block_on": ["unverified_provenance"]},
        pypi="unverified",
        decision="FAIL",
        rules=("unverified_provenance",),
        pypi_status="attestation_available",
        calls=(2, 0),
    ),
    ProviderCase(
        "E06",
        {
            "version": 2,
            "block_on": ["unverified_provenance"],
            "allow_provenance_publishers": ["github actions"],
        },
        pypi="github",
        pypi_status="attestation_available",
        calls=(2, 0),
    ),
    ProviderCase(
        "E07",
        {
            "version": 2,
            "block_on": ["unverified_provenance"],
            "allow_provenance_publishers": ["manual upload"],
        },
        pypi="github",
        decision="FAIL",
        rules=("unverified_provenance",),
        pypi_status="attestation_available",
        calls=(2, 0),
    ),
    ProviderCase(
        "E08",
        {
            "version": 2,
            "block_on": ["missing_attestation"],
            "allow_unattested_packages": ["Qualification_Alpha"],
        },
        pypi="missing",
        pypi_status="attestation_unavailable",
        calls=(2, 0),
    ),
    ProviderCase(
        "E09",
        {
            "version": 2,
            "block_on": ["provenance_unavailable"],
            "require_attestations_for_new_packages": True,
            "allow_unattested_packages": ["Qualification_Alpha"],
        },
        pypi="error",
        decision="FAIL",
        rules=("provenance_required", "provenance_unavailable"),
        pypi_status="enrichment_error",
        calls=(1, 0),
    ),
    ProviderCase(
        "E10",
        {
            "version": 2,
            "block_on": ["unverified_provenance"],
            "require_attestations_for_new_packages": True,
            "allow_unattested_packages": ["Qualification_Alpha"],
        },
        pypi="unverified",
        decision="FAIL",
        rules=("provenance_required", "unverified_provenance"),
        pypi_status="attestation_available",
        calls=(2, 0),
    ),
    ProviderCase(
        "E11",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score=6.9,
        decision="FAIL",
        rules=("scorecard_below_threshold",),
        score_status="scorecard_available",
        calls=(0, 1),
    ),
    ProviderCase(
        "E12",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score=7.0,
        score_status="scorecard_available",
        calls=(0, 1),
    ),
    ProviderCase(
        "E13",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score=7.1,
        score_status="scorecard_available",
        calls=(0, 1),
    ),
    ProviderCase(
        "E14",
        {"version": 3, "minimum_scorecard_score": 7},
        score=6.9,
        score_status="scorecard_available",
        calls=(0, 1),
    ),
    ProviderCase(
        "E15",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score=6.9,
        mapping="gitlab",
        score_status="repository_unmapped",
    ),
    ProviderCase(
        "E16",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score=6.9,
        mapping="ambiguous",
        score_status="repository_unmapped",
    ),
    ProviderCase(
        "E17",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score=6.9,
        mapping="website",
        score_status="repository_unmapped",
    ),
    ProviderCase(
        "E18",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score=6.9,
        mapping="absent",
        score_status="repository_unmapped",
    ),
    ProviderCase(
        "E19",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score="wrong-repo",
        score_status="enrichment_error",
        calls=(0, 1),
    ),
    ProviderCase(
        "E20",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score=True,
        score_status="enrichment_error",
        calls=(0, 1),
    ),
    ProviderCase(
        "E21",
        {"version": 3, "require_attestations_for_new_packages": True},
        pypi="missing",
        score=7.0,
        decision="FAIL",
        rules=("provenance_required",),
        pypi_status="attestation_unavailable",
        score_status="scorecard_available",
        calls=(2, 1),
    ),
    ProviderCase(
        "E22",
        {
            "version": 3,
            "minimum_scorecard_score": 7,
            "block_on": ["scorecard_below_threshold"],
        },
        score="404",
        score_status="scorecard_unavailable",
        calls=(0, 1),
    ),
)


class SyntheticProviderTransport:
    def __init__(self, case, provider):
        self.case, self.provider, self.calls = case, provider, []

    def open(self, req, timeout):
        url = req.full_url
        self.calls.append(url)
        if self.provider == "scorecard":
            if self.case.score == "404":
                raise HTTPError(url, 404, "Synthetic missing score", None, None)
            payload = {"score": self.case.score}
            if self.case.score == "wrong-repo":
                payload = {"score": 9, "repo": {"name": "github.com/other/unrelated"}}
        elif "/pypi/" in url:
            if self.case.pypi == "error":
                raise HTTPError(url, 503, "Synthetic unavailable service", None, None)
            payload = {
                "info": {},
                "urls": [{"filename": "qualification-alpha-1.0.0.whl"}],
            }
        elif "/integrity/" in url:
            bundles = (
                []
                if self.case.pypi == "missing"
                else [{"attestations": [{"envelope": {"statement": None}}]}]
            )
            if self.case.pypi == "github":
                bundles[0]["publisher"] = {"kind": "github actions"}
            payload = {"attestation_bundles": bundles}
        else:
            raise AssertionError("Unregistered synthetic provider request")
        return io.BytesIO(json.dumps(payload).encode("utf-8"))


def exercise_provider(case, directory, *, spelling=None):
    component = cdx_component(
        spelling or case.name, purl="pkg:pypi/qualification-alpha@1.0.0"
    )
    if case.mapping == "npm":
        component["purl"] = "pkg:npm/qualification-alpha@1.0.0"
    elif case.mapping == "versionless":
        component.update(purl="pkg:pypi/qualification-alpha", version=None)
    elif case.mapping == "gitlab":
        component["externalReferences"][0]["url"] = (
            "https://gitlab.com/example/qualification"
        )
    elif case.mapping == "ambiguous":
        component["externalReferences"].append(
            {"type": "vcs", "url": "https://github.com/other/unrelated"}
        )
    elif case.mapping == "website":
        component["externalReferences"][0]["type"] = "website"
    elif case.mapping == "absent":
        component.pop("externalReferences")
    pypi_transport = SyntheticProviderTransport(case, "pypi")
    score_transport = SyntheticProviderTransport(case, "scorecard")
    pypi = PyPIProvenanceEnricher(client=PyPIIntegrityClient(opener=pypi_transport))
    scorecard = ScorecardEnricher(client=ScorecardClient(opener=score_transport))
    flags = [
        *(["--enrich-pypi"] if case.pypi else []),
        *(["--enrich-scorecard"] if case.score is not None else []),
    ]
    with (
        patch.object(cli, "PyPIProvenanceEnricher", return_value=pypi),
        patch.object(cli, "ScorecardEnricher", return_value=scorecard),
    ):
        code, bundle = run_cli(
            directory,
            {"bomFormat": "CycloneDX", "components": []},
            {"bomFormat": "CycloneDX", "components": [component]},
            case.policy,
            flags,
            expected_provider_lookup=any(case.calls),
        )
    require("provider-decision", consumer_decision(bundle, code).upper(), case.decision)
    require(
        "provider-blocking-identities",
        tuple(row["rule_id"] for row in bundle["report"]["blocking_findings"]),
        case.rules,
    )
    require(
        "synthetic-transport-calls",
        (len(pypi_transport.calls), len(score_transport.calls)),
        case.calls,
    )
    require(
        "provider-confidence",
        bundle["report"]["evidence_confidence"],
        "scorecard_recorded" if case.score is not None else "provenance_recorded",
    )
    recorded = bundle["report"]["components"]["added"][0]
    require("raw-component-name", recorded["name"], spelling or case.name)
    require(
        "raw-component-version",
        recorded["version"],
        None if case.mapping == "versionless" else "1.0.0",
    )
    for provider, status in (
        ("provenance", case.pypi_status),
        ("scorecard", case.score_status),
    ):
        if status:
            require(
                "provider-record-status",
                status in recorded["evidence"][provider]["statuses"],
                True,
            )
    return {
        "id": case.id,
        "decision": case.decision,
        "policy": deepcopy(case.policy),
        "component_key": bundle["report"]["risks"][0]["component_key"],
        "observed_name": recorded["name"],
        "rules": case.rules,
        "provider_states": {
            key: recorded["evidence"].get(key) for key in ("provenance", "scorecard")
        },
        "synthetic_requests": {
            "pypi": pypi_transport.calls,
            "scorecard": score_transport.calls,
        },
        "transport_kind": "in-memory byte streams",
        "cryptographic_verification": "NOT_PERFORMED",
        "tool_release_verification": "OUT_OF_SCOPE",
        "actual_network": "forbidden by qualification guard",
    }


@pytest.mark.parametrize("case", PROVIDERS, ids=lambda case: case.id)
def test_provider_to_cli_decision(case, tmp_path):
    exercise_provider(case, tmp_path)


def exercise_c02_transition(directory):
    case = next(case for case in PROVIDERS if case.id == "E08")
    outputs = [
        exercise_provider(case, directory / label, spelling=label)
        for label in (
            "qualification-alpha",
            "Qualification_Alpha",
            "qualification.alpha",
        )
    ]
    require("c02-stable-decisions", [row["decision"] for row in outputs], ["PASS"] * 3)
    require(
        "c02-stable-identity",
        [row["component_key"] for row in outputs],
        ["purl:pkg:pypi/qualification-alpha"] * 3,
    )
    return {
        "id": "C02",
        "original_case_id": "E08",
        "perturbation": "PEP 503-equivalent spelling only",
        "before_canonical_identity": outputs[0]["component_key"],
        "after_canonical_identity": outputs[1]["component_key"],
        "source_evidence_changes": {
            "observed_names": [row["observed_name"] for row in outputs]
        },
        "active_policy": case.policy,
        "previous_decision": "PASS",
        "resulting_decision": "PASS",
        "expected_classification": "STABLE",
        "observed_classification": "STABLE",
        "reason": "C02 POLICY DECISION APPROVED: canonical PyPI package-name equality; unchanged exception boundary.",
    }


def test_c02_canonical_spelling_is_stable_through_actual_cli(tmp_path):
    exercise_c02_transition(tmp_path)
