"""Owner-approved C03 release coordinates and pre-request identity boundary."""

from copy import deepcopy
from dataclasses import asdict, replace
from unittest.mock import patch

import pytest

from sbom_diff_risk import cli
from sbom_diff_risk.enrichment import PyPIProvenanceEnricher
from sbom_diff_risk.errors import ComponentIdentityError
from sbom_diff_risk.models import Component, ProvenanceStatus
from sbom_diff_risk.pypi_integrity_client import PyPIClientError, PyPIRelease
from sbom_diff_risk.pypi_provenance import normalize_pypi_provenance
from test_pypi_enrichment import FakePyPIClient, _release_file
from test_decision_stability_reports import cdx_component, run_cli


def component(version=None, release="1.0.0", name="demo-pkg"):
    return Component(
        name=name,
        version=version,
        ecosystem="pypi",
        purl=f"pkg:pypi/demo-pkg@{release}",
    )


def client_for(*versions, error=None):
    releases, provenance, errors = {}, {}, {}
    for version in versions:
        file = _release_file(filename=f"demo-pkg-{version}.tar.gz")
        releases["demo-pkg", version] = PyPIRelease(
            project="demo-pkg",
            version=version,
            release_url=f"https://pypi.org/project/demo-pkg/{version}/",
            files=(file,),
        )
        provenance["demo-pkg", version, file.filename] = None
        if error:
            errors["demo-pkg", version] = error
    return FakePyPIClient(
        releases=releases, provenance=provenance, release_errors=errors
    )


@pytest.mark.parametrize("reverse", [False, True])
def test_equivalent_releases_share_consistent_evidence_without_mutation(reverse):
    items = [component(), component("1.0.0", name="Demo_Pkg")]
    if reverse:
        items.reverse()
    observed = deepcopy(items)
    client = client_for("1.0.0")
    enricher = PyPIProvenanceEnricher(client=client)
    results = enricher.enrich_components(items)
    assert items == observed
    assert client.release_calls == [("demo-pkg", "1.0.0")]
    assert results[0].provenance == results[1].provenance
    assert results[0].provenance.package_version == "1.0.0"
    assert results[0].provenance.package_name == "demo-pkg"
    assert results[0].provenance.statuses == (ProvenanceStatus.ATTESTATION_UNAVAILABLE,)
    for before, after in zip(items, results):
        assert asdict(replace(after, provenance=None)) == asdict(before)
    assert enricher.build_report_metadata().candidate_components == 1


def test_distinct_release_cache_isolation():
    client = client_for("1.0.0", "2.0.0")
    enricher = PyPIProvenanceEnricher(client=client)
    rows = enricher.enrich_components(
        [component(), component(release="2.0.0"), component("1.0.0")]
    )
    assert client.release_calls == [("demo-pkg", "1.0.0"), ("demo-pkg", "2.0.0")]
    assert [r.provenance.package_version for r in rows] == ["1.0.0", "2.0.0", "1.0.0"]
    assert rows[0].provenance.files != rows[1].provenance.files


INVALID = [
    component("2.0.0"),
    replace(component(), purl="not-a-purl"),
    replace(component(), ecosystem="npm"),
    replace(component(), name="other-package"),
]


@pytest.mark.parametrize(
    "invalid", INVALID, ids=["version", "purl", "ecosystem", "name"]
)
@pytest.mark.parametrize("batch", [False, True])
def test_direct_api_rejects_invalid_identity_before_any_lookup(invalid, batch):
    client = client_for("1.0.0", "2.0.0")
    with pytest.raises(ComponentIdentityError):
        if batch:
            PyPIProvenanceEnricher(client=client).enrich_components(
                [component("1.0.0"), invalid]
            )
        else:
            normalize_pypi_provenance(invalid, client=client)
    assert client.release_calls == client.provenance_calls == []


@pytest.mark.parametrize("purl", [None, "pkg:pypi/demo-pkg"])
def test_no_version_never_looks_up_latest(purl):
    client = client_for("1.0.0")
    evidence = normalize_pypi_provenance(replace(component(), purl=purl), client=client)
    assert evidence.statuses == (ProvenanceStatus.UNSUPPORTED_FOR_PACKAGE,)
    assert evidence.lookup_performed is False
    assert client.release_calls == []


@pytest.mark.parametrize("status", [404, 503])
def test_canonical_release_preserves_failure_states(status):
    client = client_for(
        "1.0.0", error=PyPIClientError("synthetic failure", status_code=status)
    )
    evidence = normalize_pypi_provenance(component(), client=client)
    assert evidence.package_version == "1.0.0"
    assert evidence.lookup_performed
    assert evidence.statuses == (
        (ProvenanceStatus.UNSUPPORTED_FOR_PACKAGE,)
        if status == 404
        else (ProvenanceStatus.ENRICHMENT_ERROR,)
    )


@pytest.mark.parametrize("flag", ["--enrich-pypi", "--enrich-scorecard"])
@pytest.mark.parametrize(
    "invalid", INVALID, ids=["version", "purl", "ecosystem", "name"]
)
def test_cli_validates_both_inputs_before_enricher_construction(
    flag, invalid, tmp_path
):
    # Inject normalized metadata to cover contradictions that a format parser
    # would otherwise derive or reject; the public CLI ordering is exercised.
    with (
        patch.object(
            cli,
            "normalize_input_with_options",
            side_effect=[
                ("cyclonedx-json", [component("1.0.0")], []),
                ("cyclonedx-json", [invalid], []),
            ],
        ),
        patch.object(
            cli,
            "PyPIProvenanceEnricher",
            side_effect=AssertionError(
                "enricher constructed before identity preflight"
            ),
        ) as pypi,
        patch.object(
            cli,
            "ScorecardEnricher",
            side_effect=AssertionError(
                "enricher constructed before identity preflight"
            ),
        ) as scorecard,
    ):
        code, bundle = run_cli(
            tmp_path,
            {"bomFormat": "CycloneDX", "components": []},
            {"bomFormat": "CycloneDX", "components": []},
            flags=[flag],
        )
    assert code == 2 and bundle is None
    pypi.assert_not_called()
    scorecard.assert_not_called()


def exercise_c03_transition(tmp_path, enabled=True):
    bundles = []
    for label, version in [("purl-only", None), ("explicit", "1.0.0")]:
        item = cdx_component(name="demo-pkg", version="1.0.0")
        item["version"] = version
        client = client_for("1.0.0")
        with patch.object(
            cli,
            "PyPIProvenanceEnricher",
            return_value=PyPIProvenanceEnricher(client=client),
        ) as factory:
            code, bundle = run_cli(
                tmp_path / label,
                {"bomFormat": "CycloneDX", "components": []},
                {"bomFormat": "CycloneDX", "components": [item]},
                {"version": 2, "block_on": ["provenance_unavailable"]},
                flags=["--enrich-pypi"] if enabled else [],
                expected_provider_lookup=enabled,
            )
        assert code == (0 if enabled else 1)
        if not enabled:
            factory.assert_not_called()
        assert client.release_calls == ([("demo-pkg", "1.0.0")] if enabled else [])
        assert bundle["report"]["components"]["added"][0]["version"] == version
        bundles.append(bundle)
    for bundle in bundles:
        # Invocation-specific policy source paths are not release evidence.
        bundle["policy"]["policy_evaluation"].pop("policy_path")
    assert bundles[0]["policy"] == bundles[1]["policy"]
    assert bundles[0]["summary"] == bundles[1]["summary"]
    return {
        "id": "C03",
        "perturbation": "Agreeing explicit versus PURL-only release version",
        "before_canonical_identity": {
            "key": "purl:pkg:pypi/demo-pkg",
            "version": "1.0.0",
        },
        "after_canonical_identity": {
            "key": "purl:pkg:pypi/demo-pkg",
            "version": "1.0.0",
        },
        "previous_decision": "PASS" if enabled else "FAIL",
        "resulting_decision": "PASS" if enabled else "FAIL",
        "active_policy": {"version": 2, "block_on": ["provenance_unavailable"]},
        "expected_classification": "STABLE",
        "observed_classification": "STABLE",
        "reason": "CONTRACT_CLARIFIED_CANONICAL_RELEASE_VERSION",
        "source_evidence_changes": {
            "raw_versions": [None, "1.0.0"],
            "enrichment_enabled": enabled,
        },
    }


@pytest.mark.parametrize("enabled", [False, True])
def test_original_c03_cli_representation_transition(tmp_path, enabled):
    exercise_c03_transition(tmp_path, enabled)


def test_direct_normalizer_uses_canonical_release():
    client = client_for("1.0.0")
    a = normalize_pypi_provenance(component(), client=client)
    b = normalize_pypi_provenance(component("1.0.0", name="Demo_Pkg"), client=client)
    assert a == b
    assert client.release_calls == [("demo-pkg", "1.0.0")] * 2


@pytest.mark.parametrize("version", ["1.0.0", "2.0.0"])
def test_cli_rejects_duplicate_or_conflicting_index_before_lookup(version, tmp_path):
    client = client_for("1.0.0", "2.0.0")
    items = [
        cdx_component(name="demo-pkg", version="1.0.0"),
        cdx_component(name="demo-pkg", version=version),
    ]
    with patch.object(
        cli,
        "PyPIProvenanceEnricher",
        return_value=PyPIProvenanceEnricher(client=client),
    ):
        code, bundle = run_cli(
            tmp_path,
            {"bomFormat": "CycloneDX", "components": []},
            {"bomFormat": "CycloneDX", "components": items},
            flags=["--enrich-pypi"],
        )
    assert code == 2 and bundle is None
    assert client.release_calls == client.provenance_calls == []


@pytest.mark.parametrize(
    "change", [{"version": "2.0.0"}, {"purl": "not-a-purl"}, {"name": "other-package"}]
)
def test_actual_cli_input_rejected_before_lookup(change, tmp_path):
    item = cdx_component(name="demo-pkg", version="1.0.0")
    item.update(change)
    client = client_for("1.0.0", "2.0.0")
    with patch.object(
        cli,
        "PyPIProvenanceEnricher",
        return_value=PyPIProvenanceEnricher(client=client),
    ):
        code, bundle = run_cli(
            tmp_path,
            {"bomFormat": "CycloneDX", "components": []},
            {"bomFormat": "CycloneDX", "components": [item]},
            flags=["--enrich-pypi"],
        )
    assert code == 2 and bundle is None
    assert client.release_calls == client.provenance_calls == []
