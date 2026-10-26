"""Synthetic byte-stream evidence must stay bound and strictly serializable."""

import io
import json
from unittest.mock import patch

import pytest

from sbom_diff_risk import cli
from sbom_diff_risk.scorecard_client import ScorecardClient, ScorecardClientError
from sbom_diff_risk.scorecard_enrichment import ScorecardEnricher


class ByteStreamOpener:
    def __init__(self, payload):
        self.body = json.dumps(payload).encode("utf-8")
        self.calls = []

    def open(self, req, timeout):
        self.calls.append(req.full_url)
        return io.BytesIO(self.body)


@pytest.mark.parametrize(
    "value",
    [True, False, float("inf"), float("-inf"), float("nan")],
    ids=["true", "false", "positive-infinity", "negative-infinity", "nan"],
)
@pytest.mark.parametrize("field", ["overall", "check"])
def test_invalid_score_numbers_are_controlled_client_errors(value, field):
    payload = (
        {"score": value}
        if field == "overall"
        else {"score": 8, "checks": [{"name": "Synthetic", "score": value}]}
    )
    client = ScorecardClient(opener=ByteStreamOpener(payload))
    with pytest.raises(ScorecardClientError):
        client.fetch_project("github.com", "example", "qualification")


def test_explicit_scorecard_repository_mismatch_is_rejected():
    opener = ByteStreamOpener(
        {
            "repo": {"name": "github.com/other/unrelated", "commit": "other-commit"},
            "score": 9,
        }
    )
    with pytest.raises(ScorecardClientError):
        ScorecardClient(opener=opener).fetch_project(
            "github.com", "example", "qualification"
        )
    assert len(opener.calls) == 1


@pytest.mark.parametrize(
    "requested,returned",
    [("repo-ss", "repo-\u00df"), ("repo-k", "repo-\u212a"), ("repo-ff", "repo-\ufb00")],
    ids=["sharp-s-expansion", "kelvin-sign", "ligature-expansion"],
)
def test_scorecard_response_does_not_use_unicode_name_aliases(requested, returned):
    payload = {"repo": {"name": f"github.com/example/{returned}"}, "score": 9}
    with pytest.raises(ScorecardClientError):
        ScorecardClient(opener=ByteStreamOpener(payload)).fetch_project(
            "github.com", "example", requested
        )


@pytest.mark.parametrize(
    "repo",
    [
        None,
        {"commit": "synthetic-commit"},
        {"name": "github.com/example/qualification"},
        {"name": "GitHub.com/EXAMPLE/QUALIFICATION"},
    ],
    ids=["repository-omitted", "name-omitted", "exact", "case-only"],
)
def test_scorecard_identity_compatibility_and_finite_sentinel(repo):
    payload = {"score": 7.5, "checks": [{"name": "Synthetic", "score": -1}]}
    if repo is not None:
        payload["repo"] = repo
    result = ScorecardClient(opener=ByteStreamOpener(payload)).fetch_project(
        "github.com", "example", "qualification"
    )
    assert result.score == 7.5 and result.checks[0].score == -1
    assert result.canonical_name.casefold() == "github.com/example/qualification"


def reject_nonfinite(value):
    raise ValueError(f"Non-JSON numeric token: {value}")


@pytest.mark.parametrize(
    "payload",
    [
        {"score": True},
        {"score": float("inf")},
        {"score": float("-inf")},
        {"score": float("nan")},
        {
            "repo": {"name": "github.com/other/unrelated", "commit": "other-commit"},
            "score": 9,
        },
    ],
    ids=[
        "boolean",
        "positive-infinity",
        "negative-infinity",
        "nan",
        "repository-conflict",
    ],
)
def test_cli_bad_scorecard_evidence_is_error_record_not_available_score(
    tmp_path, monkeypatch, payload
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "before.json").write_text(
        json.dumps({"bomFormat": "CycloneDX", "components": []}), encoding="utf-8"
    )
    component = {
        "name": "qualification-alpha",
        "version": "1.0.0",
        "purl": "pkg:pypi/qualification-alpha@1.0.0",
        "licenses": [{"license": {"id": "MIT"}}],
        "externalReferences": [
            {"type": "vcs", "url": "https://github.com/example/qualification"}
        ],
    }
    (tmp_path / "after.json").write_text(
        json.dumps({"bomFormat": "CycloneDX", "components": [component]}),
        encoding="utf-8",
    )
    (tmp_path / "policy.yml").write_text(
        "version: 3\nblock_on: [scorecard_below_threshold]\nminimum_scorecard_score: 7\n",
        encoding="utf-8",
    )
    opener = ByteStreamOpener(payload)
    enricher = ScorecardEnricher(client=ScorecardClient(opener=opener))
    with patch.object(cli, "ScorecardEnricher", return_value=enricher):
        code = cli.main(
            [
                "compare",
                "--before",
                "before.json",
                "--after",
                "after.json",
                "--policy",
                "policy.yml",
                "--enrich-scorecard",
                "--out-json",
                "report.json",
            ]
        )
    assert code == 0  # Missing Scorecard evidence does not create a new blocking rule.
    report = json.loads(
        (tmp_path / "report.json").read_text(encoding="utf-8"),
        parse_constant=reject_nonfinite,
    )
    recorded = report["components"]["added"][0]["evidence"]["scorecard"]
    assert recorded["statuses"] == ["enrichment_error"]
    assert recorded["score"] is None and recorded["error"]
    assert report["summary"]["policy"] == {
        "status": "pass",
        "blocking": 0,
        "warning": 0,
        "suppressed": 0,
    }
    assert report["evidence_confidence"] == "scorecard_recorded"
    assert len(opener.calls) == 1
