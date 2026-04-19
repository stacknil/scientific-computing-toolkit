from __future__ import annotations

import io
import json
from urllib import error

import pytest

from sbom_diff_risk.scorecard_client import (
    ScorecardClient,
    ScorecardClientError,
    parse_project_payload,
)


def test_parse_project_payload_extracts_score_and_checks() -> None:
    payload = {
        "date": "2026-04-10T00:00:00Z",
        "repo": {
            "name": "github.com/psf/requests",
            "commit": "abc123",
        },
        "scorecard": {
            "version": "5.0.0",
            "commit": "def456",
        },
        "score": 7.8,
        "checks": [
            {
                "name": "Maintained",
                "score": 10,
                "reason": "Project is active.",
                "documentation": {"url": "https://example.test/docs/maintained", "short": "Maintained"},
            },
            {
                "name": "Branch-Protection",
                "score": 6,
                "reason": "Not all protections are enabled.",
            },
        ],
    }

    result = parse_project_payload(payload, expected_canonical_name="github.com/psf/requests")

    assert result.canonical_name == "github.com/psf/requests"
    assert result.score == 7.8
    assert result.repository_commit == "abc123"
    assert result.scorecard_version == "5.0.0"
    assert [check.name for check in result.checks] == ["Branch-Protection", "Maintained"]
    assert result.checks[1].documentation_url == "https://example.test/docs/maintained"


def test_scorecard_client_surfaces_404_as_client_error() -> None:
    url = "https://api.securityscorecards.dev/projects/github.com/psf/requests"
    client = ScorecardClient(opener=FakeOpener({url: _http_error(url, 404)}))

    with pytest.raises(ScorecardClientError) as excinfo:
        client.fetch_project("github.com", "psf", "requests")

    assert excinfo.value.status_code == 404


class FakeOpener:
    def __init__(self, responses: dict[str, object]) -> None:
        self._responses = responses

    def open(self, req, timeout: float):  # noqa: ANN001
        outcome = self._responses[req.full_url]
        if isinstance(outcome, Exception):
            raise outcome
        return _Response(outcome)


class _Response(io.BytesIO):
    def __init__(self, payload: object) -> None:
        super().__init__(json.dumps(payload).encode("utf-8"))

    def __enter__(self):  # noqa: ANN204
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.close()


def _http_error(url: str, code: int) -> error.HTTPError:
    return error.HTTPError(url, code, "error", hdrs=None, fp=io.BytesIO(b"{}"))
