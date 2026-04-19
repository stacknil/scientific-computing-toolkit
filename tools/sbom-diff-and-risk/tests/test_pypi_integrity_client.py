from __future__ import annotations

import io
import json
from urllib import error

from sbom_diff_risk.pypi_integrity_client import (
    PyPIIntegrityClient,
    parse_provenance_payload,
    parse_release_payload,
)


def test_parse_release_payload_extracts_sorted_files() -> None:
    payload = {
        "info": {
            "package_url": "https://pypi.org/project/example/",
        },
        "urls": [
            {
                "filename": "example-1.0.0.tar.gz",
                "url": "https://files.pythonhosted.org/packages/source/e/example/example-1.0.0.tar.gz",
                "digests": {"sha256": "bbb"},
                "upload_time_iso_8601": "2026-04-01T00:00:00.000000Z",
                "yanked": False,
            },
            {
                "filename": "example-1.0.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/packages/example-1.0.0-py3-none-any.whl",
                "digests": {"sha256": "aaa"},
                "upload_time_iso_8601": "2026-04-01T00:00:01.000000Z",
                "yanked": False,
            },
        ],
    }

    release = parse_release_payload(payload, project="example", version="1.0.0")

    assert release.release_url == "https://pypi.org/project/example/"
    assert [item.filename for item in release.files] == [
        "example-1.0.0-py3-none-any.whl",
        "example-1.0.0.tar.gz",
    ]
    assert release.files[0].sha256 == "aaa"


def test_parse_provenance_payload_flattens_attestations() -> None:
    payload = {
        "attestation_bundles": [
            {
                "publisher": {"kind": "GitHub Actions"},
                "attestations": [
                    {"envelope": {"statement": "eyJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9wcmVkaWNhdGUifQ"}}
                ],
            }
        ]
    }

    provenance = parse_provenance_payload(payload, filename="example-1.0.0.tar.gz")

    assert provenance.filename == "example-1.0.0.tar.gz"
    assert provenance.attestation_count == 1
    assert provenance.attestations[0].publisher_kind == "GitHub Actions"


def test_fetch_provenance_returns_none_for_404() -> None:
    url = "https://pypi.org/integrity/example/1.0.0/example-1.0.0.tar.gz/provenance"
    client = PyPIIntegrityClient(opener=FakeOpener({url: _http_error(url, 404)}))

    provenance = client.fetch_provenance("example", "1.0.0", "example-1.0.0.tar.gz")

    assert provenance is None


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
