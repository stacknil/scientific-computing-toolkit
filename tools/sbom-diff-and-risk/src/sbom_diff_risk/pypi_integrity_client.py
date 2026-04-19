from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Any
from urllib import error, parse, request


@dataclass(slots=True, frozen=True)
class PyPIReleaseFile:
    filename: str
    url: str | None
    sha256: str | None
    upload_time: str | None
    yanked: bool


@dataclass(slots=True, frozen=True)
class PyPIRelease:
    project: str
    version: str
    release_url: str | None
    files: tuple[PyPIReleaseFile, ...]


@dataclass(slots=True, frozen=True)
class PyPIAttestation:
    statement: str | None
    publisher_kind: str | None


@dataclass(slots=True, frozen=True)
class PyPIFileProvenance:
    filename: str
    attestation_count: int
    attestations: tuple[PyPIAttestation, ...]


class PyPIClientError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        is_timeout: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.is_timeout = is_timeout


class PyPIIntegrityClient:
    def __init__(
        self,
        *,
        timeout_seconds: float = 5.0,
        base_url: str = "https://pypi.org",
        opener: request.OpenerDirector | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.base_url = base_url.rstrip("/")
        self._opener = opener or request.build_opener()

    def fetch_release(self, project: str, version: str) -> PyPIRelease:
        encoded_project = parse.quote(project, safe="")
        encoded_version = parse.quote(version, safe="")
        payload = self._read_json(f"/pypi/{encoded_project}/{encoded_version}/json")
        return parse_release_payload(payload, project=project, version=version)

    def fetch_provenance(self, project: str, version: str, filename: str) -> PyPIFileProvenance | None:
        encoded_project = parse.quote(project, safe="")
        encoded_version = parse.quote(version, safe="")
        encoded_filename = parse.quote(filename, safe="")
        path = f"/integrity/{encoded_project}/{encoded_version}/{encoded_filename}/provenance"
        try:
            payload = self._read_json(path)
        except PyPIClientError as exc:
            if exc.status_code == 404:
                return None
            raise
        return parse_provenance_payload(payload, filename=filename)

    def _read_json(self, path: str) -> object:
        url = f"{self.base_url}{path}"
        req = request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "sbom-diff-and-risk pypi-integrity-client",
            },
        )
        try:
            with self._opener.open(req, timeout=self.timeout_seconds) as response:
                payload = json.load(response)
        except error.HTTPError as exc:
            raise PyPIClientError(
                f"PyPI request failed with HTTP {exc.code} for {url}.",
                status_code=exc.code,
            ) from exc
        except error.URLError as exc:
            if _is_timeout_reason(exc.reason):
                raise PyPIClientError(
                    f"PyPI request timed out after {self.timeout_seconds} seconds for {url}.",
                    is_timeout=True,
                ) from exc
            raise PyPIClientError(f"PyPI request failed for {url}: {exc.reason}.") from exc
        except TimeoutError as exc:
            raise PyPIClientError(
                f"PyPI request timed out after {self.timeout_seconds} seconds for {url}.",
                is_timeout=True,
            ) from exc
        except socket.timeout as exc:
            raise PyPIClientError(
                f"PyPI request timed out after {self.timeout_seconds} seconds for {url}.",
                is_timeout=True,
            ) from exc
        except json.JSONDecodeError as exc:
            raise PyPIClientError(
                f"PyPI returned malformed JSON for {url}: line {exc.lineno}, column {exc.colno}: {exc.msg}."
            ) from exc

        return payload


def parse_release_payload(payload: object, *, project: str, version: str) -> PyPIRelease:
    if not isinstance(payload, dict):
        raise PyPIClientError("PyPI release response must be a JSON object.")

    raw_info = payload.get("info")
    if raw_info is None or not isinstance(raw_info, dict):
        raise PyPIClientError("PyPI release response is missing an info object.")

    release_url = _optional_text(raw_info.get("release_url")) or _optional_text(raw_info.get("package_url"))
    raw_files = payload.get("urls")
    if raw_files is None:
        raw_files = []
    if not isinstance(raw_files, list):
        raise PyPIClientError("PyPI release response urls field must be a list.")

    files: list[PyPIReleaseFile] = []
    for raw_file in raw_files:
        if not isinstance(raw_file, dict):
            raise PyPIClientError("PyPI release file entries must be JSON objects.")
        filename = _required_text(raw_file.get("filename"), "PyPI release file filename")
        raw_digests = raw_file.get("digests")
        if raw_digests is not None and not isinstance(raw_digests, dict):
            raise PyPIClientError("PyPI release file digests field must be an object when present.")
        sha256 = None
        if isinstance(raw_digests, dict):
            sha256 = _optional_text(raw_digests.get("sha256"))
        files.append(
            PyPIReleaseFile(
                filename=filename,
                url=_optional_text(raw_file.get("url")),
                sha256=sha256,
                upload_time=_optional_text(raw_file.get("upload_time_iso_8601")),
                yanked=bool(raw_file.get("yanked", False)),
            )
        )

    files.sort(key=lambda item: item.filename.lower())
    return PyPIRelease(
        project=project,
        version=version,
        release_url=release_url,
        files=tuple(files),
    )


def parse_provenance_payload(payload: object, *, filename: str) -> PyPIFileProvenance:
    if not isinstance(payload, dict):
        raise PyPIClientError("PyPI provenance response must be a JSON object.")

    raw_bundles = payload.get("attestation_bundles")
    if raw_bundles is None:
        raw_bundles = []
    if not isinstance(raw_bundles, list):
        raise PyPIClientError("PyPI provenance response attestation_bundles field must be a list.")

    attestations: list[PyPIAttestation] = []
    for raw_bundle in raw_bundles:
        if not isinstance(raw_bundle, dict):
            raise PyPIClientError("PyPI provenance bundles must be JSON objects.")
        publisher_kind = None
        raw_publisher = raw_bundle.get("publisher")
        if raw_publisher is not None:
            if not isinstance(raw_publisher, dict):
                raise PyPIClientError("PyPI provenance publisher must be an object when present.")
            publisher_kind = _optional_text(raw_publisher.get("kind"))

        raw_attestations = raw_bundle.get("attestations")
        if raw_attestations is None:
            raw_attestations = []
        if not isinstance(raw_attestations, list):
            raise PyPIClientError("PyPI provenance bundle attestations field must be a list.")

        for raw_attestation in raw_attestations:
            if not isinstance(raw_attestation, dict):
                raise PyPIClientError("PyPI provenance attestations must be JSON objects.")
            raw_envelope = raw_attestation.get("envelope")
            if raw_envelope is None or not isinstance(raw_envelope, dict):
                raise PyPIClientError("PyPI provenance attestation envelope must be an object.")
            attestations.append(
                PyPIAttestation(
                    statement=_optional_text(raw_envelope.get("statement")),
                    publisher_kind=publisher_kind,
                )
            )

    return PyPIFileProvenance(
        filename=filename,
        attestation_count=len(attestations),
        attestations=tuple(attestations),
    )


def _required_text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PyPIClientError(f"{context} must be a non-empty string.")
    return value


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PyPIClientError("Expected a string value in PyPI response.")
    stripped = value.strip()
    return stripped or None


def _is_timeout_reason(reason: object) -> bool:
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return True
    if isinstance(reason, str):
        return "timed out" in reason.lower()
    return False
