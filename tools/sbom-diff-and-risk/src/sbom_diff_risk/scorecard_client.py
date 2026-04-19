from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Any
from urllib import error, parse, request

from .models import ScorecardCheck


@dataclass(slots=True, frozen=True)
class ScorecardProjectResult:
    canonical_name: str
    score: float
    date: str | None
    scorecard_version: str | None
    scorecard_commit: str | None
    repository_commit: str | None
    checks: tuple[ScorecardCheck, ...]


class ScorecardClientError(RuntimeError):
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


class ScorecardClient:
    def __init__(
        self,
        *,
        timeout_seconds: float = 5.0,
        base_url: str = "https://api.securityscorecards.dev",
        opener: request.OpenerDirector | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.base_url = base_url.rstrip("/")
        self._opener = opener or request.build_opener()

    def fetch_project(self, platform: str, owner: str, repo: str) -> ScorecardProjectResult:
        encoded_platform = parse.quote(platform, safe="")
        encoded_owner = parse.quote(owner, safe="")
        encoded_repo = parse.quote(repo, safe="")
        path = f"/projects/{encoded_platform}/{encoded_owner}/{encoded_repo}"
        payload = self._read_json(path)
        return parse_project_payload(payload, expected_canonical_name=f"{platform}/{owner}/{repo}")

    def _read_json(self, path: str) -> object:
        url = f"{self.base_url}{path}"
        req = request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "sbom-diff-and-risk scorecard-client",
            },
        )
        try:
            with self._opener.open(req, timeout=self.timeout_seconds) as response:
                payload = json.load(response)
        except error.HTTPError as exc:
            raise ScorecardClientError(
                f"Scorecard request failed with HTTP {exc.code} for {url}.",
                status_code=exc.code,
            ) from exc
        except error.URLError as exc:
            if _is_timeout_reason(exc.reason):
                raise ScorecardClientError(
                    f"Scorecard request timed out after {self.timeout_seconds} seconds for {url}.",
                    is_timeout=True,
                ) from exc
            raise ScorecardClientError(f"Scorecard request failed for {url}: {exc.reason}.") from exc
        except TimeoutError as exc:
            raise ScorecardClientError(
                f"Scorecard request timed out after {self.timeout_seconds} seconds for {url}.",
                is_timeout=True,
            ) from exc
        except socket.timeout as exc:
            raise ScorecardClientError(
                f"Scorecard request timed out after {self.timeout_seconds} seconds for {url}.",
                is_timeout=True,
            ) from exc
        except json.JSONDecodeError as exc:
            raise ScorecardClientError(
                f"Scorecard returned malformed JSON for {url}: line {exc.lineno}, column {exc.colno}: {exc.msg}."
            ) from exc

        return payload


def parse_project_payload(payload: object, *, expected_canonical_name: str) -> ScorecardProjectResult:
    if not isinstance(payload, dict):
        raise ScorecardClientError("Scorecard response must be a JSON object.")

    raw_repo = payload.get("repo")
    repo_name = expected_canonical_name
    repo_commit = None
    if raw_repo is not None:
        if not isinstance(raw_repo, dict):
            raise ScorecardClientError("Scorecard repo field must be an object when present.")
        repo_name = _optional_text(raw_repo.get("name")) or expected_canonical_name
        repo_commit = _optional_text(raw_repo.get("commit"))

    score = _required_number(payload.get("score"), "Scorecard score")
    date = _optional_text(payload.get("date"))

    scorecard_version = None
    scorecard_commit = None
    raw_scorecard = payload.get("scorecard")
    if raw_scorecard is not None:
        if not isinstance(raw_scorecard, dict):
            raise ScorecardClientError("Scorecard metadata field must be an object when present.")
        scorecard_version = _optional_text(raw_scorecard.get("version"))
        scorecard_commit = _optional_text(raw_scorecard.get("commit"))

    raw_checks = payload.get("checks")
    if raw_checks is None:
        raw_checks = []
    if not isinstance(raw_checks, list):
        raise ScorecardClientError("Scorecard checks field must be a list.")

    checks: list[ScorecardCheck] = []
    for raw_check in raw_checks:
        if not isinstance(raw_check, dict):
            raise ScorecardClientError("Scorecard check entries must be JSON objects.")
        name = _required_text(raw_check.get("name"), "Scorecard check name")
        raw_check_score = raw_check.get("score")
        if raw_check_score is None:
            continue
        checks.append(
            ScorecardCheck(
                name=name,
                score=int(_required_number(raw_check_score, f"Scorecard check {name} score")),
                reason=_optional_text(raw_check.get("reason")),
                documentation_url=_documentation_field(raw_check.get("documentation"), "url"),
                documentation_short=_documentation_field(raw_check.get("documentation"), "short"),
            )
        )

    checks.sort(key=lambda item: item.name.lower())
    return ScorecardProjectResult(
        canonical_name=repo_name,
        score=score,
        date=date,
        scorecard_version=scorecard_version,
        scorecard_commit=scorecard_commit,
        repository_commit=repo_commit,
        checks=tuple(checks),
    )


def _documentation_field(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ScorecardClientError("Scorecard documentation field must be an object when present.")
    return _optional_text(value.get(field))


def _required_text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScorecardClientError(f"{context} must be a non-empty string.")
    return value.strip()


def _required_number(value: object, context: str) -> float:
    if not isinstance(value, (int, float)):
        raise ScorecardClientError(f"{context} must be a number.")
    return float(value)


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ScorecardClientError("Expected a string value in Scorecard response.")
    stripped = value.strip()
    return stripped or None


def _is_timeout_reason(reason: object) -> bool:
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return True
    if isinstance(reason, str):
        return "timed out" in reason.lower()
    return False
