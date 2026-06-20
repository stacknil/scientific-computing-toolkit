from __future__ import annotations

from pathlib import Path

from sbom_diff_risk.models import RiskBucket

REPO_ROOT = Path(__file__).resolve().parents[3]
RISK_MODEL_BOUNDARY = REPO_ROOT / "docs" / "risk-model-boundary.md"


def _risk_model_boundary_text() -> str:
    return RISK_MODEL_BOUNDARY.read_text(encoding="utf-8")


def _normalized_text(text: str) -> str:
    return " ".join(text.split())


def test_risk_model_boundary_names_every_risk_bucket() -> None:
    text = _risk_model_boundary_text()

    for bucket in RiskBucket:
        assert f"`{bucket.value}`" in text


def test_risk_model_boundary_names_inputs_and_nonclaims() -> None:
    text = _risk_model_boundary_text()
    normalized = _normalized_text(text)

    for phrase in (
        "`before.version`",
        "`after.version`",
        "`license_id`",
        "`purl`",
        "`source_url`",
        "allowlist",
        "`stale_enrichment_enabled`",
        "not a vulnerability scanner",
        "not a CVE resolver",
        "not a dependency safety verdict",
        "hidden network enrichment",
    ):
        assert phrase in text or _normalized_text(phrase) in normalized
