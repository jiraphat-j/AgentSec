"""Deterministic, explainable Phase 2 risk prototype."""

from __future__ import annotations

from .models import RiskAssessment, RiskBand, RiskFactor


def assess_risk(
    tool: str,
    *,
    untrusted_document: bool,
    secret_resource: bool = False,
    matching_canary: bool = False,
) -> RiskAssessment:
    factors: list[RiskFactor] = []
    if untrusted_document:
        factors.append(RiskFactor(code="untrusted_document", weight=20))
    if tool == "read_file" and secret_resource:
        factors.append(RiskFactor(code="classified_secret_access", weight=60))
    if tool == "http_post":
        factors.append(RiskFactor(code="lab_post", weight=40))
    if tool == "http_post" and matching_canary:
        factors.append(RiskFactor(code="matching_canary_transfer", weight=60))
    score = min(sum(factor.weight for factor in factors), 100)
    if score >= 80:
        band = RiskBand.HIGH
    elif score >= 40:
        band = RiskBand.ELEVATED
    else:
        band = RiskBand.LOW
    return RiskAssessment(score=score, band=band, factors=tuple(factors))
