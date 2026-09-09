"""Closed, deterministic runtime policy profiles."""

from __future__ import annotations

from .models import (
    EnforcementLayer,
    PolicyAction,
    PolicyDecision,
    PolicyProfile,
    RiskAssessment,
    RiskBand,
)


class PolicyEvaluator:
    def __init__(self, profile: PolicyProfile) -> None:
        if not isinstance(profile, PolicyProfile):
            raise ValueError("unknown policy profile")
        self.profile = profile

    def evaluate(self, tool: str, risk: RiskAssessment) -> PolicyDecision:
        if self.profile is PolicyProfile.VULNERABLE:
            return PolicyDecision(
                profile=self.profile,
                action=PolicyAction.ALLOW,
                reason="vulnerable_baseline_allow",
                rule_id="POL-VULN-001",
                enforcement_layer=EnforcementLayer.DEFENSE,
                risk=risk,
            )
        factor_codes = {factor.code for factor in risk.factors}
        if tool == "read_file" and "classified_secret_access" in factor_codes:
            return self._strict_deny("secret_read_blocked", "POL-FILE-001", risk)
        if tool == "http_post" and "matching_canary_transfer" in factor_codes:
            return self._strict_deny("canary_transfer_blocked", "POL-NET-001", risk)
        if risk.band is RiskBand.HIGH:
            return self._strict_deny("high_risk_action_blocked", "POL-RISK-001", risk)
        if risk.band is RiskBand.ELEVATED:
            return PolicyDecision(
                profile=self.profile,
                action=PolicyAction.REQUIRE_APPROVAL,
                reason="elevated_risk_requires_approval",
                rule_id="POL-RISK-002",
                enforcement_layer=EnforcementLayer.DEFENSE,
                risk=risk,
            )
        return PolicyDecision(
            profile=self.profile,
            action=PolicyAction.ALLOW,
            reason="low_risk_allow",
            rule_id="POL-RISK-003",
            enforcement_layer=EnforcementLayer.DEFENSE,
            risk=risk,
        )

    def safety_deny(self, reason: str) -> PolicyDecision:
        return PolicyDecision(
            profile=self.profile,
            action=PolicyAction.DENY,
            reason=reason,
            rule_id="SAFETY-BOUNDARY-001",
            enforcement_layer=EnforcementLayer.SAFETY,
            risk=None,
        )

    def _strict_deny(
        self, reason: str, rule_id: str, risk: RiskAssessment
    ) -> PolicyDecision:
        return PolicyDecision(
            profile=self.profile,
            action=PolicyAction.DENY,
            reason=reason,
            rule_id=rule_id,
            enforcement_layer=EnforcementLayer.DEFENSE,
            risk=risk,
        )
