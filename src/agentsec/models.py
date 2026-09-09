"""Strict external and persisted data models for supported schema versions."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .constants import MAX_TIMEOUT_SECONDS

Outcome: TypeAlias = Literal[
    "simulated_impact", "prevented", "no_correlated_chain", "incomplete"
]
EventSchemaVersion: TypeAlias = Literal["0.1", "0.2"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class DocumentFixture(StrEnum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    MISSING_CANARY = "missing_canary"


class PolicyProfile(StrEnum):
    VULNERABLE = "vulnerable"
    STRICT = "strict"


class ApprovalSimulation(StrEnum):
    DENY = "deny"
    APPROVE = "approve"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class EnforcementLayer(StrEnum):
    SAFETY = "safety"
    DEFENSE = "defense"


class RiskBand(StrEnum):
    LOW = "low"
    ELEVATED = "elevated"
    HIGH = "high"


class Scenario(StrictModel):
    schema_version: Literal["0.1"] = "0.1"
    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9-]+$")
    name: str = Field(min_length=1, max_length=160)
    document_fixture: DocumentFixture
    timeout_seconds: int = Field(ge=1, le=MAX_TIMEOUT_SECONDS)


class ReadFileArguments(StrictModel):
    path: str = Field(min_length=1, max_length=256)


class HttpPostArguments(StrictModel):
    destination: str = Field(min_length=1, max_length=256)
    body: str


class Event(StrictModel):
    schema_version: EventSchemaVersion = "0.2"
    event_id: str = Field(min_length=1, max_length=96)
    run_id: str = Field(min_length=1, max_length=96)
    trace_id: str = Field(min_length=1, max_length=96)
    sequence: int = Field(ge=1)
    timestamp: str = Field(min_length=20, max_length=40)
    event_type: str = Field(min_length=1, max_length=96)
    source_component: str = Field(min_length=1, max_length=96)
    tool_call_id: str | None = Field(default=None, max_length=96)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_utc_iso8601(cls, value: str) -> str:
        if not value.endswith("Z"):
            raise ValueError("timestamp must use UTC Z notation")
        _ = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
        return value


class ToolResult(StrictModel):
    allowed: bool
    completed: bool
    reason: str
    value: str | None = None


class RiskFactor(StrictModel):
    code: str = Field(min_length=1, max_length=96)
    weight: int = Field(ge=0, le=100)


class RiskAssessment(StrictModel):
    version: Literal["risk-v1"] = "risk-v1"
    score: int = Field(ge=0, le=100)
    band: RiskBand
    factors: tuple[RiskFactor, ...]

    @model_validator(mode="after")
    def score_and_band_must_match_factors(self) -> Self:
        codes = [factor.code for factor in self.factors]
        if len(codes) != len(set(codes)):
            raise ValueError("risk factor codes must be unique")
        expected_score = min(sum(factor.weight for factor in self.factors), 100)
        expected_band = (
            RiskBand.HIGH
            if expected_score >= 80
            else RiskBand.ELEVATED
            if expected_score >= 40
            else RiskBand.LOW
        )
        if self.score != expected_score or self.band is not expected_band:
            raise ValueError("risk score or band does not match factors")
        return self


class PolicyDecision(StrictModel):
    policy_id: Literal["ASL-POLICY"] = "ASL-POLICY"
    policy_version: Literal["policy-v1"] = "policy-v1"
    profile: PolicyProfile
    action: PolicyAction
    reason: str = Field(min_length=1, max_length=96)
    rule_id: str = Field(min_length=1, max_length=96)
    enforcement_layer: EnforcementLayer
    risk: RiskAssessment | None = None

    @model_validator(mode="after")
    def risk_must_match_enforcement_layer(self) -> Self:
        if self.enforcement_layer is EnforcementLayer.SAFETY and self.risk is not None:
            raise ValueError("mandatory safety decisions do not have a risk score")
        if self.enforcement_layer is EnforcementLayer.DEFENSE and self.risk is None:
            raise ValueError("defense decisions require a risk score")
        return self


class ApprovalResponse(StrictModel):
    schema_version: Literal["0.2"] = "0.2"
    approval_id: str = Field(min_length=1, max_length=96)
    run_id: str = Field(min_length=1, max_length=96)
    trace_id: str = Field(min_length=1, max_length=96)
    tool_call_id: str = Field(min_length=1, max_length=96)
    policy_version: Literal["policy-v1"] = "policy-v1"
    approved: bool
    reason: Literal["simulated_approval_granted", "simulated_approval_denied"]

    @model_validator(mode="after")
    def reason_must_match_result(self) -> Self:
        if self.approved != (self.reason == "simulated_approval_granted"):
            raise ValueError("approval result and reason disagree")
        return self


class PreventionResult(StrictModel):
    blocked: bool
    stage: Literal["secret_access", "outbound_transfer"] | None = None
    reason: str | None = Field(default=None, max_length=96)
    evidence_event_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def fields_must_match_blocked_state(self) -> Self:
        if self.blocked and (
            self.stage is None or self.reason is None or len(self.evidence_event_ids) < 4
        ):
            raise ValueError("blocked prevention requires stage, reason, and evidence")
        if not self.blocked and (
            self.stage is not None or self.reason is not None or self.evidence_event_ids
        ):
            raise ValueError("unblocked prevention cannot claim blocking evidence")
        return self


class ImpactResult(StrictModel):
    reached: bool
    evidence_event_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def evidence_must_match_impact_state(self) -> Self:
        if self.reached != bool(self.evidence_event_ids):
            raise ValueError("impact state and evidence disagree")
        return self


class PolicyDecisionEvidence(StrictModel):
    event_id: str
    tool_call_id: str | None
    tool: str
    decision: str
    reason: str
    rule_id: str
    enforcement_layer: EnforcementLayer
    risk: RiskAssessment | None = None


class ApprovalEvidence(StrictModel):
    event_id: str
    tool_call_id: str | None
    approved: bool
    reason: str


class DetectionResult(StrictModel):
    rule_id: str
    rule_version: int
    detected: bool
    severity: Literal["critical"] | None = None
    evidence_event_ids: tuple[str, ...] = ()
    alert_id: str | None = None
    incident_id: str | None = None


class Report(StrictModel):
    schema_version: Literal["0.2"] = "0.2"
    scenario_id: str
    scenario_name: str
    run_id: str
    trace_id: str
    status: Literal["completed"]
    executive_summary: str
    attack_vector: str
    agent_and_tool_actions: tuple[str, ...]
    timeline: tuple[Event, ...]
    evidence_cutoff_sequence: int
    policy_profile: PolicyProfile
    policy_version: Literal["policy-v1"] = "policy-v1"
    risk_version: Literal["risk-v1"] = "risk-v1"
    detection: DetectionResult
    prevention: PreventionResult
    simulated_impact: ImpactResult
    outcome: Outcome
    attempted_impact: str
    root_cause: str
    recommended_remediation: tuple[str, ...]
    safety_and_limitations: tuple[str, ...]


class ComparisonChild(StrictModel):
    profile: PolicyProfile
    run_id: str
    trace_id: str
    relative_directory: str
    report_json: str
    report_markdown: str
    outcome: Outcome
    detected: bool
    simulated_impact: ImpactResult
    prevention: PreventionResult
    policy_decisions: tuple[PolicyDecisionEvidence, ...]
    approval_results: tuple[ApprovalEvidence, ...]
    evidence_references: tuple[str, ...]


class ComparisonReport(StrictModel):
    schema_version: Literal["0.2"] = "0.2"
    comparison_id: str = Field(min_length=1, max_length=96)
    scenario_id: str
    scenario_name: str
    status: Literal["completed"] = "completed"
    policy_version: Literal["policy-v1"] = "policy-v1"
    risk_version: Literal["risk-v1"] = "risk-v1"
    children: tuple[ComparisonChild, ComparisonChild]
    divergence: str
    conclusion: str
    safety_and_limitations: tuple[str, ...]
