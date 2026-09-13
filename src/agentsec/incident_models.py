"""Strict Phase 4 investigation and incident contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from .constants import (
    INCIDENT_CORRELATOR_VERSION,
    INCIDENT_TEMPLATE_VERSION,
    INVESTIGATION_SCHEMA_VERSION,
    MAX_DERIVED_ALERTS,
    MAX_INVESTIGATION_TRACES,
    MAX_TIMELINE_ENTRIES,
)
from .models import StrictModel
from .rule_models import RuleEvaluation, SourceStatus


class AlertCategory(StrEnum):
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    CONTROL_OBSERVATION = "control_observation"


class StageLabel(StrEnum):
    UNTRUSTED_CONTEXT = "untrusted_context"
    TOOL_REQUEST = "tool_request"
    SECRET_ACCESS = "secret_access"
    OUTBOUND_ATTEMPT = "outbound_attempt"
    SIMULATED_IMPACT = "simulated_impact"
    DEFENSE_DENIAL = "defense_denial"


class EvidenceReference(StrictModel):
    snapshot_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str = Field(min_length=1, max_length=96)
    trace_id: str = Field(min_length=1, max_length=96)
    event_id: str = Field(min_length=1, max_length=96)
    sequence: int = Field(ge=1)


class TimelineEntry(StrictModel):
    evidence: EvidenceReference
    timestamp: str = Field(min_length=20, max_length=40)
    event_type: str = Field(min_length=1, max_length=96)
    source_component: str = Field(min_length=1, max_length=96)
    direct_match_evidence: bool
    historical_derived_event: bool


class StageObservation(StrictModel):
    stage: StageLabel
    evidence: tuple[EvidenceReference, ...] = Field(min_length=1, max_length=MAX_TIMELINE_ENTRIES)


class DerivedAlert(StrictModel):
    stable_key: str = Field(min_length=1, max_length=4096)
    origin: Literal["offline_derived"] = "offline_derived"
    category: AlertCategory
    rule_id: str = Field(min_length=1, max_length=96)
    rule_version: int = Field(ge=1)
    engine_version: str = Field(min_length=1, max_length=96)
    severity: Literal["low", "medium", "high", "critical"]
    description: str = Field(min_length=1, max_length=240)
    run_id: str = Field(min_length=1, max_length=96)
    trace_id: str = Field(min_length=1, max_length=96)
    evidence: tuple[EvidenceReference, ...] = Field(min_length=1, max_length=8)


class OutcomeAssessment(StrictModel):
    source_status: SourceStatus
    outcome: Literal[
        "simulated_impact",
        "prevented",
        "no_correlated_chain",
        "inconsistent",
        "unknown",
    ]
    simulated_impact: bool | None
    prevention: bool | None
    secret_access_observed: bool
    outbound_attempt_observed: bool
    evidence: tuple[EvidenceReference, ...] = Field(max_length=MAX_TIMELINE_ENTRIES)

    @model_validator(mode="after")
    def outcome_must_match_facts(self) -> Self:
        if self.source_status is not SourceStatus.COMPLETED and self.outcome != "unknown":
            raise ValueError("non-completed evidence requires an unknown outcome")
        if self.source_status is SourceStatus.COMPLETED and (
            self.outcome == "unknown" or self.simulated_impact is None or self.prevention is None
        ):
            raise ValueError("completed evidence requires a known outcome and boolean facts")
        if self.outcome == "simulated_impact" and (
            self.simulated_impact is not True or self.prevention is not False
        ):
            raise ValueError("simulated-impact outcome requires impact evidence")
        if self.outcome == "prevented" and (
            self.prevention is not True or self.simulated_impact is not False
        ):
            raise ValueError("prevention outcome requires prevention without impact")
        if self.outcome == "inconsistent" and not (
            self.simulated_impact is True and self.prevention is True
        ):
            raise ValueError("inconsistent outcome requires impact and prevention")
        if self.outcome == "no_correlated_chain" and (
            self.simulated_impact is not False or self.prevention is not False
        ):
            raise ValueError("no-chain outcome cannot claim impact or prevention")
        return self


class Incident(StrictModel):
    stable_key: str = Field(min_length=1, max_length=4096)
    correlator_version: Literal["incident-v1"] = INCIDENT_CORRELATOR_VERSION
    template_version: Literal["templates-v1"] = INCIDENT_TEMPLATE_VERSION
    status: Literal["new"] = "new"
    category: AlertCategory
    severity: Literal["low", "medium", "high", "critical"]
    run_id: str = Field(min_length=1, max_length=96)
    trace_id: str = Field(min_length=1, max_length=96)
    alerts: tuple[DerivedAlert, ...] = Field(min_length=1, max_length=MAX_DERIVED_ALERTS)
    evidence: tuple[EvidenceReference, ...] = Field(min_length=1, max_length=MAX_TIMELINE_ENTRIES)
    stages: tuple[StageObservation, ...]
    outcome: OutcomeAssessment
    timeline: tuple[TimelineEntry, ...] = Field(max_length=MAX_TIMELINE_ENTRIES)
    root_cause_hypothesis: str = Field(min_length=1, max_length=480)
    recommended_remediation: tuple[str, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def contents_must_share_identity(self) -> Self:
        if any(
            alert.run_id != self.run_id or alert.trace_id != self.trace_id for alert in self.alerts
        ):
            raise ValueError("incident alerts must share the incident run and trace")
        identities = [reference.event_id for reference in self.evidence]
        if len(identities) != len(set(identities)):
            raise ValueError("incident evidence must be unique")
        references = [
            *(reference for alert in self.alerts for reference in alert.evidence),
            *self.evidence,
            *(reference for stage in self.stages for reference in stage.evidence),
            *self.outcome.evidence,
            *(entry.evidence for entry in self.timeline),
        ]
        snapshots = {reference.snapshot_fingerprint for reference in references}
        if len(snapshots) != 1 or any(
            reference.run_id != self.run_id or reference.trace_id != self.trace_id
            for reference in references
        ):
            raise ValueError("incident references must share one snapshot, run, and trace")
        return self


class HistoricalTiming(StrictModel):
    basis: Literal["recorded_legacy"] = "recorded_legacy"
    alert_seconds: float | None = Field(default=None, ge=0)
    incident_seconds: float | None = Field(default=None, ge=0)
    exclusion_reason: str | None = Field(default=None, max_length=96)

    @model_validator(mode="after")
    def result_or_reason_is_required(self) -> Self:
        if (self.alert_seconds is None) != (self.incident_seconds is None):
            raise ValueError("recorded timing requires both alert and incident intervals")
        if self.alert_seconds is None:
            if self.exclusion_reason is None:
                raise ValueError("unavailable timing requires an exclusion reason")
        elif self.exclusion_reason is not None:
            raise ValueError("available timing cannot have an exclusion reason")
        return self


class InvestigationReport(StrictModel):
    schema_version: Literal["1.0"] = INVESTIGATION_SCHEMA_VERSION
    investigation_id: str = Field(min_length=1, max_length=96)
    status: Literal["completed"] = "completed"
    source_file: str = Field(min_length=1, max_length=255)
    source_run_id: str = Field(min_length=1, max_length=96)
    source_status: SourceStatus
    evidence_cutoff_sequence: int = Field(ge=1)
    snapshot_fingerprint_version: Literal["evidence-snapshot-v1"]
    snapshot_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    rule_set_fingerprint_version: Literal["rule-set-v1"]
    rule_set_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_event_count: int = Field(ge=1)
    evaluated_event_count: int = Field(ge=0)
    rule_evaluations: tuple[RuleEvaluation, ...]
    derived_alerts: tuple[DerivedAlert, ...] = Field(max_length=MAX_DERIVED_ALERTS)
    incidents: tuple[Incident, ...] = Field(max_length=MAX_INVESTIGATION_TRACES)
    historical_timing: HistoricalTiming
    local_processing_seconds: float = Field(ge=0)
    safety_and_limitations: tuple[str, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def summaries_must_resolve(self) -> Self:
        if self.evaluated_event_count > self.input_event_count:
            raise ValueError("evaluated events exceed input events")
        alert_keys = [alert.stable_key for alert in self.derived_alerts]
        if len(alert_keys) != len(set(alert_keys)):
            raise ValueError("derived alert identities must be unique")
        incident_keys = [incident.stable_key for incident in self.incidents]
        if len(incident_keys) != len(set(incident_keys)):
            raise ValueError("incident identities must be unique")
        nested = [alert.stable_key for incident in self.incidents for alert in incident.alerts]
        if sorted(nested) != sorted(alert_keys):
            raise ValueError("every derived alert must belong to exactly one incident")
        if any(incident.run_id != self.source_run_id for incident in self.incidents):
            raise ValueError("investigation incidents must belong to the source run")
        if any(
            reference.snapshot_fingerprint != self.snapshot_fingerprint
            for alert in self.derived_alerts
            for reference in alert.evidence
        ):
            raise ValueError("derived-alert references must use the report snapshot")
        rule_identities = [
            (evaluation.rule_id, evaluation.rule_version) for evaluation in self.rule_evaluations
        ]
        if len(rule_identities) != len(set(rule_identities)):
            raise ValueError("investigation rule evaluations must be unique")
        return self
