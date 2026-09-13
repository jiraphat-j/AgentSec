"""Evidence-backed Phase 4 incident derivation and offline investigation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from time import monotonic
from typing import Literal

from .constants import (
    CANARY_ID,
    CORRELATION_RULE_ID,
    CORRELATION_RULE_VERSION,
    EVIDENCE_FINGERPRINT_VERSION,
    MAX_DERIVED_ALERTS,
    MAX_INVESTIGATION_TRACES,
    RULESET_FINGERPRINT_VERSION,
)
from .events import default_id_factory
from .evidence import fingerprint_rules, fingerprint_snapshot, validate_snapshot
from .incident_models import (
    AlertCategory,
    DerivedAlert,
    EvidenceReference,
    HistoricalTiming,
    Incident,
    InvestigationReport,
    OutcomeAssessment,
    StageLabel,
    StageObservation,
    TimelineEntry,
)
from .models import Event
from .outcomes import derive_impact, derive_prevention
from .replay import _safe_source_name, read_replay_evidence
from .rule_engine import evaluate_rule, load_rules
from .rule_models import DetectionMatch, DetectionRule, SourceStatus

_DERIVED_TYPES = {
    "detection.match",
    "detection.no_match",
    "alert.created",
    "incident.created",
    "report.created",
}
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True, slots=True)
class InvestigationResult:
    investigation_directory: Path
    report: InvestigationReport
    events: tuple[Event, ...]


def _reference(event: Event, snapshot_fingerprint: str) -> EvidenceReference:
    return EvidenceReference(
        snapshot_fingerprint=snapshot_fingerprint,
        run_id=event.run_id,
        trace_id=event.trace_id,
        event_id=event.event_id,
        sequence=event.sequence,
    )


def _category(rule_id: str) -> AlertCategory:
    return (
        AlertCategory.CONTROL_OBSERVATION
        if rule_id == "ASL-EVENT-001"
        else AlertCategory.SUSPICIOUS_ACTIVITY
    )


def _alert(
    match: DetectionMatch,
    events_by_id: dict[str, Event],
    snapshot_fingerprint: str,
    rule_set_fingerprint: str,
) -> DerivedAlert:
    evidence_events: list[Event] = []
    for event_id in match.evidence_event_ids:
        event = events_by_id.get(event_id)
        if event is None:
            raise ValueError("detection match references missing evidence")
        if event.run_id != match.run_id or event.trace_id != match.trace_id:
            raise ValueError("detection match references evidence outside its run or trace")
        evidence_events.append(event)
    return DerivedAlert(
        stable_key=f"{snapshot_fingerprint}:{rule_set_fingerprint}:{match.dedup_key}",
        category=_category(match.rule_id),
        rule_id=match.rule_id,
        rule_version=match.rule_version,
        engine_version=match.engine_version,
        severity=match.severity,
        description=match.description,
        run_id=match.run_id,
        trace_id=match.trace_id,
        evidence=tuple(_reference(event, snapshot_fingerprint) for event in evidence_events),
    )


def _stage_for_event(event: Event) -> StageLabel | None:
    if (
        event.event_type == "agent.context.document_added"
        and event.payload.get("trust") == "untrusted"
    ):
        return StageLabel.UNTRUSTED_CONTEXT
    if event.event_type == "tool.requested":
        if event.payload.get("tool") == "http_post":
            return StageLabel.OUTBOUND_ATTEMPT
        return StageLabel.TOOL_REQUEST
    if event.event_type == "file.read" and event.payload.get("classification") == "secret":
        return StageLabel.SECRET_ACCESS
    if (
        event.event_type == "lab.sink.payload_recorded"
        and event.payload.get("matched") is True
        and event.payload.get("redacted") is True
        and event.payload.get("canary_id") == CANARY_ID
        and event.payload.get("observed_in") == "http_request_body"
    ):
        return StageLabel.SIMULATED_IMPACT
    if event.event_type == "policy.denied" and event.payload.get("enforcement_layer") == "defense":
        return StageLabel.DEFENSE_DENIAL
    return None


def _outcome(
    trace_events: list[Event],
    source_status: SourceStatus,
    snapshot_fingerprint: str,
) -> OutcomeAssessment:
    impact = derive_impact(trace_events)
    prevention = derive_prevention(trace_events)
    secret_access = any(
        event.event_type == "file.read" and event.payload.get("classification") == "secret"
        for event in trace_events
    )
    outbound_attempt = any(
        event.event_type == "tool.requested" and event.payload.get("tool") == "http_post"
        for event in trace_events
    )
    evidence_ids = tuple(
        dict.fromkeys((*impact.evidence_event_ids, *prevention.evidence_event_ids))
    )
    by_id = {event.event_id: event for event in trace_events}
    references = tuple(
        _reference(by_id[event_id], snapshot_fingerprint) for event_id in evidence_ids
    )
    if source_status is not SourceStatus.COMPLETED:
        return OutcomeAssessment(
            source_status=source_status,
            outcome="unknown",
            simulated_impact=True if impact.reached else None,
            prevention=True if prevention.blocked else None,
            secret_access_observed=secret_access,
            outbound_attempt_observed=outbound_attempt,
            evidence=references,
        )
    outcome: Literal[
        "simulated_impact", "prevented", "no_correlated_chain", "inconsistent", "unknown"
    ]
    if impact.reached and prevention.blocked:
        outcome = "inconsistent"
    elif impact.reached:
        outcome = "simulated_impact"
    elif prevention.blocked:
        outcome = "prevented"
    else:
        outcome = "no_correlated_chain"
    return OutcomeAssessment(
        source_status=source_status,
        outcome=outcome,
        simulated_impact=impact.reached,
        prevention=prevention.blocked,
        secret_access_observed=secret_access,
        outbound_attempt_observed=outbound_attempt,
        evidence=references,
    )


def _explanation(
    category: AlertCategory, outcome: OutcomeAssessment
) -> tuple[str, tuple[str, ...]]:
    remediation = (
        "Treat document content as untrusted data rather than tool instructions.",
        "Require policy authorization for classified-resource access and outbound actions.",
        "Investigate the linked event sequence and verify the simulated asset scope.",
    )
    if outcome.outcome == "simulated_impact":
        cause = (
            "The evidence supports the hypothesis that untrusted document instructions preceded "
            "classified-resource access and matching fake-canary transfer to the in-process sink."
        )
    elif outcome.outcome == "prevented":
        cause = (
            "The evidence supports the hypothesis that untrusted document instructions proposed "
            "a sensitive action which the strict defense policy denied before simulated impact."
        )
    elif category is AlertCategory.CONTROL_OBSERVATION:
        cause = (
            "A defense-policy denial was observed. This control observation alone does not prove "
            "malicious intent, prevention, or impact."
        )
    else:
        cause = (
            "The evidence contains suspicious ordered behavior, but does not establish matching "
            "fake-canary simulated impact."
        )
    return cause, remediation


def _historical_timing(events: tuple[Event, ...]) -> HistoricalTiming:
    by_id = {event.event_id: event for event in events}
    matches = [
        event
        for event in events
        if event.event_type == "detection.match"
        and event.source_component == "correlation-detector"
        and event.payload.get("rule_id") == CORRELATION_RULE_ID
    ]
    if not matches:
        return HistoricalTiming(exclusion_reason="legacy_detection_unavailable")
    for match in matches:
        ids = match.payload.get("evidence_event_ids")
        if (
            type(match.payload.get("rule_version")) is not int
            or match.payload["rule_version"] != CORRELATION_RULE_VERSION
            or not isinstance(ids, list)
            or len(ids) != 3
            or any(type(item) is not str for item in ids)
            or len(set(ids)) != 3
            or any(item not in by_id for item in ids)
        ):
            continue
        document, secret_read, sink = (by_id[item] for item in ids)
        chain = (document, secret_read, sink, match)
        if (
            any(item.run_id != match.run_id or item.trace_id != match.trace_id for item in chain)
            or [item.sequence for item in chain] != sorted(item.sequence for item in chain)
            or document.event_type != "agent.context.document_added"
            or document.payload.get("trust") != "untrusted"
            or secret_read.event_type != "file.read"
            or secret_read.payload.get("classification") != "secret"
            or secret_read.payload.get("canary_id") != CANARY_ID
            or sink.event_type != "lab.sink.payload_recorded"
            or sink.payload.get("canary_id") != CANARY_ID
            or sink.payload.get("matched") is not True
            or sink.payload.get("redacted") is not True
            or sink.payload.get("observed_in") != "http_request_body"
            or not isinstance(secret_read.payload.get("value_sha256"), str)
            or not secret_read.payload["value_sha256"]
            or sink.payload.get("value_sha256") != secret_read.payload.get("value_sha256")
        ):
            continue
        alerts = [
            event
            for event in events
            if event.event_type == "alert.created"
            and event.source_component == "alert-builder"
            and event.run_id == match.run_id
            and event.trace_id == match.trace_id
            and event.sequence > match.sequence
            and event.payload.get("rule_id") == CORRELATION_RULE_ID
            and event.payload.get("evidence_event_ids") == ids
            and isinstance(event.payload.get("alert_id"), str)
            and bool(event.payload["alert_id"])
        ]
        for alert in alerts:
            incident = next(
                (
                    event
                    for event in events
                    if event.event_type == "incident.created"
                    and event.source_component == "incident-builder"
                    and event.run_id == match.run_id
                    and event.trace_id == match.trace_id
                    and event.sequence > alert.sequence
                    and event.payload.get("alert_id") == alert.payload["alert_id"]
                    and isinstance(event.payload.get("incident_id"), str)
                    and bool(event.payload["incident_id"])
                    and event.payload.get("evidence_event_ids") == ids
                ),
                None,
            )
            if incident is None:
                continue
            try:
                times = [
                    datetime.fromisoformat(item.timestamp) for item in (*chain, alert, incident)
                ]
            except ValueError:
                return HistoricalTiming(exclusion_reason="timestamp_invalid")
            if any(item.utcoffset() != timedelta(0) for item in times):
                return HistoricalTiming(exclusion_reason="timestamp_invalid")
            if times != sorted(times):
                return HistoricalTiming(exclusion_reason="clock_order_invalid")
            return HistoricalTiming(
                alert_seconds=(times[-2] - times[0]).total_seconds(),
                incident_seconds=(times[-1] - times[0]).total_seconds(),
            )
    return HistoricalTiming(exclusion_reason="legacy_linkage_invalid")


def build_investigation(
    *,
    investigation_id: str,
    source_file: str,
    events: list[Event],
    source_status: SourceStatus,
    rules: tuple[DetectionRule, ...],
    local_processing_seconds: float,
) -> InvestigationReport:
    snapshot = validate_snapshot(events, source_status)
    snapshot_fingerprint = fingerprint_snapshot(snapshot)
    rule_set_fingerprint = fingerprint_rules(rules)
    evaluated_events = [
        event
        for event in snapshot.events
        if not event.event_type.startswith("detection.")
        and event.event_type not in {"alert.created", "incident.created", "report.created"}
    ]
    events_by_id = {event.event_id: event for event in snapshot.events}
    evaluations = []
    alert_items: list[DerivedAlert] = []
    for rule in sorted(rules, key=lambda item: (item.rule_id, item.rule_version)):
        evaluation = evaluate_rule(rule, evaluated_events)
        if len(alert_items) + len(evaluation.matches) > MAX_DERIVED_ALERTS:
            raise RuntimeError("derived alert count exceeds fixed limit")
        evaluations.append(evaluation)
        alert_items.extend(
            _alert(match, events_by_id, snapshot_fingerprint, rule_set_fingerprint)
            for match in evaluation.matches
        )
    alerts = tuple(alert_items)
    traces = sorted({alert.trace_id for alert in alerts})
    if len(traces) > MAX_INVESTIGATION_TRACES:
        raise RuntimeError("incident trace count exceeds fixed limit")
    incidents: list[Incident] = []
    for trace_id in traces:
        trace_alerts = tuple(alert for alert in alerts if alert.trace_id == trace_id)
        trace_events = [event for event in snapshot.events if event.trace_id == trace_id]
        direct_ids = {reference.event_id for alert in trace_alerts for reference in alert.evidence}
        evidence_events = sorted(
            (events_by_id[event_id] for event_id in direct_ids), key=lambda event: event.sequence
        )
        stage_events: dict[StageLabel, list[Event]] = {}
        for event in trace_events:
            stage = _stage_for_event(event)
            if stage is not None:
                stage_events.setdefault(stage, []).append(event)
        stages = tuple(
            StageObservation(
                stage=stage,
                evidence=tuple(
                    _reference(event, snapshot_fingerprint) for event in stage_events[stage]
                ),
            )
            for stage in StageLabel
            if stage in stage_events
        )
        assessment = _outcome(trace_events, source_status, snapshot_fingerprint)
        category = (
            AlertCategory.SUSPICIOUS_ACTIVITY
            if any(alert.category is AlertCategory.SUSPICIOUS_ACTIVITY for alert in trace_alerts)
            else AlertCategory.CONTROL_OBSERVATION
        )
        cause, remediation = _explanation(category, assessment)
        incidents.append(
            Incident(
                stable_key=(
                    f"{snapshot_fingerprint}:{rule_set_fingerprint}:{snapshot.run_id}:{trace_id}"
                ),
                category=category,
                severity=max(
                    (alert.severity for alert in trace_alerts),
                    key=lambda severity: _SEVERITY_ORDER[severity],
                ),
                run_id=snapshot.run_id,
                trace_id=trace_id,
                alerts=tuple(
                    sorted(
                        trace_alerts,
                        key=lambda alert: (
                            alert.rule_id,
                            alert.rule_version,
                            alert.stable_key,
                        ),
                    )
                ),
                evidence=tuple(
                    _reference(event, snapshot_fingerprint) for event in evidence_events
                ),
                stages=stages,
                outcome=assessment,
                timeline=tuple(
                    TimelineEntry(
                        evidence=_reference(event, snapshot_fingerprint),
                        timestamp=event.timestamp,
                        event_type=event.event_type,
                        source_component=event.source_component,
                        direct_match_evidence=event.event_id in direct_ids,
                        historical_derived_event=event.event_type in _DERIVED_TYPES,
                    )
                    for event in trace_events
                ),
                root_cause_hypothesis=cause,
                recommended_remediation=remediation,
            )
        )
    return InvestigationReport(
        investigation_id=investigation_id,
        source_file=source_file,
        source_run_id=snapshot.run_id,
        source_status=source_status,
        evidence_cutoff_sequence=snapshot.evidence_cutoff_sequence,
        snapshot_fingerprint_version=EVIDENCE_FINGERPRINT_VERSION,
        snapshot_fingerprint=snapshot_fingerprint,
        rule_set_fingerprint_version=RULESET_FINGERPRINT_VERSION,
        rule_set_fingerprint=rule_set_fingerprint,
        input_event_count=len(snapshot.events),
        evaluated_event_count=len(evaluated_events),
        rule_evaluations=tuple(evaluations),
        derived_alerts=tuple(
            sorted(
                alerts,
                key=lambda alert: (alert.rule_id, alert.rule_version, alert.stable_key),
            )
        ),
        incidents=tuple(incidents),
        historical_timing=_historical_timing(snapshot.events),
        local_processing_seconds=local_processing_seconds,
        safety_and_limitations=(
            "Investigation is an offline derivation from one local evidence snapshot.",
            "Snapshot fingerprints detect content changes but do not authenticate origin.",
            "Root-cause text is a deterministic hypothesis, not an automated attribution.",
            "Offline processing duration is not historical MTTD or MTTI.",
        ),
    )


class InvestigationService:
    def __init__(
        self,
        *,
        id_factory: Callable[[str], str] = default_id_factory,
        monotonic_clock: Callable[[], float] = monotonic,
    ) -> None:
        self._id_factory = id_factory
        self._monotonic_clock = monotonic_clock

    def investigate(
        self,
        source: Path,
        run_id: str,
        rules_directory: Path,
        output_directory: Path,
    ) -> InvestigationResult:
        from .incident_reporting import write_investigation_report

        rules = load_rules(rules_directory)
        evidence = read_replay_evidence(source, run_id)
        started = self._monotonic_clock()
        report = build_investigation(
            investigation_id=self._id_factory("investigation"),
            source_file=_safe_source_name(source),
            events=evidence.events,
            source_status=evidence.source_status,
            rules=rules,
            local_processing_seconds=0,
        )
        elapsed = max(self._monotonic_clock() - started, 0.0)
        report = report.model_copy(update={"local_processing_seconds": elapsed})
        output_directory.mkdir(parents=True, exist_ok=True)
        investigation_directory = output_directory / report.investigation_id
        investigation_directory.mkdir(exist_ok=False)
        write_investigation_report(report, investigation_directory)
        return InvestigationResult(investigation_directory, report, tuple(evidence.events))
