"""Validated logical evidence snapshots and deterministic provenance fingerprints."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass

from .constants import (
    EVIDENCE_FINGERPRINT_VERSION,
    RULESET_FINGERPRINT_VERSION,
    SUITE_FINGERPRINT_VERSION,
)
from .models import Event
from .rule_models import DetectionRule, SourceStatus


class EvidenceConsistencyError(ValueError):
    """Raised when source lifecycle or identity evidence is contradictory."""


@dataclass(frozen=True, slots=True)
class ValidatedSnapshot:
    events: tuple[Event, ...]
    source_status: SourceStatus
    run_id: str
    evidence_cutoff_sequence: int


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _validate_json_value(value: object) -> None:
    if value is None or type(value) in {str, bool, int}:
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EvidenceConsistencyError("source snapshot contains a non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str:
                raise EvidenceConsistencyError("source snapshot contains a non-string JSON key")
            _validate_json_value(item)
        return
    raise EvidenceConsistencyError("source snapshot contains a non-JSON value")


def _validate_relevant_payload(event: Event) -> None:
    payload = event.payload
    string_fields: dict[str, tuple[str, ...]] = {
        "run.started": ("scenario_id", "fixture", "profile", "policy_version"),
        "agent.context.document_added": ("document_id", "source", "trust"),
        "tool.requested": ("tool",),
        "file.read": ("classification", "canary_id", "value_sha256"),
        "lab.sink.payload_recorded": ("canary_id", "value_sha256", "observed_in"),
        "policy.denied": (
            "tool",
            "profile",
            "policy_id",
            "policy_version",
            "decision",
            "reason",
            "enforcement_layer",
        ),
        "detection.match": ("rule_id",),
        "alert.created": ("alert_id", "rule_id"),
        "incident.created": ("incident_id", "alert_id"),
    }
    bool_fields: dict[str, tuple[str, ...]] = {
        "lab.sink.payload_recorded": ("matched", "redacted"),
        "run.completed": ("detected", "prevented", "simulated_impact"),
    }
    for field in string_fields.get(event.event_type, ()):
        if field in payload and (type(payload[field]) is not str or not payload[field]):
            raise EvidenceConsistencyError("source event contains a malformed relevant payload")
    for field in bool_fields.get(event.event_type, ()):
        if field in payload and type(payload[field]) is not bool:
            raise EvidenceConsistencyError("source event contains a malformed relevant payload")
    if event.event_type in {"file.read", "lab.sink.payload_recorded"}:
        required = ("canary_id", "value_sha256")
        if any(field not in payload for field in required):
            raise EvidenceConsistencyError("source event lacks required relevant payload")
    if event.event_type == "detection.match":
        ids = payload.get("evidence_event_ids")
        if (
            type(payload.get("rule_version")) is not int
            or payload["rule_version"] < 1
            or not isinstance(ids, list)
            or not ids
            or any(type(item) is not str or not item for item in ids)
            or len(ids) != len(set(ids))
        ):
            raise EvidenceConsistencyError("source detection contains malformed evidence links")


def validate_snapshot(events: list[Event], source_status: SourceStatus) -> ValidatedSnapshot:
    if not events:
        raise EvidenceConsistencyError("source snapshot contains no events")
    ordered = tuple(sorted(events, key=lambda event: event.sequence))
    event_ids = [event.event_id for event in ordered]
    sequences = [event.sequence for event in ordered]
    if len(event_ids) != len(set(event_ids)) or len(sequences) != len(set(sequences)):
        raise EvidenceConsistencyError("source snapshot contains duplicate evidence identities")
    for event in ordered:
        _validate_json_value(event.payload)
        _validate_relevant_payload(event)
    run_ids = {event.run_id for event in ordered}
    if len(run_ids) != 1:
        raise EvidenceConsistencyError("source snapshot contains multiple runs")
    starts = [event for event in ordered if event.event_type == "run.started"]
    completed = [event for event in ordered if event.event_type == "run.completed"]
    failed = [event for event in ordered if event.event_type == "run.failed"]
    if len(starts) > 1:
        raise EvidenceConsistencyError("source snapshot contains duplicate run starts")
    if len(starts) != 1 or starts[0].sequence != ordered[0].sequence:
        raise EvidenceConsistencyError("source snapshot requires one initial run start")
    if source_status is SourceStatus.COMPLETED:
        if len(starts) != 1 or len(completed) != 1 or failed:
            raise EvidenceConsistencyError("completed source has invalid lifecycle evidence")
        if completed[0].sequence != ordered[-1].sequence:
            raise EvidenceConsistencyError(
                "completed source contains evidence after its terminal event"
            )
    elif source_status is SourceStatus.FAILED:
        if len(starts) != 1 or len(failed) != 1 or completed:
            raise EvidenceConsistencyError("failed source has invalid lifecycle evidence")
        if failed[0].sequence != ordered[-1].sequence:
            raise EvidenceConsistencyError(
                "failed source contains evidence after its terminal event"
            )
    elif completed or failed:
        raise EvidenceConsistencyError("incomplete source contains terminal evidence")
    return ValidatedSnapshot(
        events=ordered,
        source_status=source_status,
        run_id=ordered[0].run_id,
        evidence_cutoff_sequence=ordered[-1].sequence,
    )


def fingerprint_snapshot(snapshot: ValidatedSnapshot) -> str:
    return _sha256(
        {
            "version": EVIDENCE_FINGERPRINT_VERSION,
            "run_id": snapshot.run_id,
            "source_status": snapshot.source_status.value,
            "evidence_cutoff_sequence": snapshot.evidence_cutoff_sequence,
            "events": [event.model_dump(mode="json") for event in snapshot.events],
        }
    )


def fingerprint_rules(rules: tuple[DetectionRule, ...]) -> str:
    ordered = sorted(rules, key=lambda rule: (rule.rule_id, rule.rule_version))
    identities = [(rule.rule_id, rule.rule_version) for rule in ordered]
    if len(identities) != len(set(identities)):
        raise EvidenceConsistencyError("rule set contains duplicate identities")
    return _sha256(
        {
            "version": RULESET_FINGERPRINT_VERSION,
            "rules": [rule.model_dump(mode="json") for rule in ordered],
        }
    )


def fingerprint_suite(suite_data: object) -> str:
    return _sha256({"version": SUITE_FINGERPRINT_VERSION, "suite": suite_data})
