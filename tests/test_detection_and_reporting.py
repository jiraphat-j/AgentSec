from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.constants import CANARY_ID, MAX_REPORT_BYTES
from agentsec.detection import CorrelationDetector
from agentsec.events import EventCollector, EventStore
from agentsec.models import DetectionResult, DocumentFixture, Event, Scenario
from agentsec.outcomes import derive_impact, derive_prevention
from agentsec.reporting import (
    ReportWriteError,
    build_report,
    render_markdown,
    write_reports,
)

from .helpers import sequential_ids


def add_attack_evidence(collector: EventCollector, *, matched: bool = True) -> None:
    collector.emit("agent.context.document_added", "controller", {"trust": "untrusted"})
    collector.emit(
        "file.read",
        "fake-file-adapter",
        {"classification": "secret", "canary_id": CANARY_ID, "value_sha256": "digest"},
    )
    collector.emit(
        "lab.sink.payload_recorded",
        "lab-http-sink-adapter",
        {"canary_id": CANARY_ID, "value_sha256": "digest", "matched": matched},
    )


def test_positive_detection_records_one_idempotent_incident(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(store, "run_1", "trace_1", id_factory=sequential_ids())
    add_attack_evidence(collector)
    detector = CorrelationDetector()

    first = detector.evaluate_and_record(store.events("run_1"), collector)
    second = detector.evaluate_and_record(store.events("run_1"), collector)
    events = store.events("run_1")
    store.close()

    assert first.detected and second.detected
    assert first.evidence_event_ids == second.evidence_event_ids
    assert sum(event.event_type == "incident.created" for event in events) == 1


def test_incomplete_or_unmatched_chain_does_not_detect(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(store, "run_1", "trace_1", id_factory=sequential_ids())
    add_attack_evidence(collector, matched=False)

    result = CorrelationDetector().evaluate(store.events("run_1"))
    store.close()

    assert not result.detected


def test_wrong_order_or_digest_does_not_detect(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(store, "run_1", "trace_1", id_factory=sequential_ids())
    collector.emit(
        "lab.sink.payload_recorded",
        "lab-http-sink-adapter",
        {"canary_id": CANARY_ID, "value_sha256": "other", "matched": True},
    )
    collector.emit("agent.context.document_added", "controller", {"trust": "untrusted"})
    collector.emit(
        "file.read",
        "fake-file-adapter",
        {"classification": "secret", "canary_id": CANARY_ID, "value_sha256": "digest"},
    )

    result = CorrelationDetector().evaluate(store.events("run_1"))
    store.close()

    assert not result.detected


def test_cross_trace_events_do_not_correlate(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    ids = sequential_ids()
    first = EventCollector(store, "run_1", "trace_1", id_factory=ids)
    first.emit("agent.context.document_added", "controller", {"trust": "untrusted"})
    second = EventCollector(store, "run_1", "trace_2", id_factory=ids)
    second.emit(
        "file.read",
        "fake-file-adapter",
        {"classification": "secret", "canary_id": CANARY_ID, "value_sha256": "digest"},
    )
    second.emit(
        "lab.sink.payload_recorded",
        "lab-http-sink-adapter",
        {"canary_id": CANARY_ID, "value_sha256": "digest", "matched": True},
    )

    result = CorrelationDetector().evaluate(store.events("run_1"))
    store.close()

    assert not result.detected


def test_markdown_contains_required_sections_and_escapes_name() -> None:
    scenario = Scenario(
        id="scenario",
        name="Hostile <script> *heading*",
        document_fixture=DocumentFixture.BENIGN,
        timeout_seconds=5,
    )
    report = build_report(
        scenario,
        "run_1",
        "trace_1",
        [],
        DetectionResult(rule_id="ASL-CORR-001", rule_version=1, detected=False),
    )

    markdown = render_markdown(report)

    for heading in (
        "Executive summary",
        "Attack vector",
        "Agent and tool actions",
        "Timeline",
        "Detection",
        "Evidence references",
        "Attempted impact",
        "Root cause",
        "Recommended remediation",
        "Safety and limitations",
    ):
        assert f"## {heading}" in markdown
    assert "<script>" not in markdown


def test_report_writer_refuses_overwrite_and_oversized_output(tmp_path: Path) -> None:
    scenario = Scenario(
        id="scenario",
        name="Report test",
        document_fixture=DocumentFixture.BENIGN,
        timeout_seconds=5,
    )
    detection = DetectionResult(rule_id="ASL-CORR-001", rule_version=1, detected=False)
    normal = build_report(scenario, "run_1", "trace_1", [], detection)
    (tmp_path / "report.json").write_text("existing", encoding="utf-8")
    with pytest.raises(ReportWriteError, match="overwrite"):
        write_reports(normal, tmp_path)
    (tmp_path / "report.json").unlink()
    huge_event = Event(
        event_id="evt_1",
        run_id="run_1",
        trace_id="trace_1",
        sequence=1,
        timestamp="2026-09-08T12:00:00Z",
        event_type="test.large",
        source_component="test",
        payload={"data": "x" * MAX_REPORT_BYTES},
    )
    oversized = normal.model_copy(update={"timeline": (huge_event,)})
    with pytest.raises(ReportWriteError, match="size"):
        write_reports(oversized, tmp_path)


def test_safety_denial_and_benign_run_are_not_prevention(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(store, "run_1", "trace_1", id_factory=sequential_ids())
    collector.emit("agent.context.document_added", "controller", {"trust": "untrusted"})
    collector.emit(
        "tool.requested",
        "tool-gateway",
        {"tool": "http_post"},
        tool_call_id="call_1",
    )
    collector.emit(
        "policy.evaluated",
        "runtime-policy",
        {"tool": "http_post", "enforcement_layer": "safety"},
        tool_call_id="call_1",
    )
    collector.emit(
        "policy.denied",
        "runtime-policy",
        {
            "tool": "http_post",
            "enforcement_layer": "safety",
            "reason": "external_destination",
        },
        tool_call_id="call_1",
    )
    events = store.events("run_1")
    store.close()

    assert not derive_prevention(events).blocked
    assert not derive_impact(events).reached
    assert not derive_prevention([]).blocked


def test_prevention_requires_ordered_policy_evidence_and_no_effect(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(store, "run_1", "trace_1", id_factory=sequential_ids())
    collector.emit("agent.context.document_added", "controller", {"trust": "untrusted"})
    collector.emit(
        "tool.requested",
        "tool-gateway",
        {"tool": "read_file"},
        tool_call_id="call_1",
    )
    collector.emit(
        "policy.evaluated",
        "runtime-policy",
        {
            "tool": "read_file",
            "profile": "strict",
            "policy_id": "ASL-POLICY",
            "policy_version": "policy-v1",
            "decision": "deny",
            "enforcement_layer": "defense",
            "rule_id": "POL-FILE-001",
            "reason": "secret_read_blocked",
        },
        tool_call_id="call_1",
    )
    collector.emit(
        "policy.denied",
        "runtime-policy",
        {
            "tool": "read_file",
            "profile": "strict",
            "policy_id": "ASL-POLICY",
            "policy_version": "policy-v1",
            "decision": "deny",
            "enforcement_layer": "defense",
            "rule_id": "POL-FILE-001",
            "reason": "secret_read_blocked",
        },
        tool_call_id="call_1",
    )
    events = store.events("run_1")
    prevention = derive_prevention(events)
    for field, value in (
        ("tool", "http_post"),
        ("decision", "allow"),
        ("enforcement_layer", "safety"),
        ("rule_id", "POL-DIFFERENT"),
    ):
        inconsistent = list(events)
        evaluated = inconsistent[2]
        inconsistent[2] = evaluated.model_copy(
            update={"payload": {**evaluated.payload, field: value}}
        )
        assert not derive_prevention(inconsistent).blocked
    store.close()

    assert prevention.blocked
    assert prevention.stage == "secret_access"
    assert len(prevention.evidence_event_ids) == 4
    for sequence, (event_type, source, payload) in enumerate(
        (
            (
                "policy.allowed",
                "runtime-policy",
                {"tool": "read_file", "decision": "allow"},
            ),
            (
                "tool.executed",
                "tool-gateway",
                {"tool": "read_file", "status": "dispatched"},
            ),
            (
                "file.read",
                "fake-file-adapter",
                {"classification": "secret"},
            ),
        ),
        start=5,
    ):
        contradiction = events[-1].model_copy(
            update={
                "event_id": f"event_{sequence}",
                "sequence": sequence,
                "event_type": event_type,
                "source_component": source,
                "payload": payload,
            }
        )
        assert not derive_prevention([*events, contradiction]).blocked
