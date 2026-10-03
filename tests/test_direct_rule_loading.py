"""Approved direct-rule loading, failure and recorded-result boundaries."""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

import agentsec.detection as detection
import agentsec.resource_loader as resources
import agentsec.runner as runner
from agentsec.adapters import LabHttpSinkAdapter
from agentsec.cli import main
from agentsec.constants import DIRECT_PROMPT_SCENARIO_ID, MAX_REPLAY_EVENTS, MAX_RULE_BYTES
from agentsec.detection import CorrelationDetector
from agentsec.events import EventCollector, EventStore
from agentsec.models import InputChannel
from agentsec.rule_engine import RuleEvaluationLimitExceeded, evaluate_rule
from agentsec.rule_models import DetectionRule

from .helpers import sequential_ids
from .test_direct_correlation_parity import candidate_events
from .test_phase6a_g0_correlation_review import RESOURCES, direct_events


def rule_bytes() -> bytes:
    return (RESOURCES / "rules/asl-corr-003-v1.json").read_bytes()


def fake_resource(monkeypatch: pytest.MonkeyPatch, data: bytes) -> tuple[Mock, Mock, io.BytesIO]:
    stream = io.BytesIO(data)
    resource = Mock()
    resource.open.return_value = stream
    root = Mock()
    root.joinpath.return_value = resource
    root.files_mock = Mock(return_value=root)
    monkeypatch.setattr(resources, "files", root.files_mock)
    monkeypatch.setattr(resources, "load_canary", lambda: "LAB_FAKE_CANARY_TEST_ONLY")
    return root, resource, stream


@pytest.mark.parametrize("over", [False, True])
def test_direct_resource_uses_fixed_path_and_bounded_closed_read(
    monkeypatch: pytest.MonkeyPatch, over: bool
) -> None:
    raw = rule_bytes()
    data = raw + b" " * (MAX_RULE_BYTES - len(raw) + int(over))
    root, resource, stream = fake_resource(monkeypatch, data)
    read = Mock(wraps=stream.read)
    monkeypatch.setattr(stream, "read", read)
    if over:
        with pytest.raises(ValueError, match="direct detection rule exceeds fixed size limit"):
            resources.load_direct_detection_rule()
    else:
        assert resources.load_direct_detection_rule().rule_id == "ASL-CORR-003"
    root.joinpath.assert_called_once_with("rules", "asl-corr-003-v1.json")
    root.files_mock.assert_called_once_with("agentsec.resources")
    resource.open.assert_called_once_with("rb")
    read.assert_called_once_with(MAX_RULE_BYTES + 1)
    assert stream.closed


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff",
        b"{",
        b'{"rule_id":"ASL-CORR-003","rule_id":"OTHER"}',
        b'{"bad":NaN}',
        b'{"bad":Infinity}',
        b'{"bad":"LAB_FAKE_CANARY_TEST_ONLY"}',
        b'{"bad":"\\u004cAB_FAKE_CANARY_TEST_ONLY"}',
        b"[]",
    ],
)
def test_direct_invalid_resource_fails_closed_without_input_echo(
    monkeypatch: pytest.MonkeyPatch, raw: bytes
) -> None:
    _, _, stream = fake_resource(monkeypatch, raw)
    with pytest.raises(ValueError) as caught:
        resources.load_direct_detection_rule()
    assert str(caught.value) in {
        "direct detection rule is not valid UTF-8",
        "direct detection rule failed validation",
    }
    assert stream.closed


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rule_id", "ASL-CORR-999"),
        ("rule_version", 2),
        ("kind", "sequence"),
        ("severity", "high"),
        ("supported_event_versions", ["0.1"]),
        ("steps", []),
    ],
)
def test_direct_resource_metadata_must_match_contract(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    raw = json.loads(rule_bytes())
    raw[field] = value
    if field == "kind":
        raw["joins"] = []
    if field == "steps":
        # Schema-valid step-name mismatch, including its join references.
        raw = json.loads(rule_bytes().replace(b'"prompt"', b'"context"'))
    fake_resource(monkeypatch, json.dumps(raw).encode())
    with pytest.raises(
        ValueError, match="packaged direct detection rule does not match its contract"
    ):
        resources.load_direct_detection_rule()


def test_missing_direct_resource_never_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    events = direct_events()
    _, resource, _ = fake_resource(monkeypatch, b"")
    resource.open.side_effect = FileNotFoundError("synthetic unavailable resource")
    with pytest.raises(FileNotFoundError):
        CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT).evaluate(events)


@pytest.mark.parametrize("escaped", [False, True])
def test_schema_valid_canary_rule_is_rejected_after_decoding(
    monkeypatch: pytest.MonkeyPatch, escaped: bool
) -> None:
    raw = json.loads(rule_bytes())
    raw["description"] = "LAB_FAKE_CANARY_TEST_ONLY"
    data = json.dumps(raw).encode()
    if escaped:
        data = data.replace(b"LAB_FAKE_CANARY_TEST_ONLY", b"\\u004cAB_FAKE_CANARY_TEST_ONLY")
    assert DetectionRule.model_validate_json(data).description == "LAB_FAKE_CANARY_TEST_ONLY"
    fake_resource(monkeypatch, data)
    with pytest.raises(ValueError, match=r"^direct detection rule failed validation$"):
        resources.load_direct_detection_rule()


def test_fresh_direct_evaluation_reloads_fixed_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    events = direct_events()
    load = Mock(wraps=resources.load_direct_detection_rule)
    monkeypatch.setattr(detection, "load_direct_detection_rule", load)
    detector = CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT)
    assert detector.evaluate(events) == detector.evaluate(events)
    assert load.call_count == 2


@pytest.mark.parametrize("field", ["rule_id", "rule_version", "context_delivery_channel"])
def test_fresh_direct_configuration_is_closed(field: str) -> None:
    kwargs: dict[str, object] = {
        "context_event_type": "agent.context.prompt_added",
        "rule_id": "ASL-CORR-003",
        "rule_version": 1,
        "context_delivery_channel": "direct_prompt",
    }
    kwargs[field] = 2 if field == "rule_version" else "unsupported"
    # Construct explicitly to preserve the statically typed public API.
    detector = CorrelationDetector(
        context_event_type=str(kwargs["context_event_type"]),
        rule_id=str(kwargs["rule_id"]),
        rule_version=2 if field == "rule_version" else 1,
        context_delivery_channel=str(kwargs["context_delivery_channel"]),
    )
    with pytest.raises(ValueError, match="unsupported direct detector configuration"):
        detector.evaluate(direct_events())


@pytest.mark.parametrize("over", [False, True])
def test_direct_actual_input_event_ceiling(over: bool) -> None:
    context = direct_events()[0]
    events = [
        context.model_copy(update={"event_id": f"noise_{i}", "event_type": "test.noise"})
        for i in range(MAX_REPLAY_EVENTS + int(over))
    ]
    detector = CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT)
    if over:
        with pytest.raises(RuleEvaluationLimitExceeded, match="event count"):
            detector.evaluate(events)
    else:
        assert not detector.evaluate(events).detected


def test_live_selects_dedup_first_not_chronological_first() -> None:
    context, read, sink = direct_events()
    events = [
        context,
        read.model_copy(update={"event_id": "read_z"}),
        sink.model_copy(update={"event_id": "sink_z"}),
        read.model_copy(
            update={
                "event_id": "read_a",
                "sequence": 4,
                "payload": {**read.payload, "value_sha256": "b" * 64},
            }
        ),
        sink.model_copy(
            update={
                "event_id": "sink_a",
                "sequence": 5,
                "payload": {**sink.payload, "value_sha256": "b" * 64},
            }
        ),
    ]
    expected = (context.event_id, "read_a", "sink_a")
    offline = evaluate_rule(resources.load_direct_detection_rule(), events)
    assert len(offline.matches) == 2 and offline.matches[0].evidence_event_ids == expected
    detector = CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT)
    assert detector.evaluate(events).evidence_event_ids == expected
    assert detector.evaluate(list(reversed(events))).evidence_event_ids == expected


@pytest.mark.parametrize("fault", ["load", "candidate", "match"])
def test_fresh_recording_failure_never_records_partial_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    events = candidate_events(2499) if fault == "candidate" else direct_events()
    if fault == "load":
        fake_resource(monkeypatch, b"{")
    elif fault == "match":
        monkeypatch.setattr("agentsec.rule_engine.MAX_RULE_MATCHES", 0)
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(store, "run_test", "trace_test", id_factory=sequential_ids())
    try:
        with pytest.raises((ValueError, RuleEvaluationLimitExceeded)):
            CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT).evaluate_and_record(
                events, collector
            )
        assert store.events("run_test") == []
    finally:
        store.close()


@pytest.mark.parametrize("recorded", ["match", "no_match", "missing_artifacts"])
def test_recorded_direct_result_reuse_bypasses_fresh_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorded: str
) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(store, "run_test", "trace_test", id_factory=sequential_ids())
    detector = CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT)
    try:
        if recorded == "missing_artifacts":
            collector.emit(
                "detection.match",
                "correlation-detector",
                {
                    "rule_id": "ASL-CORR-003",
                    "rule_version": 1,
                    "severity": "critical",
                    "evidence_event_ids": ["context", "read", "sink"],
                },
            )
        else:
            detector.evaluate_and_record(direct_events() if recorded == "match" else [], collector)
        before = store.events("run_test")
        fresh = Mock(side_effect=AssertionError("recorded results must not reevaluate"))
        monkeypatch.setattr(detector, "evaluate", fresh)
        fake_resource(monkeypatch, b"{")
        result = detector.evaluate_and_record(before, collector)
        again = detector.evaluate_and_record(store.events("run_test"), collector)
        fresh.assert_not_called()
        assert result == again and result.detected is (recorded != "no_match")
        types = [event.event_type for event in store.events("run_test")]
        assert (
            types.count("alert.created") == types.count("incident.created") == int(result.detected)
        )
        if recorded == "missing_artifacts":
            assert types == ["detection.match", "alert.created", "incident.created"]
        else:
            assert store.events("run_test") == before
    finally:
        store.close()


@pytest.mark.parametrize("fault", ["load", "evaluation"])
def test_runner_fault_is_redacted_finalized_and_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fault: str,
) -> None:
    closed: list[EventStore] = []
    cleared: list[LabHttpSinkAdapter] = []
    original_close, original_clear = EventStore.close, LabHttpSinkAdapter.clear

    def close(store: EventStore) -> None:
        original_close(store)
        closed.append(store)

    def clear(sink: LabHttpSinkAdapter) -> None:
        original_clear(sink)
        cleared.append(sink)

    def fail(*_args: object) -> None:
        error = ValueError if fault == "load" else RuleEvaluationLimitExceeded
        raise error(resources.load_canary())

    raw = rule_bytes()
    monkeypatch.setattr(EventStore, "close", close)
    monkeypatch.setattr(LabHttpSinkAdapter, "clear", clear)
    monkeypatch.setattr(
        detection, "load_direct_detection_rule" if fault == "load" else "evaluate_rule", fail
    )
    monkeypatch.setattr(runner, "default_id_factory", sequential_ids())
    code = main(["run", DIRECT_PROMPT_SCENARIO_ID, "--output-dir", str(tmp_path)])
    assert code == (2 if fault == "load" else 1)
    output = capsys.readouterr()
    assert output.out == "" and output.err == (
        "error: invalid input (ValueError)\n"
        if fault == "load"
        else "error: operation failed (RuleEvaluationLimitExceeded)\n"
    )
    assert len(closed) == len(cleared) == 1 and cleared[0].observations == ()
    database = next(tmp_path.glob("*/events.sqlite3"))
    store = EventStore(database)
    try:
        events = store.events(database.parent.name)
        assert events[-1].event_type == "run.failed"
        assert not {
            "detection.match",
            "detection.no_match",
            "alert.created",
            "incident.created",
            "report.created",
            "run.completed",
        } & {e.event_type for e in events}
        assert resources.load_canary() not in json.dumps([e.model_dump() for e in events])
    finally:
        original_close(store)
    assert not list(tmp_path.glob("*/report.*"))
    assert rule_bytes() == raw
