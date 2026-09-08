from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.constants import MAX_EVENT_PAYLOAD_BYTES, MAX_OPERATIONAL_EVENTS, SCENARIO_ID
from agentsec.events import (
    EventCollector,
    EventLimitExceeded,
    EventPayloadTooLarge,
    EventStore,
    EvidenceLeakError,
)
from agentsec.models import Scenario
from agentsec.resource_loader import load_document, load_scenario

from .helpers import fixed_clock, sequential_ids


def test_packaged_scenario_and_document_load() -> None:
    scenario = load_scenario(SCENARIO_ID)

    assert scenario.id == SCENARIO_ID
    assert "agentsec:indirect-prompt-injection" in load_document(scenario.document_fixture)


def test_scenario_rejects_unknown_fields() -> None:
    raw = json.dumps(
        {
            "schema_version": "0.1",
            "id": SCENARIO_ID,
            "name": "Invalid",
            "document_fixture": "malicious",
            "timeout_seconds": 5,
            "adapter": "attacker-selected",
        }
    )

    with pytest.raises(ValidationError):
        Scenario.model_validate_json(raw)


def test_event_store_reopens_and_orders_equal_timestamps(tmp_path: Path) -> None:
    database = tmp_path / "events.sqlite3"
    store = EventStore(database)
    collector = EventCollector(
        store,
        "run_1",
        "trace_1",
        id_factory=sequential_ids(),
        clock=fixed_clock,
    )
    first = collector.emit("run.started", "controller")
    second = collector.emit("agent.context.document_added", "controller")
    store.close()

    reopened = EventStore(database)
    events = reopened.events("run_1")
    reopened.close()

    assert [event.event_id for event in events] == [first.event_id, second.event_id]
    assert events[0].timestamp == events[1].timestamp
    assert [event.sequence for event in events] == [1, 2]


def test_event_table_rejects_update_and_delete(tmp_path: Path) -> None:
    database = tmp_path / "events.sqlite3"
    store = EventStore(database)
    collector = EventCollector(store, "run_1", "trace_1", id_factory=sequential_ids())
    collector.emit("run.started", "controller")
    store.close()
    connection = sqlite3.connect(database)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("UPDATE events SET event_type = 'forged'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("DELETE FROM events")
    connection.close()


def test_collector_rejects_raw_canary_before_persistence(tmp_path: Path) -> None:
    raw_canary = "LAB_FAKE_CANARY_test"
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(
        store,
        "run_1",
        "trace_1",
        forbidden_values=(raw_canary,),
        id_factory=sequential_ids(),
    )

    with pytest.raises(EvidenceLeakError):
        collector.emit("unsafe", "test", {"value": raw_canary})

    assert store.events("run_1") == []
    store.close()


def test_payload_cannot_override_trusted_envelope(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(store, "run_trusted", "trace_trusted", id_factory=sequential_ids())
    event = collector.emit(
        "tool.requested",
        "tool-gateway",
        {"event_type": "policy.allowed", "run_id": "attacker"},
    )
    store.close()

    assert event.event_type == "tool.requested"
    assert event.run_id == "run_trusted"
    assert event.payload["event_type"] == "policy.allowed"


def test_event_payload_and_count_are_bounded(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(store, "run_1", "trace_1", id_factory=sequential_ids())

    with pytest.raises(EventPayloadTooLarge):
        collector.emit("large", "test", {"data": "x" * MAX_EVENT_PAYLOAD_BYTES})
    for _ in range(MAX_OPERATIONAL_EVENTS):
        collector.emit("bounded", "test")
    with pytest.raises(EventLimitExceeded):
        collector.emit("overflow", "test")
    final = collector.emit("run.failed", "controller", finalization=True)
    store.close()

    assert final.sequence == MAX_OPERATIONAL_EVENTS + 1
