from __future__ import annotations

import json
import sqlite3
from io import BytesIO
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from agentsec import resource_loader
from agentsec.constants import (
    DIRECT_PROMPT_SCENARIO_ID,
    MAX_DOCUMENT_BYTES,
    MAX_EVENT_PAYLOAD_BYTES,
    MAX_OPERATIONAL_EVENTS,
    MAX_SCENARIO_BYTES,
    SCENARIO_ID,
)
from agentsec.events import (
    EventCollector,
    EventLimitExceeded,
    EventPayloadTooLarge,
    EventStore,
    EvidenceLeakError,
)
from agentsec.models import (
    ApprovalResponse,
    DirectPromptScenario,
    DocumentFixture,
    Event,
    EventSchemaVersion,
    PolicyDecision,
    PromptFixture,
    Report,
    Scenario,
)
from agentsec.resource_loader import load_document, load_prompt, load_scenario

from .helpers import fixed_clock, sequential_ids


def test_packaged_scenario_and_document_load() -> None:
    scenario = load_scenario(SCENARIO_ID)
    assert isinstance(scenario, Scenario)

    assert scenario.id == SCENARIO_ID
    assert "agentsec:indirect-prompt-injection" in load_document(scenario.document_fixture)


def test_packaged_direct_prompt_scenario_exposes_only_closed_metadata() -> None:
    scenario = load_scenario(DIRECT_PROMPT_SCENARIO_ID)

    assert isinstance(scenario, DirectPromptScenario)
    assert scenario.id == DIRECT_PROMPT_SCENARIO_ID
    assert scenario.input_channel.value == "direct_prompt"
    assert "agentsec:direct-prompt-injection" in load_prompt(scenario.input_fixture)


def test_scenario_loader_rejects_unlisted_id() -> None:
    with pytest.raises(ValueError, match="unknown scenario"):
        load_scenario("unlisted-scenario")


@pytest.mark.parametrize("scenario_id", [SCENARIO_ID, DIRECT_PROMPT_SCENARIO_ID])
def test_scenario_loader_rejects_ambiguous_invalid_or_substituted_resources(
    scenario_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = load_scenario(scenario_id)
    valid = original.model_dump(mode="json")
    expected_name = (
        "indirect-injection-secret-exfiltration.json"
        if scenario_id == SCENARIO_ID
        else "direct-prompt-injection-secret-exfiltration.json"
    )

    class FakeResource:
        def __init__(self, data: bytes) -> None:
            self.data = data

        def joinpath(self, *parts: str) -> FakeResource:
            assert parts == ("scenarios", expected_name)
            return self

        def open(self, _mode: str) -> BytesIO:
            return BytesIO(self.data)

    resource = FakeResource(b"")
    monkeypatch.setattr(resource_loader, "files", lambda _package: resource)
    invalid: list[tuple[bytes, str]] = [
        (b"\xff", "UTF-8"),
        (b"x" * (MAX_SCENARIO_BYTES + 1), "size limit"),
        (b"{", "valid JSON"),
        (json.dumps({**valid, "id": "substituted"}).encode(), "identity"),
        (json.dumps({**valid, "schema_version": "9.9"}).encode(), ""),
        (json.dumps({**valid, "adapter": "host"}).encode(), ""),
        (json.dumps({**valid, "timeout_seconds": 5.5}).encode(), ""),
        (b'{"id":"first","id":"second"}', "duplicate"),
        (b'{"timeout_seconds":NaN}', "non-finite"),
    ]
    if scenario_id == DIRECT_PROMPT_SCENARIO_ID:
        invalid.extend(
            [
                (json.dumps({**valid, "input_channel": "document"}).encode(), ""),
                (json.dumps({**valid, "input_fixture": "external"}).encode(), ""),
            ]
        )
    for data, message in invalid:
        resource.data = data
        with pytest.raises((ValueError, ValidationError), match=message or None):
            load_scenario(scenario_id)


@pytest.mark.parametrize(
    ("data", "message"),
    [(b"\xff", "UTF-8"), (b"x" * (MAX_DOCUMENT_BYTES + 1), "size limit")],
)
def test_prompt_loader_rejects_invalid_or_oversized_text(
    data: bytes, message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeResource:
        def joinpath(self, *parts: str) -> FakeResource:
            assert parts == ("prompts", "malicious.txt")
            return self

        def open(self, _mode: str) -> BytesIO:
            return BytesIO(data)

    monkeypatch.setattr(resource_loader, "files", lambda _package: FakeResource())
    with pytest.raises(ValueError, match=message):
        load_prompt(PromptFixture.MALICIOUS)


@pytest.mark.parametrize(
    ("data", "message"),
    [(b"\xff", "UTF-8"), (b"x" * (MAX_DOCUMENT_BYTES + 1), "size limit")],
)
def test_legacy_document_loader_rejects_invalid_or_oversized_text(
    data: bytes, message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeResource:
        def joinpath(self, *parts: str) -> FakeResource:
            assert parts == ("documents", "malicious.txt")
            return self

        def open(self, _mode: str) -> BytesIO:
            return BytesIO(data)

    monkeypatch.setattr(resource_loader, "files", lambda _package: FakeResource())
    with pytest.raises(ValueError, match=message):
        load_document(DocumentFixture.MALICIOUS)


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


def test_legacy_event_version_remains_readable_and_unknown_version_fails() -> None:
    legacy = {
        "schema_version": "0.1",
        "event_id": "evt_1",
        "run_id": "run_1",
        "trace_id": "trace_1",
        "sequence": 1,
        "timestamp": "2026-09-08T12:00:00Z",
        "event_type": "run.started",
        "source_component": "controller",
        "payload": {},
    }

    assert Event.model_validate(legacy).schema_version == "0.1"
    with pytest.raises(ValidationError):
        Event.model_validate({**legacy, "schema_version": "9.9"})


def test_collector_can_explicitly_emit_legacy_but_rejects_unknown_version(
    tmp_path: Path,
) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(
        store,
        "run_1",
        "trace_1",
        schema_version="0.1",
        id_factory=sequential_ids(),
    )

    assert collector.emit("run.started", "controller").schema_version == "0.1"
    with pytest.raises(ValueError, match="unsupported"):
        EventCollector(
            store,
            "run_2",
            "trace_2",
            schema_version=cast(EventSchemaVersion, "9.9"),
        )
    store.close()


def test_phase_2_contract_examples_validate() -> None:
    root = Path(__file__).parents[1] / "examples" / "contracts"

    legacy = Event.model_validate_json(
        (root / "event-legacy-v0.1.json").read_text(encoding="utf-8")
    )
    vulnerable = PolicyDecision.model_validate_json(
        (root / "policy-vulnerable-allowed.json").read_text(encoding="utf-8")
    )
    strict = PolicyDecision.model_validate_json(
        (root / "policy-strict-denied.json").read_text(encoding="utf-8")
    )
    approval = ApprovalResponse.model_validate_json(
        (root / "approval-simulated.json").read_text(encoding="utf-8")
    )
    approved = ApprovalResponse.model_validate_json(
        (root / "approval-simulated-approved.json").read_text(encoding="utf-8")
    )
    safety = PolicyDecision.model_validate_json(
        (root / "policy-safety-denied.json").read_text(encoding="utf-8")
    )
    unavailable = PolicyDecision.model_validate_json(
        (root / "policy-approval-unavailable.json").read_text(encoding="utf-8")
    )
    phase_2_event = Event.model_validate_json(
        (root / "event-policy-denied-v0.2.json").read_text(encoding="utf-8")
    )
    report = Report.model_validate_json(
        (root / "report-v0.2-prevented.json").read_text(encoding="utf-8")
    )

    assert legacy.schema_version == "0.1"
    assert vulnerable.profile.value == "vulnerable"
    assert strict.reason == "secret_read_blocked"
    assert approval.approved is False
    assert approved.approved is True
    assert safety.enforcement_layer.value == "safety"
    assert unavailable.reason == "approval_unavailable"
    assert phase_2_event.schema_version == "0.2"
    assert report.outcome == "prevented"
