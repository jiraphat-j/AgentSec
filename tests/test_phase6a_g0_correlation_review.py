"""C07 repair regressions; changed runtime requires the Phase 6A human-review gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.constants import VIRTUAL_SECRET_PATH
from agentsec.detection import CorrelationDetector
from agentsec.models import Event, InputChannel
from agentsec.rule_engine import evaluate_rule, load_rules
from agentsec.rule_testing import load_rule_fixtures

RESOURCES = Path(__file__).parents[1] / "src/agentsec/resources"


def direct_events() -> list[Event]:
    fixture = next(
        item
        for item in load_rule_fixtures(RESOURCES / "rule_fixtures")
        if item.name == "asl-corr-003-positive"
    )
    assert fixture.events[1].payload["resource"] == VIRTUAL_SECRET_PATH
    return list(fixture.events)


def detected(engine: str, events: list[Event]) -> bool:
    if engine == "live":
        return (
            CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT)
            .evaluate(events)
            .detected
        )
    rule = next(rule for rule in load_rules(RESOURCES / "rules") if rule.rule_id == "ASL-CORR-003")
    return bool(evaluate_rule(rule, events).matches)


@pytest.mark.parametrize("engine", ["live", "offline"])
@pytest.mark.parametrize(
    "mutation", ["wrong_path", "missing_path", "prompt_source", "read_source", "sink_source"]
)
def test_direct_c07_rejects_wrong_resource_or_source(engine: str, mutation: str) -> None:
    events = direct_events()
    assert detected(engine, events)
    if mutation == "wrong_path":
        read = events[1]
        events[1] = read.model_copy(
            update={"payload": {**read.payload, "resource": "workspace/public.txt"}}
        )
    elif mutation == "missing_path":
        read = events[1]
        payload = dict(read.payload)
        payload.pop("resource")
        events[1] = read.model_copy(update={"payload": payload})
    else:
        index = {"prompt_source": 0, "read_source": 1, "sink_source": 2}[mutation]
        events[index] = events[index].model_copy(update={"source_component": "untrusted-input"})

    assert detected(engine, events) is False, f"C07 {engine} accepted {mutation} evidence"


@pytest.mark.parametrize("noise", ["wrong_path", "prompt_source", "read_source", "sink_source"])
def test_direct_c07_invalid_candidate_does_not_hide_later_valid_evidence(noise: str) -> None:
    events = [
        event.model_copy(update={"sequence": event.sequence * 2}) for event in direct_events()
    ]
    index = {"wrong_path": 1, "prompt_source": 0, "read_source": 1, "sink_source": 2}[noise]
    original = events[index]
    changes: dict[str, object] = {
        "event_id": "invalid_candidate",
        "sequence": original.sequence - 1,
    }
    if noise == "wrong_path":
        changes["payload"] = {**original.payload, "resource": "workspace/public.txt"}
    else:
        changes["source_component"] = "untrusted-input"
    events.insert(index, original.model_copy(update=changes))
    live = CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT).evaluate(events)
    rule = next(rule for rule in load_rules(RESOURCES / "rules") if rule.rule_id == "ASL-CORR-003")
    offline = evaluate_rule(rule, events)
    assert live.detected and len(offline.matches) == 1
    assert live.evidence_event_ids == offline.matches[0].evidence_event_ids
    assert "invalid_candidate" not in live.evidence_event_ids


def test_direct_c07_valid_chain_has_exact_live_offline_parity() -> None:
    events = direct_events()
    live = CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT).evaluate(events)
    rule = next(rule for rule in load_rules(RESOURCES / "rules") if rule.rule_id == "ASL-CORR-003")
    offline = evaluate_rule(rule, events)
    assert live.detected and len(offline.matches) == 1
    assert live.rule_id == offline.rule_id == "ASL-CORR-003"
    assert live.rule_version == offline.rule_version == 1
    assert (
        live.evidence_event_ids
        == offline.matches[0].evidence_event_ids
        == tuple(event.event_id for event in events)
    )


def test_direct_c07_does_not_tighten_historical_indirect_detector() -> None:
    fixture = next(
        item
        for item in load_rule_fixtures(RESOURCES / "rule_fixtures")
        if item.name == "asl-corr-002-positive"
    )
    events = []
    for event in fixture.events:
        payload = dict(event.payload)
        payload.pop("resource", None)
        events.append(
            event.model_copy(
                update={"source_component": "historical-component", "payload": payload}
            )
        )
    result = CorrelationDetector.for_input_channel(InputChannel.DOCUMENT).evaluate(events)
    assert result.detected and result.rule_id == "ASL-CORR-001" and result.rule_version == 1
