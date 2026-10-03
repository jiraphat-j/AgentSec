"""Remaining C07 candidate and live/offline parity acceptance checks."""

from __future__ import annotations

import pytest

import agentsec.rule_engine as rule_engine
from agentsec.constants import MAX_RULE_CANDIDATES, MAX_RULE_MATCHES
from agentsec.detection import CorrelationDetector
from agentsec.models import Event, InputChannel
from agentsec.rule_engine import RuleEvaluationLimitExceeded, evaluate_rule, load_rules
from agentsec.rule_models import DetectionRule

from .test_phase6a_g0_correlation_review import RESOURCES, detected, direct_events


def direct_rule() -> DetectionRule:
    return next(rule for rule in load_rules(RESOURCES / "rules") if rule.rule_id == "ASL-CORR-003")


@pytest.mark.parametrize(
    "noise",
    [
        "read_classification",
        "read_canary",
        "sink_canary",
        "sink_matched",
        "sink_redacted",
        "sink_digest",
        "context_run",
        "context_trace",
    ],
)
def test_direct_later_valid_chain_survives_earlier_nonmatching_candidate(noise: str) -> None:
    events = [
        event.model_copy(update={"sequence": event.sequence * 2}) for event in direct_events()
    ]
    index = 1 if noise.startswith("read_") else 2 if noise.startswith("sink_") else 0
    original = events[index]
    changes: dict[str, object] = {
        "event_id": "irrelevant_candidate",
        "sequence": original.sequence - 1,
    }
    if noise.startswith("context_"):
        changes["run_id" if noise == "context_run" else "trace_id"] = "unrelated_identity"
    else:
        key, value = {
            "read_classification": ("classification", "public"),
            "read_canary": ("canary_id", "different_canary"),
            "sink_canary": ("canary_id", "different_canary"),
            "sink_matched": ("matched", False),
            "sink_redacted": ("redacted", False),
            "sink_digest": ("value_sha256", "0" * 64),
        }[noise]
        assert original.payload[key] != value
        changes["payload"] = {**original.payload, key: value}
    events.insert(index, original.model_copy(update=changes))
    offline = evaluate_rule(direct_rule(), events)
    expected = tuple(event.event_id for event in events if event.event_id != "irrelevant_candidate")
    assert tuple(match.evidence_event_ids for match in offline.matches) == (expected,)
    live = CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT).evaluate(events)
    assert live.detected, f"Live detector lost the valid chain after {noise}"
    assert live.evidence_event_ids == expected


@pytest.mark.parametrize("engine", ["live", "offline"])
def test_direct_missing_read_and_sink_digests_cannot_establish_matching_transfer(
    engine: str,
) -> None:
    events = direct_events()
    assert detected(engine, events)
    for index in (1, 2):
        payload = dict(events[index].payload)
        payload.pop("value_sha256")
        events[index] = events[index].model_copy(update={"payload": payload})
    assert detected(engine, events) is False, f"{engine} matched absent digests"


@pytest.mark.parametrize("index", [0, 1, 2], ids=["context", "read", "sink"])
def test_direct_live_and_offline_reject_unsupported_event_version(index: int) -> None:
    events = direct_events()
    events[index] = events[index].model_copy(update={"schema_version": "0.1"})
    assert not evaluate_rule(direct_rule(), events).matches
    assert (
        not CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT)
        .evaluate(events)
        .detected
    )


def test_direct_enumerates_distinct_digest_chains_deterministically() -> None:
    context, read, sink = direct_events()
    second_read = read.model_copy(
        update={
            "event_id": "read_second",
            "sequence": 4,
            "payload": {**read.payload, "value_sha256": "b" * 64},
        }
    )
    second_sink = sink.model_copy(
        update={
            "event_id": "sink_second",
            "sequence": 5,
            "payload": {**sink.payload, "value_sha256": "b" * 64},
        }
    )
    assert read.payload["value_sha256"] != "b" * 64
    events = [context, read, sink, second_read, second_sink]
    evaluation = evaluate_rule(direct_rule(), events)
    triples = {match.evidence_event_ids for match in evaluation.matches}
    assert triples == {
        (context.event_id, read.event_id, sink.event_id),
        (context.event_id, second_read.event_id, second_sink.event_id),
    }
    assert evaluate_rule(direct_rule(), list(reversed(events))) == evaluation
    live = CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT).evaluate(events)
    assert live.detected and live.evidence_event_ids in triples


def candidate_events(sink_count: int) -> list[Event]:
    context, read, sink = direct_events()
    return [
        *[
            context.model_copy(update={"event_id": f"context_{index}", "sequence": index + 1})
            for index in range(4)
        ],
        read.model_copy(update={"sequence": 5}),
        *[
            sink.model_copy(update={"event_id": f"sink_{index}", "sequence": index + 6})
            for index in range(sink_count)
        ],
    ]


@pytest.mark.parametrize("over", [False, True])
@pytest.mark.parametrize("engine", ["live", "offline"])
def test_direct_rule_actual_candidate_ceiling_is_explicit(over: bool, engine: str) -> None:
    # Four contexts * (one context visit + one read visit + 2,498 sink visits).
    assert MAX_RULE_CANDIDATES == 4 * (2 + 2498)
    events = candidate_events(2498 + int(over))
    detector = CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT)
    if over:
        with pytest.raises(RuleEvaluationLimitExceeded, match="candidate count"):
            if engine == "live":
                detector.evaluate(events)
            else:
                evaluate_rule(direct_rule(), events)
    else:
        result = evaluate_rule(direct_rule(), events)
        assert result.candidate_count == MAX_RULE_CANDIDATES
        assert len(result.matches) == 4 * 2498 < MAX_RULE_MATCHES
        assert result.duplicate_matches_removed == 0
        if engine == "live":
            assert (
                detector.evaluate(events).evidence_event_ids == result.matches[0].evidence_event_ids
            )


@pytest.mark.parametrize("over", [False, True])
@pytest.mark.parametrize("engine", ["live", "offline"])
def test_direct_rule_match_exhaustion_at_disclosed_reduced_cap(
    monkeypatch: pytest.MonkeyPatch, over: bool, engine: str
) -> None:
    # The actual match ceiling cannot be reached first while candidates have the same ceiling.
    monkeypatch.setattr(rule_engine, "MAX_RULE_MATCHES", 4)
    events = candidate_events(1 + int(over))
    detector = CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT)
    if over:
        with pytest.raises(RuleEvaluationLimitExceeded, match="match count"):
            if engine == "live":
                detector.evaluate(events)
            else:
                evaluate_rule(direct_rule(), events)
    else:
        matches = evaluate_rule(direct_rule(), events).matches
        assert len(matches) == 4
        if engine == "live":
            assert detector.evaluate(events).evidence_event_ids == matches[0].evidence_event_ids
