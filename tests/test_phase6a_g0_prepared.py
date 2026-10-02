"""Prepared Phase 6A G0 security regressions; execute only after owner review."""

from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path

import pytest

from agentsec.constants import DIRECT_PROMPT_SCENARIO_ID
from agentsec.detection import CorrelationDetector
from agentsec.events import EventStore
from agentsec.models import InputChannel, PolicyProfile, PromptFixture
from agentsec.resource_loader import load_canary, load_prompt
from agentsec.rule_engine import evaluate_rule, load_rules
from agentsec.rule_testing import load_rule_fixtures
from agentsec.runner import ScenarioRunner

from .helpers import sequential_ids

RESOURCE_ROOT = Path(__file__).parents[1] / "src" / "agentsec" / "resources"


@pytest.mark.parametrize("profile", [PolicyProfile.VULNERABLE, PolicyProfile.STRICT])
def test_direct_artifacts_exclude_raw_prompt_and_canary(
    tmp_path: Path, profile: PolicyProfile
) -> None:
    result = ScenarioRunner(id_factory=sequential_ids()).run(
        DIRECT_PROMPT_SCENARIO_ID, tmp_path, profile=profile
    )
    forbidden = (
        load_prompt(PromptFixture.MALICIOUS).encode(),
        b"[agentsec:direct-prompt-injection]",
        load_canary().encode(),
    )
    for name in ("events.sqlite3", "report.json", "report.md"):
        data = (result.run_directory / name).read_bytes()
        assert all(value not in data for value in forbidden), name

    store = EventStore(result.run_directory / "events.sqlite3")
    events = store.events(result.run_id, result.trace_id)
    store.close()
    context_index = next(
        index
        for index, event in enumerate(events)
        if event.event_type == "agent.context.prompt_added"
    )
    assert context_index < next(
        index for index, event in enumerate(events) if event.event_type == "tool.requested"
    )
    assert events[context_index].payload == {
        "prompt_id": "malicious",
        "source": "packaged_prompt_fixture",
        "trust": "untrusted",
        "delivery_channel": "direct_prompt",
    }


@pytest.mark.parametrize("profile", [PolicyProfile.VULNERABLE, PolicyProfile.STRICT])
def test_direct_run_uses_no_host_socket_dns_or_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: PolicyProfile
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("host network or process API called")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "system", forbidden)

    result = ScenarioRunner(id_factory=sequential_ids()).run(
        DIRECT_PROMPT_SCENARIO_ID, tmp_path, profile=profile
    )

    assert result.report.outcome == (
        "simulated_impact" if profile is PolicyProfile.VULNERABLE else "prevented"
    )


def test_direct_failure_persists_only_safe_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw_prompt = load_prompt(PromptFixture.MALICIOUS)

    def fail_after_context(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(raw_prompt)

    monkeypatch.setattr("agentsec.runner.DeterministicMockAgent.execute", fail_after_context)
    with pytest.raises(RuntimeError, match="Summarize the supplied request"):
        ScenarioRunner(id_factory=sequential_ids()).run(DIRECT_PROMPT_SCENARIO_ID, tmp_path)

    run_directory = next(tmp_path.iterdir())
    assert not (run_directory / "report.json").exists()
    database = (run_directory / "events.sqlite3").read_bytes()
    for forbidden in (
        raw_prompt.encode(),
        b"[agentsec:direct-prompt-injection]",
        load_canary().encode(),
    ):
        assert forbidden not in database
    store = EventStore(run_directory / "events.sqlite3")
    events = store.events("run_1", "trace_1")
    store.close()
    assert [event.event_type for event in events] == [
        "run.started",
        "agent.context.prompt_added",
        "run.failed",
    ]
    assert events[-1].payload == {"error_type": "RuntimeError", "profile": "vulnerable"}


@pytest.mark.parametrize(
    ("event_index", "field", "value"),
    [
        (0, "trust", "trusted"),
        (0, "delivery_channel", "document"),
        (1, "classification", "public"),
        (1, "canary_id", "wrong_canary"),
        (2, "value_sha256", "wrong_digest"),
        (2, "matched", False),
        (2, "redacted", False),
    ],
)
def test_direct_live_and_offline_rule_reject_same_tampering(
    event_index: int, field: str, value: object
) -> None:
    rule = next(
        item for item in load_rules(RESOURCE_ROOT / "rules") if item.rule_id == "ASL-CORR-003"
    )
    fixture = next(
        item
        for item in load_rule_fixtures(RESOURCE_ROOT / "rule_fixtures")
        if item.name == "asl-corr-003-positive"
    )
    events = list(fixture.events)
    assert (
        CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT).evaluate(events).detected
    )
    assert len(evaluate_rule(rule, events).matches) == 1

    target = events[event_index]
    events[event_index] = target.model_copy(update={"payload": {**target.payload, field: value}})
    assert (
        not CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT)
        .evaluate(events)
        .detected
    )
    assert evaluate_rule(rule, events).matches == ()
