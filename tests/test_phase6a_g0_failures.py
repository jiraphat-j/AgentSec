"""Sandbox-only G0 failure, cleanup, host-I/O, and direct-policy regressions."""

from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import agentsec.runner as runner_module
from agentsec.adapters import LabHttpSinkAdapter, VirtualFileAdapter
from agentsec.approvals import ApprovalSimulator
from agentsec.cli import main
from agentsec.constants import (
    CANARY_ID,
    DIRECT_PROMPT_SCENARIO_ID,
    LAB_SINK_DESTINATION,
    MAX_EVENT_PAYLOAD_BYTES,
    MAX_EVENTS,
    MAX_OPERATIONAL_EVENTS,
    MAX_TOOL_BODY_BYTES,
    MAX_TOOL_REQUESTS,
    VIRTUAL_SECRET_PATH,
)
from agentsec.events import EventCollector, EventLimitExceeded, EventPayloadTooLarge, EventStore
from agentsec.gateway import ToolGateway
from agentsec.models import (
    ApprovalSimulation,
    Event,
    InputChannel,
    PolicyAction,
    PolicyProfile,
    PromptFixture,
    RiskAssessment,
    RiskBand,
)
from agentsec.policy import PolicyEvaluator
from agentsec.resource_loader import load_canary, load_prompt
from agentsec.risk import assess_risk
from agentsec.runner import ScenarioRunner

from .helpers import sequential_ids


def assert_redacted(directory: Path, logs: str = "") -> None:
    forbidden = (
        load_canary(),
        load_prompt(PromptFixture.MALICIOUS),
        "[agentsec:direct-prompt-injection]",
    )
    values = [logs]
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        assert all(value.encode() not in raw for value in forbidden), path.name
        if path.suffix == ".json":
            values.append(json.dumps(json.loads(raw), ensure_ascii=False))
        if path.suffix == ".sqlite3":
            with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as connection:
                values.extend(
                    json.dumps(json.loads(row[0]), ensure_ascii=False)
                    for row in connection.execute("SELECT payload_json FROM events")
                )
    assert all(value not in text for text in values for value in forbidden)


@pytest.mark.parametrize("profile", list(PolicyProfile))
def test_direct_host_file_operations_stay_in_packaged_resources_and_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: PolicyProfile
) -> None:
    resources = Path(__file__).parents[1] / "src/agentsec/resources"
    opened: list[Path] = []
    original_builtin = builtins.open
    original_io = io.open
    original_os = os.open

    def check(file: object) -> None:
        if isinstance(file, int):
            return
        assert isinstance(file, (str, bytes, os.PathLike))
        path = Path(os.fsdecode(file)).absolute()
        assert path.is_relative_to(resources) or path.is_relative_to(tmp_path), path
        opened.append(path)

    def builtin_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        check(file)
        return original_builtin(file, *args, **kwargs)

    def io_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        check(file)
        return original_io(file, *args, **kwargs)

    def os_open(file: Any, *args: Any, **kwargs: Any) -> int:
        check(file)
        return original_os(file, *args, **kwargs)

    with monkeypatch.context() as active:
        active.setattr(builtins, "open", builtin_open)
        active.setattr(io, "open", io_open)
        active.setattr(os, "open", os_open)
        result = ScenarioRunner().run(DIRECT_PROMPT_SCENARIO_ID, tmp_path, profile=profile)
    assert opened
    assert any(path.name == "malicious.txt" for path in opened)
    assert all(path.name != ".env" for path in opened)
    assert result.report.outcome == (
        "prevented" if profile is PolicyProfile.STRICT else "simulated_impact"
    )


@pytest.mark.parametrize(
    "fault,profile",
    [
        (fault, PolicyProfile.VULNERABLE)
        for fault in ("file", "sink", "store", "report", "finalization")
    ]
    + [(fault, PolicyProfile.STRICT) for fault in ("store", "report")],
)
def test_direct_cli_failure_closes_store_clears_sink_and_redacts_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fault: str,
    profile: PolicyProfile,
) -> None:
    stores: list[EventStore] = []
    sinks: list[LabHttpSinkAdapter] = []
    closed: list[EventStore] = []
    cleared: list[LabHttpSinkAdapter] = []
    unsafe_error = load_prompt(PromptFixture.MALICIOUS) + load_canary()

    class TrackedStore(EventStore):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            stores.append(self)

        def _append(self, event: Event) -> None:
            if fault == "store" and event.event_type == "tool.requested":
                raise OSError(unsafe_error)
            if fault == "finalization" and event.event_type == "run.failed":
                raise OSError(unsafe_error)
            super()._append(event)

        def close(self) -> None:
            super().close()
            closed.append(self)

    class TrackedSink(LabHttpSinkAdapter):
        def __init__(self, canary_id: str, canary_value: str, value_sha256: str) -> None:
            super().__init__(canary_id, canary_value, value_sha256)
            sinks.append(self)

        def clear(self) -> None:
            super().clear()
            cleared.append(self)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError(unsafe_error)

    original_replace = Path.replace

    def fail_second_publication(path: Path, target: Path) -> Path:
        if path.name == ".report.md.tmp":
            raise OSError(unsafe_error)
        return original_replace(path, target)

    monkeypatch.setattr(runner_module, "EventStore", TrackedStore)
    monkeypatch.setattr(runner_module, "LabHttpSinkAdapter", TrackedSink)
    if fault in {"file", "finalization"}:
        monkeypatch.setattr(VirtualFileAdapter, "read", fail)
    elif fault == "sink":
        monkeypatch.setattr(LabHttpSinkAdapter, "record", fail)
    elif fault == "report":
        monkeypatch.setattr(Path, "replace", fail_second_publication)
    assert (
        main(
            [
                "run",
                DIRECT_PROMPT_SCENARIO_ID,
                "--profile",
                profile.value,
                "--output-dir",
                str(tmp_path),
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "error: operation failed (ReportWriteError)\n"
        if fault == "report"
        else "error: operation failed (OSError)\n"
    )
    assert len(stores) == len(closed) == len(sinks) == len(cleared) == 1
    assert stores == closed and sinks == cleared
    assert sinks[0].observations == ()
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        stores[0].events("not-a-run")
    assert not list(tmp_path.rglob("report.json"))
    assert not list(tmp_path.rglob("report.md"))
    assert not list(tmp_path.rglob("*.tmp"))
    assert_redacted(tmp_path, captured.out + captured.err)
    source = next(tmp_path.rglob("events.sqlite3"))
    with closing(sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True)) as connection:
        event_types = [row[0] for row in connection.execute("SELECT event_type FROM events")]
    assert "run.completed" not in event_types and "report.created" not in event_types
    assert ("run.failed" in event_types) is (fault != "finalization")


@pytest.mark.parametrize("profile", list(PolicyProfile))
@pytest.mark.parametrize("elapsed", [5.0, 5.001])
def test_direct_deadline_at_and_over_bound_has_safe_finalization(
    tmp_path: Path, profile: PolicyProfile, elapsed: float
) -> None:
    ticks = iter([0.0])

    def clock() -> float:
        return next(ticks, elapsed)

    runner = ScenarioRunner(id_factory=sequential_ids(), monotonic_clock=clock)
    if elapsed == 5.0:
        assert (
            runner.run(DIRECT_PROMPT_SCENARIO_ID, tmp_path, profile=profile).report.status
            == "completed"
        )
    else:
        with pytest.raises(runner_module.ScenarioDeadlineExceeded, match="deadline"):
            runner.run(DIRECT_PROMPT_SCENARIO_ID, tmp_path, profile=profile)
        assert not list(tmp_path.rglob("report.json"))
        reader = EventStore(next(tmp_path.rglob("events.sqlite3")))
        try:
            assert [event.event_type for event in reader.events("run_1")] == [
                "run.started",
                "run.failed",
            ]
        finally:
            reader.close()
    assert_redacted(tmp_path)


def test_operational_finalization_and_payload_limits_at_and_over_actual_caps(
    tmp_path: Path,
) -> None:
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(store, "run_1", "trace_1", id_factory=sequential_ids())
    overhead = len(json.dumps({"data": ""}, separators=(",", ":")).encode())
    data = "x" * (MAX_EVENT_PAYLOAD_BYTES - overhead)
    exact: dict[str, object] = {"data": data}
    try:
        collector.emit("test.at_payload_cap", "test", exact)
        with pytest.raises(EventPayloadTooLarge, match="payload"):
            collector.emit("test.over_payload_cap", "test", {"data": data + "x"})
        for _ in range(MAX_OPERATIONAL_EVENTS - 1):
            collector.emit("test.operational", "test")
        with pytest.raises(EventLimitExceeded, match="ceiling"):
            collector.emit("test.over_operational", "test")
        for _ in range(MAX_EVENTS - MAX_OPERATIONAL_EVENTS):
            collector.emit("test.finalization", "test", finalization=True)
        with pytest.raises(EventLimitExceeded, match="ceiling"):
            collector.emit("test.over_finalization", "test", finalization=True)
        assert len(store.events("run_1")) == MAX_EVENTS
    finally:
        store.close()


def direct_gateway(
    tmp_path: Path, profile: PolicyProfile, approval: ApprovalSimulation
) -> tuple[ToolGateway, LabHttpSinkAdapter, EventStore]:
    canary = load_canary()
    digest = hashlib.sha256(canary.encode()).hexdigest()
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(
        store, "run_1", "trace_1", forbidden_values=(canary,), id_factory=sequential_ids()
    )
    sink = LabHttpSinkAdapter(CANARY_ID, canary, digest)
    gateway = ToolGateway(
        collector,
        VirtualFileAdapter(canary),
        sink,
        digest,
        canary,
        profile=profile,
        context_origin=InputChannel.DIRECT_PROMPT,
        approval_simulator=ApprovalSimulator(approval),
        call_id_factory=lambda: "call_test",
    )
    return gateway, sink, store


@pytest.mark.parametrize("profile", list(PolicyProfile))
def test_direct_gateway_actual_body_and_request_caps(
    tmp_path: Path, profile: PolicyProfile
) -> None:
    gateway, sink, store = direct_gateway(tmp_path, profile, ApprovalSimulation.APPROVE)
    try:
        assert gateway.invoke(
            "http_post", {"destination": LAB_SINK_DESTINATION, "body": "x" * MAX_TOOL_BODY_BYTES}
        ).completed
        over = gateway.invoke(
            "http_post",
            {"destination": LAB_SINK_DESTINATION, "body": "x" * (MAX_TOOL_BODY_BYTES + 1)},
        )
        assert not over.allowed and over.reason == "body_too_large"
        for _ in range(MAX_TOOL_REQUESTS - 2):
            assert gateway.invoke(
                "http_post", {"destination": LAB_SINK_DESTINATION, "body": "safe"}
            ).completed
        over_count = gateway.invoke(
            "http_post", {"destination": LAB_SINK_DESTINATION, "body": "safe"}
        )
        assert not over_count.allowed and over_count.reason == "tool_action_limit"
        assert len(sink.observations) == MAX_TOOL_REQUESTS - 1
    finally:
        sink.clear()
        store.close()
    assert_redacted(tmp_path)


@pytest.mark.parametrize("profile", list(PolicyProfile))
@pytest.mark.parametrize("case", ["path", "external", "tool", "forged_origin", "forged_trust"])
def test_direct_gateway_mandatory_safety_precedes_risk_and_approval(
    tmp_path: Path, profile: PolicyProfile, case: str
) -> None:
    gateway, sink, store = direct_gateway(tmp_path, profile, ApprovalSimulation.APPROVE)
    tool, arguments = {
        "path": ("read_file", {"path": "../../host-secret"}),
        "external": ("http_post", {"destination": "https://example.invalid", "body": "safe"}),
        "tool": ("shell", {"command": "never-executed"}),
        "forged_origin": ("read_file", {"path": VIRTUAL_SECRET_PATH, "context_origin": "document"}),
        "forged_trust": ("read_file", {"path": VIRTUAL_SECRET_PATH, "trust": "trusted"}),
    }[case]
    try:
        assert not gateway.invoke(tool, arguments).allowed
        events = store.events("run_1")
        assert [event.event_type for event in events] == [
            "tool.requested",
            "policy.evaluated",
            "policy.denied",
        ]
        assert events[1].payload["enforcement_layer"] == "safety"
        assert events[1].payload["risk"] is None
        assert sink.observations == ()
    finally:
        store.close()


@pytest.mark.parametrize("approval", list(ApprovalSimulation))
def test_direct_safe_post_approval_does_not_claim_canary_impact(
    tmp_path: Path, approval: ApprovalSimulation
) -> None:
    gateway, sink, store = direct_gateway(tmp_path, PolicyProfile.STRICT, approval)
    try:
        result = gateway.invoke("http_post", {"destination": LAB_SINK_DESTINATION, "body": "safe"})
        assert result.completed is (approval is ApprovalSimulation.APPROVE)
        events = store.events("run_1")
        risk = events[1].payload["risk"]
        assert risk["version"] == "risk-v2" and risk["context_origin"] == "direct_prompt"
        assert risk["score"] == 60
        assert any(event.event_type == "approval.simulated" for event in events)
        assert all(not observation.matched for observation in sink.observations)
    finally:
        store.close()


@pytest.mark.parametrize("channel", list(InputChannel))
@pytest.mark.parametrize("profile", list(PolicyProfile))
@pytest.mark.parametrize(
    "case", ["low", "untrusted", "post", "untrusted_post", "secret", "untrusted_secret", "canary"]
)
def test_risk_policy_matrix_preserves_historical_and_direct_semantics(
    channel: InputChannel, profile: PolicyProfile, case: str
) -> None:
    tool, untrusted, secret, matched, score, band, strict_action = {
        "low": ("read_file", False, False, False, 0, RiskBand.LOW, PolicyAction.ALLOW),
        "untrusted": ("read_file", True, False, False, 20, RiskBand.LOW, PolicyAction.ALLOW),
        "post": (
            "http_post",
            False,
            False,
            False,
            40,
            RiskBand.ELEVATED,
            PolicyAction.REQUIRE_APPROVAL,
        ),
        "untrusted_post": (
            "http_post",
            True,
            False,
            False,
            60,
            RiskBand.ELEVATED,
            PolicyAction.REQUIRE_APPROVAL,
        ),
        "secret": ("read_file", False, True, False, 60, RiskBand.ELEVATED, PolicyAction.DENY),
        "untrusted_secret": ("read_file", True, True, False, 80, RiskBand.HIGH, PolicyAction.DENY),
        "canary": ("http_post", True, False, True, 100, RiskBand.HIGH, PolicyAction.DENY),
    }[case]
    risk = assess_risk(
        tool,
        untrusted_document=untrusted,
        secret_resource=secret,
        matching_canary=matched,
        context_origin=channel,
    )
    direct = channel is InputChannel.DIRECT_PROMPT
    assert (risk.version, risk.context_origin, risk.score, risk.band) == (
        "risk-v2" if direct else "risk-v1",
        "direct_prompt" if direct else None,
        score,
        band,
    )
    codes = [factor.code for factor in risk.factors]
    if untrusted:
        assert codes[0] == ("untrusted_context" if direct else "untrusted_document")
    assert RiskAssessment.model_validate_json(risk.model_dump_json()) == risk
    historical = risk.model_dump(mode="json")
    if not direct:
        historical.pop("context_origin")
        assert RiskAssessment.model_validate_json(json.dumps(historical)) == risk
    decision = PolicyEvaluator(profile).evaluate(tool, risk)
    assert decision.policy_version == "policy-v1"
    assert decision.action is (
        PolicyAction.ALLOW if profile is PolicyProfile.VULNERABLE else strict_action
    )


@pytest.mark.parametrize(
    "version,origin", [("risk-v1", "direct_prompt"), ("risk-v2", None), ("risk-v2", "document")]
)
def test_risk_reader_rejects_forged_version_origin_pair(version: str, origin: str | None) -> None:
    with pytest.raises(ValidationError):
        RiskAssessment.model_validate_json(
            json.dumps(
                {
                    "version": version,
                    "context_origin": origin,
                    "score": 0,
                    "band": "low",
                    "factors": [],
                }
            )
        )
