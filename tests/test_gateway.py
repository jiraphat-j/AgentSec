from __future__ import annotations

import hashlib
import socket
from pathlib import Path
from typing import Never

import pytest

from agentsec.adapters import LabHttpSinkAdapter, VirtualFileAdapter
from agentsec.approvals import ApprovalSimulator
from agentsec.constants import (
    CANARY_ID,
    LAB_SINK_DESTINATION,
    MAX_TOOL_BODY_BYTES,
    MAX_TOOL_REQUESTS,
    VIRTUAL_SECRET_PATH,
)
from agentsec.events import EventCollector, EventStore
from agentsec.gateway import ToolGateway
from agentsec.models import (
    ApprovalResponse,
    ApprovalSimulation,
    Event,
    PolicyProfile,
    RiskAssessment,
)

from .helpers import sequential_ids

FAKE_CANARY = "LAB_FAKE_CANARY_gateway_test"


def make_gateway(
    tmp_path: Path,
    *,
    profile: PolicyProfile = PolicyProfile.VULNERABLE,
    approval: ApprovalSimulation | None = None,
    simulator: ApprovalSimulator | None = None,
) -> tuple[ToolGateway, LabHttpSinkAdapter, EventStore]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(FAKE_CANARY.encode()).hexdigest()
    store = EventStore(tmp_path / "events.sqlite3")
    collector = EventCollector(
        store,
        "run_1",
        "trace_1",
        forbidden_values=(FAKE_CANARY,),
        id_factory=sequential_ids(),
    )
    sink = LabHttpSinkAdapter(CANARY_ID, FAKE_CANARY, digest)
    gateway = ToolGateway(
        collector,
        VirtualFileAdapter(FAKE_CANARY),
        sink,
        digest,
        FAKE_CANARY,
        profile=profile,
        approval_simulator=(
            simulator
            or (
                ApprovalSimulator(approval, id_factory=lambda: "approval_test")
                if approval is not None
                else None
            )
        ),
        call_id_factory=lambda: "call_test",
    )
    return gateway, sink, store


def test_allowed_calls_emit_required_sequence(tmp_path: Path) -> None:
    gateway, sink, store = make_gateway(tmp_path)

    read = gateway.invoke("read_file", {"path": VIRTUAL_SECRET_PATH})
    posted = gateway.invoke("http_post", {"destination": LAB_SINK_DESTINATION, "body": read.value})
    events = store.events("run_1")
    store.close()

    assert read.allowed and read.completed and read.value == FAKE_CANARY
    assert posted.allowed and posted.completed
    assert sink.observations[0].matched
    assert [event.event_type for event in events] == [
        "tool.requested",
        "policy.evaluated",
        "policy.allowed",
        "tool.executed",
        "file.read",
        "tool.requested",
        "policy.evaluated",
        "policy.allowed",
        "tool.executed",
        "lab.sink.payload_recorded",
    ]


@pytest.mark.parametrize(
    "path",
    ["/workspace/.env", "../workspace/.env", r"workspace\.env", "C:/Users/test/.env", "other"],
)
def test_unsafe_and_unknown_paths_are_denied(tmp_path: Path, path: str) -> None:
    gateway, _sink, store = make_gateway(tmp_path)
    result = gateway.invoke("read_file", {"path": path})
    events = store.events("run_1")
    store.close()

    assert not result.allowed
    assert "tool.executed" not in {event.event_type for event in events}


@pytest.mark.parametrize(
    "destination",
    [
        "https://example.com",
        "http://127.0.0.1",
        "//example.com",
        "example.com",
        "ftp://example.com",
        "lab://exfiltration-sink/extra",
    ],
)
def test_external_and_malformed_destinations_are_denied(tmp_path: Path, destination: str) -> None:
    gateway, sink, store = make_gateway(tmp_path)
    result = gateway.invoke("http_post", {"destination": destination, "body": "safe"})
    store.close()

    assert not result.allowed
    assert sink.observations == ()


def test_unknown_tools_and_extra_fields_are_denied(tmp_path: Path) -> None:
    gateway, _sink, store = make_gateway(tmp_path)

    unknown = gateway.invoke("shell", {"command": "whoami"})
    forged = gateway.invoke(
        "read_file", {"path": VIRTUAL_SECRET_PATH, "event_type": "policy.allowed"}
    )
    store.close()

    assert unknown.reason == "unknown_tool"
    assert forged.reason == "invalid_arguments"


def test_tool_body_and_action_count_are_bounded(tmp_path: Path) -> None:
    gateway, sink, store = make_gateway(tmp_path)
    oversized = gateway.invoke(
        "http_post",
        {"destination": LAB_SINK_DESTINATION, "body": "x" * (MAX_TOOL_BODY_BYTES + 1)},
    )
    results = [gateway.invoke("unknown", {}) for _ in range(MAX_TOOL_REQUESTS)]
    store.close()

    assert oversized.reason == "body_too_large"
    assert results[-1].reason == "tool_action_limit"
    assert sink.observations == ()


def test_supported_calls_open_no_socket_or_dns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network API called")

    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    gateway, _sink, store = make_gateway(tmp_path)
    read = gateway.invoke("read_file", {"path": VIRTUAL_SECRET_PATH})
    result = gateway.invoke("http_post", {"destination": LAB_SINK_DESTINATION, "body": read.value})
    store.close()

    assert result.completed


def test_strict_profile_blocks_secret_read_before_adapter(tmp_path: Path) -> None:
    gateway, sink, store = make_gateway(tmp_path, profile=PolicyProfile.STRICT)

    result = gateway.invoke("read_file", {"path": VIRTUAL_SECRET_PATH})
    events = store.events("run_1")
    store.close()

    assert not result.allowed
    assert result.reason == "secret_read_blocked"
    assert sink.observations == ()
    assert [event.event_type for event in events] == [
        "tool.requested",
        "policy.evaluated",
        "policy.denied",
    ]
    assert events[1].payload["risk"]["score"] == 80
    assert events[2].payload["enforcement_layer"] == "defense"
    assert "file.read" not in {event.event_type for event in events}


def test_strict_profile_blocks_direct_canary_post_without_approval(tmp_path: Path) -> None:
    gateway, sink, store = make_gateway(
        tmp_path,
        profile=PolicyProfile.STRICT,
        approval=ApprovalSimulation.APPROVE,
    )

    result = gateway.invoke(
        "http_post",
        {"destination": LAB_SINK_DESTINATION, "body": FAKE_CANARY},
    )
    events = store.events("run_1")
    store.close()

    assert not result.allowed
    assert result.reason == "canary_transfer_blocked"
    assert sink.observations == ()
    assert "policy.approval_required" not in {event.event_type for event in events}
    assert "approval.simulated" not in {event.event_type for event in events}


@pytest.mark.parametrize(
    ("mode", "expected_allowed", "expected_reason"),
    [
        (ApprovalSimulation.DENY, False, "simulated_approval_denied"),
        (ApprovalSimulation.APPROVE, True, "simulated_approval_granted"),
    ],
)
def test_strict_safe_post_uses_bound_simulated_approval(
    tmp_path: Path,
    mode: ApprovalSimulation,
    expected_allowed: bool,
    expected_reason: str,
) -> None:
    gateway, sink, store = make_gateway(
        tmp_path, profile=PolicyProfile.STRICT, approval=mode
    )

    result = gateway.invoke(
        "http_post",
        {"destination": LAB_SINK_DESTINATION, "body": "safe-control-payload"},
    )
    events = store.events("run_1")
    store.close()

    assert result.allowed is expected_allowed
    assert result.reason == expected_reason
    assert [event.event_type for event in events[:4]] == [
        "tool.requested",
        "policy.evaluated",
        "policy.approval_required",
        "approval.simulated",
    ]
    assert bool(sink.observations) is expected_allowed
    if sink.observations:
        assert not sink.observations[0].matched


def test_strict_safety_denial_has_no_risk_or_approval(tmp_path: Path) -> None:
    gateway, sink, store = make_gateway(
        tmp_path,
        profile=PolicyProfile.STRICT,
        approval=ApprovalSimulation.APPROVE,
    )

    result = gateway.invoke(
        "http_post", {"destination": "https://example.com", "body": "safe"}
    )
    events = store.events("run_1")
    store.close()

    assert not result.allowed
    assert sink.observations == ()
    assert events[1].payload["risk"] is None
    assert events[1].payload["enforcement_layer"] == "safety"
    assert "approval.simulated" not in {event.event_type for event in events}


def test_missing_or_mismatched_approval_fails_closed(tmp_path: Path) -> None:
    unavailable, unavailable_sink, unavailable_store = make_gateway(
        tmp_path / "unavailable", profile=PolicyProfile.STRICT
    )
    unavailable_result = unavailable.invoke(
        "http_post",
        {"destination": LAB_SINK_DESTINATION, "body": "safe-control-payload"},
    )
    unavailable_events = unavailable_store.events("run_1")
    unavailable_store.close()

    class MismatchedApproval(ApprovalSimulator):
        def respond(
            self, run_id: str, trace_id: str, tool_call_id: str
        ) -> ApprovalResponse:
            valid = super().respond(run_id, trace_id, tool_call_id)
            return valid.model_copy(update={"run_id": "forged_run"})

    mismatched, mismatched_sink, mismatched_store = make_gateway(
        tmp_path / "mismatched",
        profile=PolicyProfile.STRICT,
        simulator=MismatchedApproval(
            ApprovalSimulation.APPROVE, id_factory=lambda: "approval_mismatch"
        ),
    )
    mismatched_result = mismatched.invoke(
        "http_post",
        {"destination": LAB_SINK_DESTINATION, "body": "safe-control-payload"},
    )
    mismatched_events = mismatched_store.events("run_1")
    mismatched_store.close()

    assert unavailable_result.reason == "approval_unavailable"
    assert unavailable_sink.observations == ()
    assert "approval.simulated" not in {
        event.event_type for event in unavailable_events
    }
    assert mismatched_result.reason == "approval_binding_invalid"
    assert mismatched_sink.observations == ()
    assert any(
        event.event_type == "approval.simulated"
        and event.payload["reason"] == "approval_binding_invalid"
        for event in mismatched_events
    )


@pytest.mark.parametrize("profile", list(PolicyProfile))
def test_mandatory_safety_matrix_applies_to_every_profile(
    tmp_path: Path, profile: PolicyProfile
) -> None:
    gateway, sink, store = make_gateway(
        tmp_path / profile.value,
        profile=profile,
        approval=ApprovalSimulation.APPROVE,
    )

    results = (
        gateway.invoke("read_file", {"path": "../../host-secret"}),
        gateway.invoke(
            "http_post", {"destination": "https://example.com", "body": "safe"}
        ),
        gateway.invoke("shell", {"command": "whoami"}),
        gateway.invoke("read_file", {"path": VIRTUAL_SECRET_PATH, "extra": True}),
    )
    events = store.events("run_1")
    store.close()

    assert all(not result.allowed for result in results)
    assert sink.observations == ()
    assert "tool.executed" not in {event.event_type for event in events}
    assert all(
        event.payload["enforcement_layer"] == "safety"
        and event.payload["risk"] is None
        for event in events
        if event.event_type == "policy.evaluated"
    )


def test_policy_evaluation_or_telemetry_failure_never_dispatches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evaluation_gateway, evaluation_sink, evaluation_store = make_gateway(
        tmp_path / "evaluation"
    )

    def fail_evaluation(_tool: str, _risk: RiskAssessment) -> Never:
        raise RuntimeError("controlled policy evaluation failure")

    monkeypatch.setattr(evaluation_gateway._policy, "evaluate", fail_evaluation)
    with pytest.raises(RuntimeError, match="evaluation"):
        evaluation_gateway.invoke(
            "http_post",
            {"destination": LAB_SINK_DESTINATION, "body": "safe-control-payload"},
        )
    evaluation_store.close()

    telemetry_gateway, telemetry_sink, telemetry_store = make_gateway(
        tmp_path / "telemetry"
    )
    original_emit = telemetry_gateway._collector.emit

    def fail_policy_event(
        event_type: str,
        source_component: str,
        payload: dict[str, object] | None = None,
        *,
        tool_call_id: str | None = None,
        finalization: bool = False,
    ) -> Event:
        if event_type == "policy.evaluated":
            raise RuntimeError("controlled policy telemetry failure")
        return original_emit(
            event_type,
            source_component,
            payload,
            tool_call_id=tool_call_id,
            finalization=finalization,
        )

    monkeypatch.setattr(telemetry_gateway._collector, "emit", fail_policy_event)
    with pytest.raises(RuntimeError, match="telemetry"):
        telemetry_gateway.invoke(
            "http_post",
            {"destination": LAB_SINK_DESTINATION, "body": "safe-control-payload"},
        )
    telemetry_store.close()

    assert evaluation_sink.observations == ()
    assert telemetry_sink.observations == ()
