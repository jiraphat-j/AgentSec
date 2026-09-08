from __future__ import annotations

import hashlib
import socket
from pathlib import Path

import pytest

from agentsec.adapters import LabHttpSinkAdapter, VirtualFileAdapter
from agentsec.constants import (
    CANARY_ID,
    LAB_SINK_DESTINATION,
    MAX_TOOL_BODY_BYTES,
    MAX_TOOL_REQUESTS,
    VIRTUAL_SECRET_PATH,
)
from agentsec.events import EventCollector, EventStore
from agentsec.gateway import ToolGateway

from .helpers import sequential_ids

FAKE_CANARY = "LAB_FAKE_CANARY_gateway_test"


def make_gateway(tmp_path: Path) -> tuple[ToolGateway, LabHttpSinkAdapter, EventStore]:
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
