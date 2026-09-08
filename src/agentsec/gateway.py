"""Closed tool registry, mandatory safety validation, and policy telemetry."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from .adapters import LabHttpSinkAdapter, ResourceDeniedError, VirtualFileAdapter
from .constants import (
    CANARY_ID,
    LAB_SINK_DESTINATION,
    MAX_TOOL_BODY_BYTES,
    MAX_TOOL_REQUESTS,
    VIRTUAL_SECRET_PATH,
)
from .events import EventCollector
from .models import HttpPostArguments, ReadFileArguments, ToolResult


def _tool_call_id() -> str:
    return f"call_{uuid4().hex}"


class ToolGateway:
    def __init__(
        self,
        collector: EventCollector,
        file_adapter: VirtualFileAdapter,
        sink_adapter: LabHttpSinkAdapter,
        value_sha256: str,
        *,
        call_id_factory: Callable[[], str] = _tool_call_id,
    ) -> None:
        self._collector = collector
        self._file_adapter = file_adapter
        self._sink_adapter = sink_adapter
        self._value_sha256 = value_sha256
        self._call_id_factory = call_id_factory
        self._request_count = 0

    def invoke(self, tool: object, arguments: object) -> ToolResult:
        call_id = self._call_id_factory()
        self._request_count += 1
        known_tool = (
            tool if isinstance(tool, str) and tool in {"read_file", "http_post"} else "unknown"
        )
        if isinstance(arguments, Mapping):
            known_names = sorted(
                key
                for key in arguments
                if isinstance(key, str) and key in {"path", "destination", "body"}
            )
            unknown_field_count = len(arguments) - len(known_names)
        else:
            known_names = []
            unknown_field_count = 1
        self._collector.emit(
            "tool.requested",
            "tool-gateway",
            {
                "tool": known_tool,
                "argument_names": known_names,
                "unknown_field_count": unknown_field_count,
            },
            tool_call_id=call_id,
        )
        if self._request_count > MAX_TOOL_REQUESTS:
            return self._deny(known_tool, call_id, "tool_action_limit")
        if not isinstance(tool, str) or not isinstance(arguments, Mapping):
            return self._deny(known_tool, call_id, "invalid_arguments")
        normalized_arguments: Mapping[str, Any] = arguments
        if len(normalized_arguments) > 16:
            return self._deny(known_tool, call_id, "invalid_arguments")
        if tool == "read_file":
            return self._read_file(normalized_arguments, call_id)
        if tool == "http_post":
            return self._http_post(normalized_arguments, call_id)
        return self._deny(known_tool, call_id, "unknown_tool")

    def _read_file(self, arguments: Mapping[str, Any], call_id: str) -> ToolResult:
        try:
            validated = ReadFileArguments.model_validate(dict(arguments))
        except ValidationError:
            return self._deny("read_file", call_id, "invalid_arguments")
        if validated.path != VIRTUAL_SECRET_PATH:
            return self._deny("read_file", call_id, "unsafe_or_unknown_virtual_path")
        self._allow("read_file", call_id, "seeded_fake_secret")
        try:
            value = self._file_adapter.read(validated.path)
        except ResourceDeniedError:
            self._failed("read_file", call_id, "adapter_denied")
            return ToolResult(allowed=True, completed=False, reason="adapter_denied")
        self._collector.emit(
            "file.read",
            "fake-file-adapter",
            {
                "resource": VIRTUAL_SECRET_PATH,
                "classification": "secret",
                "canary_id": CANARY_ID,
                "value_sha256": self._value_sha256,
                "redacted": True,
            },
            tool_call_id=call_id,
        )
        return ToolResult(allowed=True, completed=True, reason="completed", value=value)

    def _http_post(self, arguments: Mapping[str, Any], call_id: str) -> ToolResult:
        try:
            validated = HttpPostArguments.model_validate(dict(arguments))
        except ValidationError:
            return self._deny("http_post", call_id, "invalid_arguments")
        if len(validated.body.encode("utf-8")) > MAX_TOOL_BODY_BYTES:
            return self._deny("http_post", call_id, "body_too_large")
        if validated.destination != LAB_SINK_DESTINATION:
            return self._deny("http_post", call_id, "external_destination")
        self._allow("http_post", call_id, "in_process_lab_sink")
        try:
            observation = self._sink_adapter.record(validated.destination, validated.body)
        except ResourceDeniedError:
            self._failed("http_post", call_id, "adapter_denied")
            return ToolResult(allowed=True, completed=False, reason="adapter_denied")
        self._collector.emit(
            "lab.sink.payload_recorded",
            "lab-http-sink-adapter",
            {
                "destination": LAB_SINK_DESTINATION,
                "canary_id": observation.canary_id,
                "value_sha256": observation.value_sha256,
                "observed_in": observation.observed_in,
                "redacted": observation.redacted,
                "matched": observation.matched,
            },
            tool_call_id=call_id,
        )
        return ToolResult(allowed=True, completed=True, reason="completed")

    def _allow(self, tool: str, call_id: str, reason: str) -> None:
        self._collector.emit(
            "policy.evaluated",
            "vulnerable-baseline-policy",
            {"tool": tool, "profile": "vulnerable"},
            tool_call_id=call_id,
        )
        self._collector.emit(
            "policy.allowed",
            "vulnerable-baseline-policy",
            {"tool": tool, "reason": reason},
            tool_call_id=call_id,
        )
        self._collector.emit(
            "tool.executed",
            "tool-gateway",
            {"tool": tool, "status": "dispatched"},
            tool_call_id=call_id,
        )

    def _deny(self, tool: str, call_id: str, reason: str) -> ToolResult:
        self._collector.emit(
            "policy.evaluated",
            "vulnerable-baseline-policy",
            {"tool": tool, "profile": "vulnerable"},
            tool_call_id=call_id,
        )
        self._collector.emit(
            "policy.denied",
            "vulnerable-baseline-policy",
            {"tool": tool, "reason": reason},
            tool_call_id=call_id,
        )
        return ToolResult(allowed=False, completed=False, reason=reason)

    def _failed(self, tool: str, call_id: str, reason: str) -> None:
        self._collector.emit(
            "tool.failed",
            "tool-gateway",
            {"tool": tool, "reason": reason},
            tool_call_id=call_id,
        )
