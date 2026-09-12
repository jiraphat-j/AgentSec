"""Closed tool registry, immutable safety checks, and versioned policy telemetry."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from .adapters import LabHttpSinkAdapter, ResourceDeniedError, VirtualFileAdapter
from .approvals import ApprovalBindingError, ApprovalSimulator
from .constants import (
    CANARY_ID,
    LAB_SINK_DESTINATION,
    MAX_TOOL_BODY_BYTES,
    MAX_TOOL_REQUESTS,
    VIRTUAL_SECRET_PATH,
)
from .events import EventCollector
from .models import (
    HttpPostArguments,
    PolicyAction,
    PolicyDecision,
    PolicyProfile,
    ReadFileArguments,
    ToolResult,
)
from .policy import PolicyEvaluator
from .risk import assess_risk


def _tool_call_id() -> str:
    return f"call_{uuid4().hex}"


class ToolGateway:
    def __init__(
        self,
        collector: EventCollector,
        file_adapter: VirtualFileAdapter,
        sink_adapter: LabHttpSinkAdapter,
        value_sha256: str,
        canary_value: str,
        *,
        profile: PolicyProfile = PolicyProfile.VULNERABLE,
        untrusted_document: bool = True,
        approval_simulator: ApprovalSimulator | None = None,
        call_id_factory: Callable[[], str] = _tool_call_id,
    ) -> None:
        if not isinstance(profile, PolicyProfile):
            raise ValueError("unknown policy profile")
        self._collector = collector
        self._file_adapter = file_adapter
        self._sink_adapter = sink_adapter
        self._value_sha256 = value_sha256
        self._canary_value = canary_value
        self._untrusted_document = untrusted_document
        self._approval_simulator = approval_simulator
        self._policy = PolicyEvaluator(profile)
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
            return self._safety_deny(known_tool, call_id, "tool_action_limit")
        if not isinstance(tool, str) or not isinstance(arguments, Mapping):
            return self._safety_deny(known_tool, call_id, "invalid_arguments")
        normalized_arguments: Mapping[str, Any] = arguments
        if len(normalized_arguments) > 16:
            return self._safety_deny(known_tool, call_id, "invalid_arguments")
        if tool == "read_file":
            return self._read_file(normalized_arguments, call_id)
        if tool == "http_post":
            return self._http_post(normalized_arguments, call_id)
        return self._safety_deny(known_tool, call_id, "unknown_tool")

    def _read_file(self, arguments: Mapping[str, Any], call_id: str) -> ToolResult:
        try:
            validated = ReadFileArguments.model_validate(dict(arguments))
        except ValidationError:
            return self._safety_deny("read_file", call_id, "invalid_arguments")
        if validated.path != VIRTUAL_SECRET_PATH:
            return self._safety_deny("read_file", call_id, "unsafe_or_unknown_virtual_path")
        risk = assess_risk(
            "read_file",
            untrusted_document=self._untrusted_document,
            secret_resource=True,
        )
        authorization = self._authorize(
            "read_file", call_id, self._policy.evaluate("read_file", risk)
        )
        if not authorization.allowed:
            return authorization
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
            return self._safety_deny("http_post", call_id, "invalid_arguments")
        if len(validated.body.encode("utf-8")) > MAX_TOOL_BODY_BYTES:
            return self._safety_deny("http_post", call_id, "body_too_large")
        if validated.destination != LAB_SINK_DESTINATION:
            return self._safety_deny("http_post", call_id, "external_destination")
        risk = assess_risk(
            "http_post",
            untrusted_document=self._untrusted_document,
            matching_canary=self._canary_value in validated.body,
        )
        authorization = self._authorize(
            "http_post", call_id, self._policy.evaluate("http_post", risk)
        )
        if not authorization.allowed:
            return authorization
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

    def _authorize(self, tool: str, call_id: str, decision: PolicyDecision) -> ToolResult:
        self._emit_evaluated(tool, call_id, decision)
        if decision.action is PolicyAction.DENY:
            return self._record_denied(tool, call_id, decision.reason, decision)
        if decision.action is PolicyAction.ALLOW:
            return self._record_allowed(tool, call_id, decision.reason, decision)
        self._collector.emit(
            "policy.approval_required",
            "runtime-policy",
            self._decision_payload(tool, decision),
            tool_call_id=call_id,
        )
        if self._approval_simulator is None:
            return self._record_denied(tool, call_id, "approval_unavailable", decision)
        response = self._approval_simulator.respond(
            self._collector.run_id, self._collector.trace_id, call_id
        )
        try:
            approved = self._approval_simulator.resolve(
                response,
                run_id=self._collector.run_id,
                trace_id=self._collector.trace_id,
                tool_call_id=call_id,
            )
        except ApprovalBindingError:
            self._collector.emit(
                "approval.simulated",
                "approval-simulator",
                {
                    "approval_id": response.approval_id,
                    "approved": False,
                    "reason": "approval_binding_invalid",
                    "policy_version": decision.policy_version,
                },
                tool_call_id=call_id,
            )
            return self._record_denied(tool, call_id, "approval_binding_invalid", decision)
        self._collector.emit(
            "approval.simulated",
            "approval-simulator",
            {
                "approval_id": response.approval_id,
                "approved": approved,
                "reason": response.reason,
                "policy_version": response.policy_version,
            },
            tool_call_id=call_id,
        )
        if approved:
            return self._record_allowed(tool, call_id, "simulated_approval_granted", decision)
        return self._record_denied(tool, call_id, "simulated_approval_denied", decision)

    def _safety_deny(self, tool: str, call_id: str, reason: str) -> ToolResult:
        decision = self._policy.safety_deny(reason)
        self._emit_evaluated(tool, call_id, decision)
        return self._record_denied(tool, call_id, reason, decision)

    def _emit_evaluated(self, tool: str, call_id: str, decision: PolicyDecision) -> None:
        self._collector.emit(
            "policy.evaluated",
            "runtime-policy",
            self._decision_payload(tool, decision),
            tool_call_id=call_id,
        )

    def _record_allowed(
        self, tool: str, call_id: str, reason: str, decision: PolicyDecision
    ) -> ToolResult:
        payload = self._decision_payload(tool, decision)
        payload.update({"decision": "allow", "reason": reason})
        self._collector.emit("policy.allowed", "runtime-policy", payload, tool_call_id=call_id)
        self._collector.emit(
            "tool.executed",
            "tool-gateway",
            {"tool": tool, "status": "dispatched"},
            tool_call_id=call_id,
        )
        return ToolResult(allowed=True, completed=True, reason=reason)

    def _record_denied(
        self, tool: str, call_id: str, reason: str, decision: PolicyDecision
    ) -> ToolResult:
        payload = self._decision_payload(tool, decision)
        payload.update({"decision": "deny", "reason": reason})
        self._collector.emit("policy.denied", "runtime-policy", payload, tool_call_id=call_id)
        return ToolResult(allowed=False, completed=False, reason=reason)

    @staticmethod
    def _decision_payload(tool: str, decision: PolicyDecision) -> dict[str, object]:
        return {
            "tool": tool,
            "profile": decision.profile.value,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "rule_id": decision.rule_id,
            "decision": decision.action.value,
            "reason": decision.reason,
            "enforcement_layer": decision.enforcement_layer.value,
            "risk": (decision.risk.model_dump(mode="json") if decision.risk is not None else None),
        }

    def _failed(self, tool: str, call_id: str, reason: str) -> None:
        self._collector.emit(
            "tool.failed",
            "tool-gateway",
            {"tool": tool, "reason": reason},
            tool_call_id=call_id,
        )
