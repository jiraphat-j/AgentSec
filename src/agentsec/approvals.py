"""Synchronous approval simulation for otherwise eligible lab actions."""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from .constants import POLICY_VERSION
from .models import ApprovalResponse, ApprovalSimulation


def _approval_id() -> str:
    return f"approval_{uuid4().hex}"


class ApprovalBindingError(ValueError):
    pass


class ApprovalSimulator:
    def __init__(
        self,
        mode: ApprovalSimulation = ApprovalSimulation.DENY,
        *,
        id_factory: Callable[[], str] = _approval_id,
    ) -> None:
        if not isinstance(mode, ApprovalSimulation):
            raise ValueError("unknown approval simulation mode")
        self.mode = mode
        self._id_factory = id_factory
        self._consumed: set[str] = set()

    def respond(self, run_id: str, trace_id: str, tool_call_id: str) -> ApprovalResponse:
        approved = self.mode is ApprovalSimulation.APPROVE
        return ApprovalResponse(
            approval_id=self._id_factory(),
            run_id=run_id,
            trace_id=trace_id,
            tool_call_id=tool_call_id,
            approved=approved,
            reason=("simulated_approval_granted" if approved else "simulated_approval_denied"),
        )

    def resolve(
        self,
        response: ApprovalResponse,
        *,
        run_id: str,
        trace_id: str,
        tool_call_id: str,
    ) -> bool:
        if response.approval_id in self._consumed:
            raise ApprovalBindingError("approval response was already consumed")
        if (
            response.schema_version != "0.2"
            or response.approved != (response.reason == "simulated_approval_granted")
            or response.run_id != run_id
            or response.trace_id != trace_id
            or response.tool_call_id != tool_call_id
            or response.policy_version != POLICY_VERSION
        ):
            raise ApprovalBindingError("approval response does not match the current request")
        self._consumed.add(response.approval_id)
        return response.approved
