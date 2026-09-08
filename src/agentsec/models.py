"""Strict external and persisted data models for schema version 0.1."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .constants import MAX_TIMEOUT_SECONDS


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class DocumentFixture(StrEnum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    MISSING_CANARY = "missing_canary"


class Scenario(StrictModel):
    schema_version: Literal["0.1"] = "0.1"
    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9-]+$")
    name: str = Field(min_length=1, max_length=160)
    document_fixture: DocumentFixture
    timeout_seconds: int = Field(ge=1, le=MAX_TIMEOUT_SECONDS)


class ReadFileArguments(StrictModel):
    path: str = Field(min_length=1, max_length=256)


class HttpPostArguments(StrictModel):
    destination: str = Field(min_length=1, max_length=256)
    body: str


class Event(StrictModel):
    schema_version: Literal["0.1"] = "0.1"
    event_id: str = Field(min_length=1, max_length=96)
    run_id: str = Field(min_length=1, max_length=96)
    trace_id: str = Field(min_length=1, max_length=96)
    sequence: int = Field(ge=1)
    timestamp: str = Field(min_length=20, max_length=40)
    event_type: str = Field(min_length=1, max_length=96)
    source_component: str = Field(min_length=1, max_length=96)
    tool_call_id: str | None = Field(default=None, max_length=96)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_utc_iso8601(cls, value: str) -> str:
        if not value.endswith("Z"):
            raise ValueError("timestamp must use UTC Z notation")
        _ = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
        return value


class ToolResult(StrictModel):
    allowed: bool
    completed: bool
    reason: str
    value: str | None = None


class DetectionResult(StrictModel):
    rule_id: str
    rule_version: int
    detected: bool
    severity: Literal["critical"] | None = None
    evidence_event_ids: tuple[str, ...] = ()
    alert_id: str | None = None
    incident_id: str | None = None


class Report(StrictModel):
    schema_version: Literal["0.1"] = "0.1"
    scenario_id: str
    scenario_name: str
    run_id: str
    trace_id: str
    status: Literal["completed"]
    executive_summary: str
    attack_vector: str
    agent_and_tool_actions: tuple[str, ...]
    timeline: tuple[Event, ...]
    evidence_cutoff_sequence: int
    detection: DetectionResult
    attempted_impact: str
    root_cause: str
    recommended_remediation: tuple[str, ...]
    safety_and_limitations: tuple[str, ...]
