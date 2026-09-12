"""Strict Phase 3 detection-rule, fixture, and replay contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from .constants import (
    DETECTION_ENGINE_VERSION,
    MAX_RULE_MEMBERSHIP_VALUES,
    MAX_RULE_PREDICATES,
    MAX_RULE_STEPS,
    REPLAY_SCHEMA_VERSION,
    RULE_SCHEMA_VERSION,
)
from .models import Event, EventSchemaVersion, StrictModel

type RuleScalar = str | bool | int
type RuleField = Literal[
    "schema_version",
    "event_type",
    "source_component",
    "tool_call_id",
    "payload.trust",
    "payload.resource",
    "payload.classification",
    "payload.canary_id",
    "payload.value_sha256",
    "payload.observed_in",
    "payload.matched",
    "payload.redacted",
    "payload.tool",
    "payload.profile",
    "payload.decision",
    "payload.reason",
    "payload.enforcement_layer",
]


class RuleKind(StrEnum):
    SINGLE_EVENT = "single_event"
    SEQUENCE = "sequence"
    CORRELATION = "correlation"


class PredicateOperator(StrEnum):
    EQUALS = "equals"
    IN = "in"


class RulePredicate(StrictModel):
    field: RuleField
    operator: PredicateOperator
    value: RuleScalar | None = None
    values: tuple[RuleScalar, ...] = Field(default=(), max_length=MAX_RULE_MEMBERSHIP_VALUES)

    @field_validator("value")
    @classmethod
    def bound_scalar_value(cls, value: RuleScalar | None) -> RuleScalar | None:
        if isinstance(value, str) and len(value) > 256:
            raise ValueError("rule scalar exceeds length limit")
        return value

    @field_validator("values")
    @classmethod
    def bound_and_unique_values(cls, values: tuple[RuleScalar, ...]) -> tuple[RuleScalar, ...]:
        identities = [(type(value).__name__, value) for value in values]
        if len(identities) != len(set(identities)):
            raise ValueError("membership values must be unique by type and value")
        if any(isinstance(value, str) and len(value) > 256 for value in values):
            raise ValueError("rule scalar exceeds length limit")
        return values

    @model_validator(mode="after")
    def operator_fields_must_agree(self) -> Self:
        if self.operator is PredicateOperator.EQUALS:
            if self.value is None or self.values:
                raise ValueError("equals requires value and forbids values")
        elif self.value is not None or not self.values:
            raise ValueError("in requires values and forbids value")
        return self


class RuleStep(StrictModel):
    name: str = Field(min_length=1, max_length=48, pattern=r"^[a-z][a-z0-9_]*$")
    predicates: tuple[RulePredicate, ...] = Field(min_length=1, max_length=MAX_RULE_PREDICATES)


class RuleJoin(StrictModel):
    left_step: str = Field(min_length=1, max_length=48, pattern=r"^[a-z][a-z0-9_]*$")
    left_field: RuleField
    right_step: str = Field(min_length=1, max_length=48, pattern=r"^[a-z][a-z0-9_]*$")
    right_field: RuleField


class DetectionRule(StrictModel):
    schema_version: Literal["1.0"] = RULE_SCHEMA_VERSION
    rule_id: str = Field(min_length=1, max_length=96, pattern=r"^[A-Z0-9-]+$")
    rule_version: int = Field(ge=1, le=1_000_000)
    description: str = Field(min_length=1, max_length=240)
    severity: Literal["low", "medium", "high", "critical"]
    supported_event_versions: tuple[EventSchemaVersion, ...] = Field(min_length=1, max_length=2)
    kind: RuleKind
    steps: tuple[RuleStep, ...] = Field(min_length=1, max_length=MAX_RULE_STEPS)
    joins: tuple[RuleJoin, ...] = Field(default=(), max_length=MAX_RULE_PREDICATES)

    @model_validator(mode="after")
    def structure_must_match_kind(self) -> Self:
        if len(self.supported_event_versions) != len(set(self.supported_event_versions)):
            raise ValueError("supported event versions must be unique")
        names = [step.name for step in self.steps]
        if len(names) != len(set(names)):
            raise ValueError("rule step names must be unique")
        if self.kind is RuleKind.SINGLE_EVENT and len(self.steps) != 1:
            raise ValueError("single-event rules require exactly one step")
        if self.kind in {RuleKind.SEQUENCE, RuleKind.CORRELATION} and len(self.steps) < 2:
            raise ValueError("sequence and correlation rules require at least two steps")
        if self.kind is RuleKind.CORRELATION and not self.joins:
            raise ValueError("correlation rules require joins")
        if self.kind is not RuleKind.CORRELATION and self.joins:
            raise ValueError("only correlation rules may define joins")
        positions = {name: index for index, name in enumerate(names)}
        join_identities: set[tuple[str, str, str, str]] = set()
        for join in self.joins:
            if join.left_step not in positions or join.right_step not in positions:
                raise ValueError("join references an unknown step")
            if positions[join.left_step] >= positions[join.right_step]:
                raise ValueError("join must reference steps in forward order")
            identity = (
                join.left_step,
                join.left_field,
                join.right_step,
                join.right_field,
            )
            if identity in join_identities:
                raise ValueError("rule joins must be unique")
            join_identities.add(identity)
        return self


class DetectionMatch(StrictModel):
    dedup_key: str = Field(min_length=1, max_length=2048)
    rule_id: str
    rule_version: int
    engine_version: Literal["engine-v1"] = DETECTION_ENGINE_VERSION
    run_id: str
    trace_id: str
    evidence_event_ids: tuple[str, ...] = Field(min_length=1, max_length=MAX_RULE_STEPS)
    severity: Literal["low", "medium", "high", "critical"]
    description: str


class RuleEvaluation(StrictModel):
    rule_id: str
    rule_version: int
    engine_version: Literal["engine-v1"] = DETECTION_ENGINE_VERSION
    candidate_count: int = Field(ge=0)
    duplicate_matches_removed: int = Field(ge=0)
    matches: tuple[DetectionMatch, ...]

    @model_validator(mode="after")
    def matches_must_belong_to_evaluation(self) -> Self:
        if any(
            (match.rule_id, match.rule_version, match.engine_version)
            != (self.rule_id, self.rule_version, self.engine_version)
            for match in self.matches
        ):
            raise ValueError("match identity must agree with its rule evaluation")
        return self


class RuleTestFixture(StrictModel):
    schema_version: Literal["1.0"] = RULE_SCHEMA_VERSION
    name: str = Field(min_length=1, max_length=96, pattern=r"^[a-z0-9-]+$")
    rule_id: str
    rule_version: int = Field(ge=1)
    events: tuple[Event, ...] = Field(min_length=1, max_length=256)
    expected_evidence: tuple[tuple[str, ...], ...]


class RuleFixtureResult(StrictModel):
    fixture: str
    rule_id: str
    rule_version: int
    passed: bool
    expected_evidence: tuple[tuple[str, ...], ...]
    actual_evidence: tuple[tuple[str, ...], ...]


class RuleTestReport(StrictModel):
    schema_version: Literal["1.0"] = RULE_SCHEMA_VERSION
    status: Literal["passed", "failed"]
    total_rules: int = Field(ge=0)
    covered_rules: int = Field(ge=0)
    assertions_passed: int = Field(ge=0)
    assertions_total: int = Field(ge=0)
    results: tuple[RuleFixtureResult, ...]

    @model_validator(mode="after")
    def summaries_must_agree_with_results(self) -> Self:
        identities = {(result.rule_id, result.rule_version) for result in self.results}
        positive = {
            (result.rule_id, result.rule_version)
            for result in self.results
            if result.expected_evidence
        }
        negative = {
            (result.rule_id, result.rule_version)
            for result in self.results
            if not result.expected_evidence
        }
        covered = len(positive & negative)
        passed = sum(result.passed for result in self.results)
        expected_status = (
            "passed" if passed == len(self.results) and covered == self.total_rules else "failed"
        )
        if self.total_rules < len(identities):
            raise ValueError("rule-test results exceed declared rule total")
        if self.covered_rules != covered or self.covered_rules > self.total_rules:
            raise ValueError("rule coverage summary is inconsistent")
        if self.assertions_total != len(self.results) or self.assertions_passed != passed:
            raise ValueError("fixture assertion summary is inconsistent")
        if self.status != expected_status:
            raise ValueError("rule-test status is inconsistent")
        return self


class SourceStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


class ReplayReport(StrictModel):
    schema_version: Literal["1.0"] = REPLAY_SCHEMA_VERSION
    replay_id: str = Field(min_length=1, max_length=96)
    status: Literal["completed"] = "completed"
    source_file: str = Field(min_length=1, max_length=255)
    source_run_id: str
    source_status: SourceStatus
    evidence_cutoff_sequence: int = Field(ge=1)
    input_event_count: int = Field(ge=1)
    evaluated_event_count: int = Field(ge=0)
    evaluations: tuple[RuleEvaluation, ...]
    total_matches: int = Field(ge=0)
    duplicate_matches_removed: int = Field(ge=0)
    local_processing_seconds: float = Field(ge=0)
    safety_and_limitations: tuple[str, ...]

    @model_validator(mode="after")
    def summaries_must_agree_with_evaluations(self) -> Self:
        if self.evaluated_event_count > self.input_event_count:
            raise ValueError("evaluated event count exceeds input event count")
        identities = [
            (evaluation.rule_id, evaluation.rule_version) for evaluation in self.evaluations
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("replay evaluations contain duplicate rule identities")
        if self.total_matches != sum(len(evaluation.matches) for evaluation in self.evaluations):
            raise ValueError("replay match total is inconsistent")
        if self.duplicate_matches_removed != sum(
            evaluation.duplicate_matches_removed for evaluation in self.evaluations
        ):
            raise ValueError("replay duplicate summary is inconsistent")
        if any(
            match.run_id != self.source_run_id
            for evaluation in self.evaluations
            for match in evaluation.matches
        ):
            raise ValueError("replay match run must agree with the source run")
        return self
