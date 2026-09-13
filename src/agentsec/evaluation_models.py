"""Strict Phase 4 evaluation-suite and metric contracts."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import Field, model_validator

from .constants import (
    DETECTION_ENGINE_VERSION,
    EVALUATION_SCHEMA_VERSION,
    INCIDENT_CORRELATOR_VERSION,
    INCIDENT_TEMPLATE_VERSION,
    MAX_EVALUATION_CASES,
    MAX_EVALUATION_CHILD_RUNS,
    METRICS_VERSION,
    PACKAGE_VERSION,
)
from .incident_models import AlertCategory
from .models import DocumentFixture, PolicyProfile, StrictModel

type GroundTruth = Literal["attack", "benign"]


class ExpectedProfileFacts(StrictModel):
    profile: PolicyProfile
    matching_rules: tuple[str, ...]
    simulated_impact: bool
    prevention: bool
    derived_incidents: int = Field(ge=0, le=128)


class EvaluationCase(StrictModel):
    case_id: str = Field(min_length=1, max_length=96, pattern=r"^[a-z0-9-]+$")
    scenario_id: Literal["indirect-injection-secret-exfiltration"] = (
        "indirect-injection-secret-exfiltration"
    )
    fixture: DocumentFixture
    ground_truth: GroundTruth
    attack_family: str | None = Field(default=None, max_length=96)
    expectations: tuple[ExpectedProfileFacts, ExpectedProfileFacts]

    @model_validator(mode="after")
    def profiles_and_labels_must_be_complete(self) -> Self:
        if {item.profile for item in self.expectations} != {
            PolicyProfile.VULNERABLE,
            PolicyProfile.STRICT,
        }:
            raise ValueError("evaluation case requires one expectation for each profile")
        if self.ground_truth == "attack" and self.attack_family is None:
            raise ValueError("attack cases require an attack family")
        if self.ground_truth == "benign" and self.attack_family is not None:
            raise ValueError("benign cases cannot claim an attack family")
        return self


class EvaluationSuite(StrictModel):
    schema_version: Literal["1.0"] = EVALUATION_SCHEMA_VERSION
    suite_id: Literal["core-lab-v1"]
    description: str = Field(min_length=1, max_length=240)
    cases: tuple[EvaluationCase, ...] = Field(min_length=1, max_length=MAX_EVALUATION_CASES)

    @model_validator(mode="after")
    def cases_must_be_unique_and_complete(self) -> Self:
        identities = [case.case_id for case in self.cases]
        fixtures = [case.fixture for case in self.cases]
        if len(identities) != len(set(identities)) or len(fixtures) != len(set(fixtures)):
            raise ValueError("evaluation cases and fixtures must be unique")
        if set(fixtures) != set(DocumentFixture):
            raise ValueError("core suite must contain every closed document fixture")
        return self


class ChildObservation(StrictModel):
    matching_rules: tuple[str, ...]
    simulated_impact: bool
    prevention: bool
    derived_incidents: int = Field(ge=0, le=128)
    secret_access_observed: bool
    outbound_attempt_observed: bool
    incident_categories: tuple[AlertCategory, ...]


class RuleRunCount(StrictModel):
    rule_id: str = Field(min_length=1, max_length=96)
    run_count: int = Field(ge=0)


class IncidentCategoryCount(StrictModel):
    category: AlertCategory
    incident_count: int = Field(ge=0)


class EvaluationChildResult(StrictModel):
    case_id: str
    trial: int = Field(ge=1, le=10)
    profile: PolicyProfile
    ground_truth: GroundTruth
    status: Literal["completed", "failed"]
    run_id: str | None = None
    trace_id: str | None = None
    relative_directory: str | None = None
    observation: ChildObservation | None = None
    expectation: ExpectedProfileFacts
    assertion_passed: bool
    exclusion_reason: str | None = Field(default=None, max_length=96)
    recorded_alert_seconds: float | None = Field(default=None, ge=0)
    recorded_incident_seconds: float | None = Field(default=None, ge=0)
    timing_exclusion_reason: str | None = Field(default=None, max_length=96)

    @model_validator(mode="after")
    def status_fields_must_agree(self) -> Self:
        if self.expectation.profile is not self.profile:
            raise ValueError("child expectation profile must match its assigned profile")
        if self.relative_directory is not None:
            relative = PurePosixPath(self.relative_directory)
            if relative.is_absolute() or ".." in relative.parts or "\\" in self.relative_directory:
                raise ValueError("child artifact directory must be a safe relative POSIX path")
        timing_available = (
            self.recorded_alert_seconds is not None and self.recorded_incident_seconds is not None
        )
        if (self.recorded_alert_seconds is None) != (self.recorded_incident_seconds is None):
            raise ValueError("child timing requires both alert and incident intervals")
        if timing_available == (self.timing_exclusion_reason is not None):
            raise ValueError("child timing requires either intervals or an exclusion reason")
        if self.status == "completed":
            if (
                any(
                    item is None
                    for item in (
                        self.run_id,
                        self.trace_id,
                        self.relative_directory,
                        self.observation,
                    )
                )
                or self.exclusion_reason is not None
            ):
                raise ValueError("completed evaluation child requires observation and artifacts")
        elif (
            self.run_id is not None
            or self.trace_id is not None
            or self.observation is not None
            or self.exclusion_reason is None
            or self.assertion_passed
            or timing_available
        ):
            raise ValueError("failed evaluation child requires an exclusion reason and no claims")
        return self


class MetricResult(StrictModel):
    version: Literal["metrics-v1"] = METRICS_VERSION
    profile: PolicyProfile
    name: Literal[
        "simulated_attack_success_rate",
        "attack_run_detection_rate",
        "simulated_impact_detection_rate",
        "prevention_rate",
        "benign_run_false_positive_rate",
    ]
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    value: float | None = Field(default=None, ge=0, le=1)
    eligible_count: int = Field(ge=0)
    excluded_count: int = Field(ge=0)
    unavailable_reason: Literal["no_eligible_samples"] | None = None

    @model_validator(mode="after")
    def fraction_must_be_exact(self) -> Self:
        if self.numerator > self.denominator or self.eligible_count != self.denominator:
            raise ValueError("metric counts are inconsistent")
        if self.denominator == 0:
            if self.value is not None or self.unavailable_reason != "no_eligible_samples":
                raise ValueError("zero-denominator metric must be unavailable")
        elif self.value != self.numerator / self.denominator or self.unavailable_reason is not None:
            raise ValueError("metric value does not match its fraction")
        return self


class ConfusionCounts(StrictModel):
    profile: PolicyProfile
    true_positive: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    true_negative: int = Field(ge=0)


class TimingSummary(StrictModel):
    profile: PolicyProfile
    basis: Literal["recorded_legacy"] = "recorded_legacy"
    mean_alert_seconds: float | None = Field(default=None, ge=0)
    mean_incident_seconds: float | None = Field(default=None, ge=0)
    sample_count: int = Field(ge=0)
    excluded_count: int = Field(ge=0)

    @model_validator(mode="after")
    def availability_must_match_sample_count(self) -> Self:
        available = self.mean_alert_seconds is not None and self.mean_incident_seconds is not None
        if (self.mean_alert_seconds is None) != (self.mean_incident_seconds is None):
            raise ValueError("timing summary requires both means")
        if available != (self.sample_count > 0):
            raise ValueError("timing summary availability must match sample count")
        return self


class PairedResult(StrictModel):
    case_id: str
    trial: int = Field(ge=1, le=10)
    status: Literal["complete", "incomplete"]
    vulnerable_run_id: str | None
    strict_run_id: str | None
    vulnerable_impact: bool | None
    strict_prevention: bool | None

    @model_validator(mode="after")
    def status_must_match_members(self) -> Self:
        values = (
            self.vulnerable_run_id,
            self.strict_run_id,
            self.vulnerable_impact,
            self.strict_prevention,
        )
        if self.status == "complete" and any(value is None for value in values):
            raise ValueError("complete pair requires both child observations")
        if self.status == "incomplete" and all(value is not None for value in values):
            raise ValueError("incomplete pair cannot contain two complete observations")
        return self


class EvaluationReport(StrictModel):
    schema_version: Literal["1.0"] = EVALUATION_SCHEMA_VERSION
    package_version: Literal["0.4.0"] = PACKAGE_VERSION
    engine_version: Literal["engine-v1"] = DETECTION_ENGINE_VERSION
    correlator_version: Literal["incident-v1"] = INCIDENT_CORRELATOR_VERSION
    template_version: Literal["templates-v1"] = INCIDENT_TEMPLATE_VERSION
    metrics_version: Literal["metrics-v1"] = METRICS_VERSION
    evaluation_id: str = Field(min_length=1, max_length=96)
    suite_id: Literal["core-lab-v1"]
    suite_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["passed", "failed", "partial"]
    repetitions: int = Field(ge=1, le=10)
    unique_case_count: int = Field(ge=1, le=MAX_EVALUATION_CASES)
    total_trials: int = Field(ge=1, le=MAX_EVALUATION_CHILD_RUNS // 2)
    scheduled_children: int = Field(ge=1, le=MAX_EVALUATION_CHILD_RUNS)
    completed_children: int = Field(ge=0)
    failed_children: int = Field(ge=0)
    excluded_children: int = Field(ge=0)
    assertion_failures: int = Field(ge=0)
    children: tuple[EvaluationChildResult, ...] = Field(max_length=MAX_EVALUATION_CHILD_RUNS)
    metrics: tuple[MetricResult, ...]
    confusion_counts: tuple[ConfusionCounts, ConfusionCounts]
    timing: tuple[TimingSummary, TimingSummary]
    pairs: tuple[PairedResult, ...]
    impact_pair_prevention_numerator: int = Field(ge=0)
    impact_pair_prevention_denominator: int = Field(ge=0)
    impact_pair_prevention_rate: float | None = Field(default=None, ge=0, le=1)
    rule_run_counts: tuple[RuleRunCount, ...]
    incident_category_counts: tuple[IncidentCategoryCount, ...]
    safety_and_limitations: tuple[str, ...]

    @model_validator(mode="after")
    def summary_counts_must_agree(self) -> Self:
        completed = sum(child.status == "completed" for child in self.children)
        failed = sum(child.status == "failed" for child in self.children)
        assertions = sum(
            child.status == "completed" and not child.assertion_passed for child in self.children
        )
        if self.scheduled_children != len(self.children):
            raise ValueError("evaluation scheduled count is inconsistent")
        if self.total_trials != self.unique_case_count * self.repetitions:
            raise ValueError("evaluation trial count is inconsistent")
        if self.scheduled_children != self.total_trials * len(PolicyProfile):
            raise ValueError("evaluation profile matrix is inconsistent")
        if self.excluded_children != failed:
            raise ValueError("evaluation exclusion count is inconsistent")
        if (self.completed_children, self.failed_children, self.assertion_failures) != (
            completed,
            failed,
            assertions,
        ):
            raise ValueError("evaluation summary counts are inconsistent")
        expected_status = "partial" if failed else "failed" if assertions else "passed"
        if self.status != expected_status:
            raise ValueError("evaluation status is inconsistent")
        if len(self.metrics) != 10:
            raise ValueError("evaluation requires five metrics per profile")
        if len(self.pairs) != self.scheduled_children // 2:
            raise ValueError("evaluation pairing count is inconsistent")
        child_keys = [(child.case_id, child.trial, child.profile) for child in self.children]
        if len(child_keys) != len(set(child_keys)):
            raise ValueError("evaluation child identities must be unique")
        metric_keys = [(metric.profile, metric.name) for metric in self.metrics]
        if len(metric_keys) != len(set(metric_keys)):
            raise ValueError("evaluation metric identities must be unique")
        if {item.profile for item in self.confusion_counts} != set(PolicyProfile):
            raise ValueError("evaluation requires confusion counts for both profiles")
        if {item.profile for item in self.timing} != set(PolicyProfile):
            raise ValueError("evaluation requires timing summaries for both profiles")
        rule_ids = [item.rule_id for item in self.rule_run_counts]
        categories = [item.category for item in self.incident_category_counts]
        if len(rule_ids) != len(set(rule_ids)) or len(categories) != len(set(categories)):
            raise ValueError("evaluation aggregate identities must be unique")
        from .metrics import build_confusion_counts, build_metrics, build_pairs, build_timing

        if self.metrics != build_metrics(self.children):
            raise ValueError("evaluation metrics do not match child observations")
        if self.confusion_counts != build_confusion_counts(self.children):
            raise ValueError("evaluation confusion counts do not match child observations")
        if self.timing != build_timing(self.children):
            raise ValueError("evaluation timing does not match child observations")
        if self.pairs != build_pairs(self.children):
            raise ValueError("evaluation pairs do not match child observations")
        impacted_pairs = tuple(
            pair
            for pair in self.pairs
            if pair.status == "complete" and pair.vulnerable_impact is True
        )
        paired_numerator = sum(pair.strict_prevention is True for pair in impacted_pairs)
        paired_denominator = len(impacted_pairs)
        if (
            self.impact_pair_prevention_numerator != paired_numerator
            or self.impact_pair_prevention_denominator != paired_denominator
            or self.impact_pair_prevention_rate
            != (paired_numerator / paired_denominator if paired_denominator else None)
        ):
            raise ValueError("restricted paired prevention fraction is inconsistent")
        expected_rule_counts = {
            rule_id: sum(
                child.observation is not None and rule_id in child.observation.matching_rules
                for child in self.children
            )
            for rule_id in {
                rule_id
                for child in self.children
                if child.observation is not None
                for rule_id in child.observation.matching_rules
            }
        }
        if {item.rule_id: item.run_count for item in self.rule_run_counts} != expected_rule_counts:
            raise ValueError("evaluation rule counts do not match child observations")
        expected_categories = {
            category: sum(
                child.observation is not None
                and child.observation.incident_categories.count(category)
                for child in self.children
            )
            for category in {
                category
                for child in self.children
                if child.observation is not None
                for category in child.observation.incident_categories
            }
        }
        if {
            item.category: item.incident_count for item in self.incident_category_counts
        } != expected_categories:
            raise ValueError("evaluation category counts do not match child observations")
        return self
