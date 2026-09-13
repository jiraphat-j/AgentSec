"""Closed, deterministic Phase 4 evaluation orchestration."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from time import monotonic

from pydantic import ValidationError

from .constants import (
    EVALUATION_SUITE_ID,
    MAX_EVALUATION_ARTIFACT_BYTES,
    MAX_EVALUATION_CHILD_RUNS,
    MAX_EVALUATION_REPETITIONS,
    MAX_EVALUATION_SECONDS,
    MAX_EVALUATION_SUITE_BYTES,
)
from .evaluation_models import (
    ChildObservation,
    EvaluationCase,
    EvaluationChildResult,
    EvaluationReport,
    EvaluationSuite,
    ExpectedProfileFacts,
    IncidentCategoryCount,
    RuleRunCount,
)
from .events import default_id_factory
from .evidence import EvidenceConsistencyError, fingerprint_suite
from .incidents import InvestigationService
from .metrics import build_confusion_counts, build_metrics, build_pairs, build_timing
from .models import ApprovalSimulation, Event, PolicyProfile
from .outcomes import derive_impact, derive_prevention
from .replay import ReplayResourceLimitExceeded
from .reporting import ReportWriteError
from .resource_loader import load_canary, load_scenario
from .rule_engine import RuleEvaluationLimitExceeded
from .runner import ScenarioRunner


class EvaluationInputError(ValueError):
    """Raised for an unsupported or malformed packaged suite request."""


class EvaluationResourceLimitExceeded(RuntimeError):
    """Raised when a fixed suite, time, or artifact limit is exceeded."""


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    evaluation_directory: Path
    report: EvaluationReport


def load_evaluation_suite(suite_id: str) -> tuple[EvaluationSuite, dict[str, object]]:
    if suite_id != EVALUATION_SUITE_ID:
        raise EvaluationInputError("unknown evaluation suite")
    resource = files("agentsec.resources").joinpath("evaluation_suites", "core-lab-v1.json")
    data = resource.read_bytes()
    if len(data) > MAX_EVALUATION_SUITE_BYTES:
        raise EvaluationResourceLimitExceeded("evaluation suite exceeds fixed size limit")
    if load_canary().encode("utf-8") in data:
        raise EvaluationInputError("raw lab canary is forbidden in evaluation suite data")
    try:
        suite = EvaluationSuite.model_validate_json(data)
    except ValidationError as error:
        raise EvaluationInputError("packaged evaluation suite failed validation") from error
    if load_canary() in json.dumps(suite.model_dump(mode="json"), ensure_ascii=False):
        raise EvaluationInputError("decoded lab canary is forbidden in evaluation suite data")
    return suite, suite.model_dump(mode="json")


def _expectation(case: EvaluationCase, profile: PolicyProfile) -> ExpectedProfileFacts:
    return next(item for item in case.expectations if item.profile is profile)


def _artifact_bytes(directory: Path) -> int:
    total = 0
    for path in directory.rglob("*"):
        if path.is_file():
            total += path.stat().st_size
            if total > MAX_EVALUATION_ARTIFACT_BYTES:
                raise EvaluationResourceLimitExceeded(
                    "evaluation artifacts exceed fixed aggregate limit"
                )
    return total


class EvaluationService:
    def __init__(
        self,
        *,
        id_factory: Callable[[str], str] = default_id_factory,
        monotonic_clock: Callable[[], float] = monotonic,
    ) -> None:
        self._id_factory = id_factory
        self._monotonic_clock = monotonic_clock

    def evaluate(
        self,
        suite_id: str,
        repetitions: int,
        output_directory: Path,
    ) -> EvaluationResult:
        if type(repetitions) is not int or not 1 <= repetitions <= MAX_EVALUATION_REPETITIONS:
            raise EvaluationInputError("repetitions must be between 1 and 10")
        suite, suite_data = load_evaluation_suite(suite_id)
        scheduled = len(suite.cases) * len(PolicyProfile) * repetitions
        if scheduled > MAX_EVALUATION_CHILD_RUNS:
            raise EvaluationResourceLimitExceeded("evaluation child count exceeds fixed limit")
        output_directory.mkdir(parents=True, exist_ok=True)
        evaluation_id = self._id_factory("evaluation")
        evaluation_directory = output_directory / evaluation_id
        evaluation_directory.mkdir(exist_ok=False)
        children: list[EvaluationChildResult] = []
        started = self._monotonic_clock()
        runner = ScenarioRunner(id_factory=self._id_factory, monotonic_clock=self._monotonic_clock)
        investigator = InvestigationService(
            id_factory=self._id_factory, monotonic_clock=self._monotonic_clock
        )
        base_scenario = load_scenario(suite.cases[0].scenario_id)
        rule_resource = files("agentsec.resources").joinpath("rules")
        stop_reason: str | None = None

        with as_file(rule_resource) as rules_directory:
            for case in suite.cases:
                for trial in range(1, repetitions + 1):
                    for profile in PolicyProfile:
                        expectation = _expectation(case, profile)
                        child_parent = (
                            evaluation_directory / case.case_id / str(trial) / profile.value
                        )
                        relative_parent = child_parent.relative_to(evaluation_directory).as_posix()
                        if stop_reason is not None:
                            children.append(
                                self._failed_child(
                                    case,
                                    trial,
                                    profile,
                                    expectation,
                                    stop_reason,
                                    None,
                                )
                            )
                            continue
                        if self._monotonic_clock() - started > MAX_EVALUATION_SECONDS:
                            stop_reason = "not_run_suite_deadline"
                            children.append(
                                self._failed_child(
                                    case,
                                    trial,
                                    profile,
                                    expectation,
                                    "not_run_suite_deadline",
                                    relative_parent,
                                )
                            )
                            continue
                        scenario = base_scenario.model_copy(
                            update={"document_fixture": case.fixture}
                        )
                        try:
                            run = runner.run_scenario(
                                scenario,
                                child_parent,
                                profile=profile,
                                approval_simulation=ApprovalSimulation.DENY,
                            )
                            investigation = investigator.investigate(
                                run.run_directory / "events.sqlite3",
                                run.run_id,
                                rules_directory,
                                run.run_directory / "investigation",
                            )
                            investigation_report = investigation.report
                            child_events = list(investigation.events)
                            self._validate_child(
                                case,
                                profile,
                                run.run_id,
                                run.trace_id,
                                investigation_report,
                                child_events,
                            )
                            matching_rules = tuple(
                                sorted(
                                    evaluation.rule_id
                                    for evaluation in investigation_report.rule_evaluations
                                    if evaluation.matches
                                )
                            )
                            impact = derive_impact(child_events)
                            prevention = derive_prevention(child_events)
                            if impact.reached and prevention.blocked:
                                raise EvidenceConsistencyError(
                                    "child evidence has contradictory outcomes"
                                )
                            if (
                                impact.reached != run.report.simulated_impact.reached
                                or prevention.blocked != run.report.prevention.blocked
                            ):
                                raise EvidenceConsistencyError(
                                    "child report disagrees with evidence"
                                )
                            observation = ChildObservation(
                                matching_rules=matching_rules,
                                simulated_impact=impact.reached,
                                prevention=prevention.blocked,
                                derived_incidents=len(investigation_report.incidents),
                                secret_access_observed=any(
                                    event.event_type == "file.read"
                                    and event.payload.get("classification") == "secret"
                                    for event in child_events
                                ),
                                outbound_attempt_observed=any(
                                    event.event_type == "tool.requested"
                                    and event.payload.get("tool") == "http_post"
                                    for event in child_events
                                ),
                                incident_categories=tuple(
                                    incident.category for incident in investigation_report.incidents
                                ),
                            )
                            assertion_passed = (
                                observation.matching_rules == expectation.matching_rules
                                and observation.simulated_impact == expectation.simulated_impact
                                and observation.prevention == expectation.prevention
                                and observation.derived_incidents == expectation.derived_incidents
                            )
                            child_result = EvaluationChildResult(
                                case_id=case.case_id,
                                trial=trial,
                                profile=profile,
                                ground_truth=case.ground_truth,
                                status="completed",
                                run_id=run.run_id,
                                trace_id=run.trace_id,
                                relative_directory=run.run_directory.relative_to(
                                    evaluation_directory
                                ).as_posix(),
                                observation=observation,
                                expectation=expectation,
                                assertion_passed=assertion_passed,
                                recorded_alert_seconds=(
                                    investigation_report.historical_timing.alert_seconds
                                ),
                                recorded_incident_seconds=(
                                    investigation_report.historical_timing.incident_seconds
                                ),
                                timing_exclusion_reason=(
                                    investigation_report.historical_timing.exclusion_reason
                                ),
                            )
                            _artifact_bytes(evaluation_directory)
                            children.append(child_result)
                        except (
                            EvaluationResourceLimitExceeded,
                            ReplayResourceLimitExceeded,
                            RuleEvaluationLimitExceeded,
                            EvidenceConsistencyError,
                            ReportWriteError,
                        ) as error:
                            children.append(
                                self._failed_child(
                                    case,
                                    trial,
                                    profile,
                                    expectation,
                                    f"child_{type(error).__name__}",
                                    relative_parent if child_parent.exists() else None,
                                )
                            )
                            stop_reason = "not_run_global_integrity_or_budget"
                        except Exception as error:
                            children.append(
                                self._failed_child(
                                    case,
                                    trial,
                                    profile,
                                    expectation,
                                    f"child_{type(error).__name__}",
                                    relative_parent if child_parent.exists() else None,
                                )
                            )

        child_tuple = tuple(children)
        failed = sum(child.status == "failed" for child in child_tuple)
        assertions = sum(
            child.status == "completed" and not child.assertion_passed for child in child_tuple
        )
        pairs = build_pairs(child_tuple)
        impacted_pairs = tuple(
            pair for pair in pairs if pair.status == "complete" and pair.vulnerable_impact is True
        )
        pair_numerator = sum(pair.strict_prevention is True for pair in impacted_pairs)
        pair_denominator = len(impacted_pairs)
        evaluation_report = EvaluationReport(
            evaluation_id=evaluation_id,
            suite_id=suite.suite_id,
            suite_fingerprint=fingerprint_suite(suite_data),
            status="partial" if failed else "failed" if assertions else "passed",
            repetitions=repetitions,
            unique_case_count=len(suite.cases),
            total_trials=len(suite.cases) * repetitions,
            scheduled_children=scheduled,
            completed_children=scheduled - failed,
            failed_children=failed,
            excluded_children=failed,
            assertion_failures=assertions,
            children=child_tuple,
            metrics=build_metrics(child_tuple),
            confusion_counts=build_confusion_counts(child_tuple),
            timing=build_timing(child_tuple),
            pairs=pairs,
            impact_pair_prevention_numerator=pair_numerator,
            impact_pair_prevention_denominator=pair_denominator,
            impact_pair_prevention_rate=(
                pair_numerator / pair_denominator if pair_denominator else None
            ),
            rule_run_counts=self._rule_counts(child_tuple),
            incident_category_counts=self._category_counts(child_tuple),
            safety_and_limitations=(
                "All executions use closed packaged fixtures, rules, and an in-process sink.",
                "Repetitions test deterministic stability, not independent scenario diversity.",
                "Metrics describe this synthetic suite and are not real-world accuracy estimates.",
                "Suite fingerprints detect content changes but do not authenticate origin.",
                "Recorded legacy timing is separate from offline Phase 4 processing duration.",
            ),
        )
        from .evaluation_reporting import render_evaluation_markdown, write_evaluation_report

        report_bytes = len(
            json.dumps(
                evaluation_report.model_dump(mode="json"),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            ).encode("utf-8")
        ) + len(render_evaluation_markdown(evaluation_report).encode("utf-8"))
        if _artifact_bytes(evaluation_directory) + report_bytes > MAX_EVALUATION_ARTIFACT_BYTES:
            raise EvaluationResourceLimitExceeded(
                "evaluation artifacts exceed fixed aggregate limit"
            )
        write_evaluation_report(evaluation_report, evaluation_directory)
        return EvaluationResult(evaluation_directory, evaluation_report)

    @staticmethod
    def _rule_counts(
        children: tuple[EvaluationChildResult, ...],
    ) -> tuple[RuleRunCount, ...]:
        rule_ids = sorted(
            {
                rule_id
                for child in children
                if child.observation is not None
                for rule_id in child.observation.matching_rules
            }
        )
        return tuple(
            RuleRunCount(
                rule_id=rule_id,
                run_count=sum(
                    child.observation is not None and rule_id in child.observation.matching_rules
                    for child in children
                ),
            )
            for rule_id in rule_ids
        )

    @staticmethod
    def _category_counts(
        children: tuple[EvaluationChildResult, ...],
    ) -> tuple[IncidentCategoryCount, ...]:
        categories = sorted(
            {
                category
                for child in children
                if child.observation is not None
                for category in child.observation.incident_categories
            }
        )
        return tuple(
            IncidentCategoryCount(
                category=category,
                incident_count=sum(
                    child.observation is not None
                    and child.observation.incident_categories.count(category)
                    for child in children
                ),
            )
            for category in categories
        )

    @staticmethod
    def _failed_child(
        case: EvaluationCase,
        trial: int,
        profile: PolicyProfile,
        expectation: ExpectedProfileFacts,
        reason: str,
        relative_directory: str | None,
    ) -> EvaluationChildResult:
        return EvaluationChildResult(
            case_id=case.case_id,
            trial=trial,
            profile=profile,
            ground_truth=case.ground_truth,
            status="failed",
            relative_directory=relative_directory,
            expectation=expectation,
            assertion_passed=False,
            exclusion_reason=reason,
            timing_exclusion_reason="child_failed",
        )

    @staticmethod
    def _validate_child(
        case: EvaluationCase,
        profile: PolicyProfile,
        run_id: str,
        trace_id: str,
        report: object,
        events: list[Event],
    ) -> None:
        from .incident_models import InvestigationReport

        if not isinstance(report, InvestigationReport):
            raise ValueError("child investigation report has an invalid type")
        if report.source_status.value != "completed" or report.source_run_id != run_id:
            raise ValueError("child evidence lifecycle or run identity is inconsistent")
        if report.input_event_count != len(events):
            raise ValueError("child investigation does not describe its event snapshot")
        traces = {event.trace_id for event in events}
        if traces != {trace_id}:
            raise ValueError("evaluation child must contain exactly its assigned trace")
        started = next(event for event in events if event.event_type == "run.started")
        if started.payload.get("scenario_id") != case.scenario_id:
            raise ValueError("child scenario does not match its assigned case")
        if started.payload.get("fixture") != case.fixture.value:
            raise ValueError("child fixture does not match its assigned case")
        if started.payload.get("profile") != profile.value:
            raise ValueError("child profile does not match its assigned case")
