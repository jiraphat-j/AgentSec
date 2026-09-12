"""Trusted scenario controller and two-profile comparison orchestration."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

from .adapters import LabHttpSinkAdapter, VirtualFileAdapter
from .approvals import ApprovalSimulator
from .comparison import (
    ComparisonEvidence,
    build_comparison,
    write_comparison_reports,
)
from .constants import CANARY_ID, POLICY_VERSION, RISK_VERSION
from .detection import CorrelationDetector
from .events import EventCollector, EventStore, default_id_factory
from .gateway import ToolGateway
from .mock_agent import DeterministicMockAgent
from .models import (
    ApprovalSimulation,
    ComparisonReport,
    DetectionResult,
    Event,
    PolicyProfile,
    Report,
    Scenario,
)
from .reporting import build_report, write_reports
from .resource_loader import load_canary, load_document, load_scenario


class ScenarioDeadlineExceeded(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class RunResult:
    run_id: str
    trace_id: str
    run_directory: Path
    detection: DetectionResult
    report: Report


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    comparison_id: str
    comparison_directory: Path
    vulnerable: RunResult
    strict: RunResult
    report: ComparisonReport


class ScenarioRunner:
    def __init__(
        self,
        *,
        id_factory: Callable[[str], str] = default_id_factory,
        monotonic_clock: Callable[[], float] = monotonic,
    ) -> None:
        self._id_factory = id_factory
        self._monotonic_clock = monotonic_clock

    def run(
        self,
        scenario_id: str,
        output_directory: Path,
        *,
        profile: PolicyProfile = PolicyProfile.VULNERABLE,
        approval_simulation: ApprovalSimulation = ApprovalSimulation.DENY,
    ) -> RunResult:
        scenario = load_scenario(scenario_id)
        return self.run_scenario(
            scenario,
            output_directory,
            profile=profile,
            approval_simulation=approval_simulation,
        )

    def run_scenario(
        self,
        scenario: Scenario,
        output_directory: Path,
        *,
        profile: PolicyProfile = PolicyProfile.VULNERABLE,
        approval_simulation: ApprovalSimulation = ApprovalSimulation.DENY,
    ) -> RunResult:
        if not isinstance(profile, PolicyProfile):
            raise ValueError("unknown policy profile")
        if not isinstance(approval_simulation, ApprovalSimulation):
            raise ValueError("unknown approval simulation mode")
        if (
            profile is PolicyProfile.VULNERABLE
            and approval_simulation is not ApprovalSimulation.DENY
        ):
            raise ValueError("approval simulation applies only to the strict profile")
        document = load_document(scenario.document_fixture)
        canary = load_canary()
        canary_sha256 = hashlib.sha256(canary.encode("utf-8")).hexdigest()
        run_id = self._id_factory("run")
        trace_id = self._id_factory("trace")
        output_directory.mkdir(parents=True, exist_ok=True)
        run_directory = output_directory / run_id
        run_directory.mkdir(exist_ok=False)
        store = EventStore(run_directory / "events.sqlite3")
        collector = EventCollector(
            store,
            run_id,
            trace_id,
            forbidden_values=(canary,),
            id_factory=self._id_factory,
        )
        sink = LabHttpSinkAdapter(CANARY_ID, canary, canary_sha256)
        approval_simulator = (
            ApprovalSimulator(
                approval_simulation,
                id_factory=lambda: self._id_factory("approval"),
            )
            if profile is PolicyProfile.STRICT
            else None
        )
        started = self._monotonic_clock()

        def check_deadline() -> None:
            if self._monotonic_clock() - started > scenario.timeout_seconds:
                raise ScenarioDeadlineExceeded("scenario deadline exceeded")

        try:
            collector.emit(
                "run.started",
                "scenario-controller",
                {
                    "scenario_id": scenario.id,
                    "fixture": scenario.document_fixture.value,
                    "profile": profile.value,
                    "policy_version": POLICY_VERSION,
                    "risk_version": RISK_VERSION,
                    "approval_simulation": (
                        approval_simulation.value
                        if profile is PolicyProfile.STRICT
                        else "not_applicable"
                    ),
                },
            )
            check_deadline()
            collector.emit(
                "agent.context.document_added",
                "scenario-controller",
                {
                    "document_id": scenario.document_fixture.value,
                    "source": "packaged_text_fixture",
                    "trust": "untrusted",
                },
            )
            gateway = ToolGateway(
                collector,
                VirtualFileAdapter(canary),
                sink,
                canary_sha256,
                canary,
                profile=profile,
                approval_simulator=approval_simulator,
                call_id_factory=lambda: self._id_factory("call"),
            )
            DeterministicMockAgent().execute(document, gateway, check_deadline)
            check_deadline()
            detector = CorrelationDetector()
            detection = detector.evaluate_and_record(store.events(run_id, trace_id), collector)
            evidence = store.events(run_id, trace_id)
            report = build_report(scenario, run_id, trace_id, evidence, detection, profile)
            json_path, markdown_path = write_reports(report, run_directory)
            collector.emit(
                "report.created",
                "report-generator",
                {
                    "formats": [json_path.name, markdown_path.name],
                    "evidence_cutoff_sequence": report.evidence_cutoff_sequence,
                    "profile": profile.value,
                    "outcome": report.outcome,
                },
                finalization=True,
            )
            collector.emit(
                "run.completed",
                "scenario-controller",
                {
                    "detected": detection.detected,
                    "prevented": report.prevention.blocked,
                    "simulated_impact": report.simulated_impact.reached,
                    "outcome": report.outcome,
                },
                finalization=True,
            )
            return RunResult(run_id, trace_id, run_directory, detection, report)
        except Exception as error:
            try:
                collector.emit(
                    "run.failed",
                    "scenario-controller",
                    {"error_type": type(error).__name__, "profile": profile.value},
                    finalization=True,
                )
            except Exception as finalization_error:
                error.add_note(
                    f"run.failed could not be persisted: {type(finalization_error).__name__}"
                )
            raise
        finally:
            sink.clear()
            store.close()

    def compare(self, scenario_id: str, output_directory: Path) -> ComparisonResult:
        scenario = load_scenario(scenario_id)
        comparison_id = self._id_factory("comparison")
        output_directory.mkdir(parents=True, exist_ok=True)
        comparison_directory = output_directory / comparison_id
        comparison_directory.mkdir(exist_ok=False)
        vulnerable = self.run_scenario(
            scenario,
            comparison_directory / PolicyProfile.VULNERABLE.value,
            profile=PolicyProfile.VULNERABLE,
        )
        strict = self.run_scenario(
            scenario,
            comparison_directory / PolicyProfile.STRICT.value,
            profile=PolicyProfile.STRICT,
            approval_simulation=ApprovalSimulation.DENY,
        )
        vulnerable_events = self._read_run_events(vulnerable)
        strict_events = self._read_run_events(strict)
        report = build_comparison(
            scenario,
            comparison_id,
            self._comparison_evidence(
                PolicyProfile.VULNERABLE,
                vulnerable,
                vulnerable_events,
                comparison_directory,
            ),
            self._comparison_evidence(
                PolicyProfile.STRICT,
                strict,
                strict_events,
                comparison_directory,
            ),
        )
        write_comparison_reports(report, comparison_directory)
        return ComparisonResult(comparison_id, comparison_directory, vulnerable, strict, report)

    @staticmethod
    def _read_run_events(result: RunResult) -> list[Event]:
        store = EventStore(result.run_directory / "events.sqlite3")
        try:
            return store.events(result.run_id, result.trace_id)
        finally:
            store.close()

    @staticmethod
    def _comparison_evidence(
        profile: PolicyProfile,
        result: RunResult,
        events: list[Event],
        comparison_directory: Path,
    ) -> ComparisonEvidence:
        return ComparisonEvidence(
            profile=profile,
            run_id=result.run_id,
            trace_id=result.trace_id,
            relative_directory=result.run_directory.relative_to(comparison_directory).as_posix(),
            events=events,
        )
