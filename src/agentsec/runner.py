"""Trusted scenario controller for the deterministic Vertical Slice."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

from .adapters import LabHttpSinkAdapter, VirtualFileAdapter
from .constants import CANARY_ID
from .detection import CorrelationDetector
from .events import EventCollector, EventStore, default_id_factory
from .gateway import ToolGateway
from .mock_agent import DeterministicMockAgent
from .models import DetectionResult, Scenario
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


class ScenarioRunner:
    def __init__(
        self,
        *,
        id_factory: Callable[[str], str] = default_id_factory,
        monotonic_clock: Callable[[], float] = monotonic,
    ) -> None:
        self._id_factory = id_factory
        self._monotonic_clock = monotonic_clock

    def run(self, scenario_id: str, output_directory: Path) -> RunResult:
        scenario = load_scenario(scenario_id)
        return self.run_scenario(scenario, output_directory)

    def run_scenario(self, scenario: Scenario, output_directory: Path) -> RunResult:
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
        started = self._monotonic_clock()

        def check_deadline() -> None:
            if self._monotonic_clock() - started > scenario.timeout_seconds:
                raise ScenarioDeadlineExceeded("scenario deadline exceeded")

        try:
            collector.emit(
                "run.started",
                "scenario-controller",
                {"scenario_id": scenario.id, "fixture": scenario.document_fixture.value},
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
                call_id_factory=lambda: self._id_factory("call"),
            )
            DeterministicMockAgent().execute(document, gateway, check_deadline)
            check_deadline()
            detector = CorrelationDetector()
            detection = detector.evaluate_and_record(store.events(run_id, trace_id), collector)
            evidence = store.events(run_id, trace_id)
            report = build_report(scenario, run_id, trace_id, evidence, detection)
            json_path, markdown_path = write_reports(report, run_directory)
            collector.emit(
                "report.created",
                "report-generator",
                {
                    "formats": [json_path.name, markdown_path.name],
                    "evidence_cutoff_sequence": report.evidence_cutoff_sequence,
                },
                finalization=True,
            )
            collector.emit(
                "run.completed",
                "scenario-controller",
                {"detected": detection.detected},
                finalization=True,
            )
            return RunResult(run_id, trace_id, run_directory, detection)
        except Exception as error:
            try:
                collector.emit(
                    "run.failed",
                    "scenario-controller",
                    {"error_type": type(error).__name__},
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
