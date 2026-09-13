from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest
from pydantic import ValidationError

import agentsec.evaluation as evaluation_module
import agentsec.incidents as incidents_module
from agentsec.adapters import LabHttpSinkAdapter, VirtualFileAdapter
from agentsec.cli import main
from agentsec.constants import MAX_REPORT_BYTES
from agentsec.evaluation import (
    EvaluationResourceLimitExceeded,
    EvaluationService,
    load_evaluation_suite,
)
from agentsec.evaluation_models import (
    ChildObservation,
    EvaluationChildResult,
    ExpectedProfileFacts,
    GroundTruth,
)
from agentsec.evaluation_reporting import write_evaluation_report
from agentsec.events import EventCollector, EventStore
from agentsec.evidence import (
    EvidenceConsistencyError,
    fingerprint_rules,
    fingerprint_snapshot,
    fingerprint_suite,
    validate_snapshot,
)
from agentsec.incident_models import AlertCategory, Incident
from agentsec.incident_reporting import write_investigation_report
from agentsec.incidents import InvestigationService, build_investigation
from agentsec.metrics import build_confusion_counts, build_metrics, build_timing
from agentsec.models import DocumentFixture, Event, PolicyProfile
from agentsec.phase4_artifacts import publish_report_pair
from agentsec.reporting import ReportWriteError
from agentsec.resource_loader import load_canary, load_scenario
from agentsec.rule_engine import load_rules
from agentsec.rule_models import SourceStatus
from agentsec.runner import ScenarioRunner

from .helpers import sequential_ids

RESOURCE_ROOT = Path(__file__).parents[1] / "src" / "agentsec" / "resources"
RULES = RESOURCE_ROOT / "rules"


def test_phase_4_fingerprint_fixed_vectors() -> None:
    event = Event(
        event_id="evt_1",
        run_id="run_1",
        trace_id="trace_1",
        sequence=1,
        timestamp="2026-09-12T00:00:00Z",
        event_type="run.started",
        source_component="fixture",
        payload={"profile": "strict", "count": 1, "enabled": True},
    )
    snapshot = validate_snapshot([event], SourceStatus.INCOMPLETE)
    _, suite_data = load_evaluation_suite("core-lab-v1")

    assert fingerprint_snapshot(snapshot) == (
        "14fa38b1705351531017a0aecc348168c80e5eec6a1520a26c4dd8b931c612e1"
    )
    rules = load_rules(RULES)
    assert fingerprint_rules(rules) == (
        "5b15e8bec52b1520975af8701de6e87801251ab64e85165c79d6b5f723d36be8"
    )
    assert fingerprint_suite(suite_data) == (
        "53de470176966e7bcb52b82ae89d64fe27016e954c4db4e011c08352422a82c4"
    )
    changed = event.model_copy(update={"payload": {**event.payload, "count": 2}})
    assert fingerprint_snapshot(validate_snapshot([changed], SourceStatus.INCOMPLETE)) != (
        fingerprint_snapshot(snapshot)
    )
    changed_rule = rules[0].model_copy(update={"description": "Changed test description"})
    assert fingerprint_rules((changed_rule, *rules[1:])) != fingerprint_rules(rules)


def test_investigation_is_read_only_and_derives_one_trace_incident(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(
        "indirect-injection-secret-exfiltration", tmp_path / "source"
    )
    source = run.run_directory / "events.sqlite3"
    before = source.read_bytes()

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("runtime adapter or network API invoked during investigation")

    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(VirtualFileAdapter, "read", fail)
    monkeypatch.setattr(LabHttpSinkAdapter, "record", fail)

    result = InvestigationService(
        id_factory=sequential_ids(), monotonic_clock=lambda: 1.0
    ).investigate(source, run.run_id, RULES, tmp_path / "investigations")

    assert source.read_bytes() == before
    assert result.report.source_status is SourceStatus.COMPLETED
    assert result.report.input_event_count > result.report.evaluated_event_count
    assert [item.rule_id for item in result.report.derived_alerts] == [
        "ASL-CORR-002",
        "ASL-SEQ-001",
    ]
    assert len(result.report.incidents) == 1
    assert result.report.incidents[0].outcome.outcome == "simulated_impact"
    assert result.report.incidents[0].status == "new"
    assert result.report.historical_timing.exclusion_reason is None
    assert len(result.report.snapshot_fingerprint) == 64
    assert len(result.report.rule_set_fingerprint) == 64
    store = EventStore(source)
    try:
        source_events = store.events(run.run_id)
    finally:
        store.close()
    reversed_snapshot = validate_snapshot(list(reversed(source_events)), SourceStatus.COMPLETED)
    assert fingerprint_snapshot(reversed_snapshot) == result.report.snapshot_fingerprint
    assert [entry.evidence.sequence for entry in result.report.incidents[0].timeline] == sorted(
        entry.evidence.sequence for entry in result.report.incidents[0].timeline
    )
    raw_canary = load_canary().encode()
    assert all(
        raw_canary not in path.read_bytes()
        for path in result.investigation_directory.iterdir()
        if path.is_file()
    )
    cli_status = main(
        [
            "investigate",
            "--events",
            str(source),
            "--run-id",
            run.run_id,
            "--rules",
            str(RULES),
            "--output-dir",
            str(tmp_path / "cli-investigation"),
        ]
    )
    cli_output = capsys.readouterr()
    assert cli_status == 0
    assert "derived_alerts=2" in cli_output.out
    assert cli_output.err == ""


def test_benign_and_incomplete_investigations_do_not_invent_outcomes(tmp_path: Path) -> None:
    scenario = load_scenario("indirect-injection-secret-exfiltration").model_copy(
        update={"document_fixture": DocumentFixture.BENIGN}
    )
    benign = ScenarioRunner(id_factory=sequential_ids()).run_scenario(scenario, tmp_path / "benign")
    benign_result = InvestigationService(id_factory=sequential_ids()).investigate(
        benign.run_directory / "events.sqlite3",
        benign.run_id,
        RULES,
        tmp_path / "benign-investigation",
    )
    assert benign_result.report.derived_alerts == ()
    assert benign_result.report.incidents == ()

    database = tmp_path / "incomplete.sqlite3"
    store = EventStore(database)
    collector = EventCollector(store, "run_incomplete", "trace_1", id_factory=sequential_ids())
    collector.emit("run.started", "scenario-controller", {})
    collector.emit(
        "agent.context.document_added",
        "scenario-controller",
        {"trust": "untrusted"},
    )
    store.close()
    incomplete = InvestigationService(id_factory=sequential_ids()).investigate(
        database,
        "run_incomplete",
        RULES,
        tmp_path / "incomplete-investigation",
    )
    assert incomplete.report.source_status is SourceStatus.INCOMPLETE
    assert incomplete.report.incidents == ()


def test_investigation_rejects_evidence_after_terminal_event(tmp_path: Path) -> None:
    database = tmp_path / "invalid.sqlite3"
    store = EventStore(database)
    collector = EventCollector(store, "run_1", "trace_1", id_factory=sequential_ids())
    collector.emit("run.started", "controller", {})
    collector.emit("run.completed", "controller", {}, finalization=True)
    collector.emit("unexpected.after_terminal", "controller", {}, finalization=True)
    store.close()

    with pytest.raises(EvidenceConsistencyError, match="after its terminal"):
        InvestigationService(id_factory=sequential_ids()).investigate(
            database, "run_1", RULES, tmp_path / "output"
        )


def test_fingerprint_validation_rejects_empty_nonfinite_and_duplicate_rules() -> None:
    with pytest.raises(EvidenceConsistencyError, match="no events"):
        validate_snapshot([], SourceStatus.INCOMPLETE)

    event = Event(
        event_id="evt_1",
        run_id="run_1",
        trace_id="trace_1",
        sequence=1,
        timestamp="2026-09-12T00:00:00Z",
        event_type="run.started",
        source_component="fixture",
        payload={"not_finite": float("nan")},
    )
    with pytest.raises(EvidenceConsistencyError, match="non-finite"):
        validate_snapshot([event], SourceStatus.INCOMPLETE)

    rule = load_rules(RULES)[0]
    with pytest.raises(EvidenceConsistencyError, match="duplicate identities"):
        fingerprint_rules((rule, rule))


def test_relevant_payload_types_are_not_coerced() -> None:
    started = Event(
        event_id="evt_1",
        run_id="run_1",
        trace_id="trace_1",
        sequence=1,
        timestamp="2026-09-13T00:00:00Z",
        event_type="run.started",
        source_component="fixture",
        payload={"profile": True},
    )
    with pytest.raises(EvidenceConsistencyError, match="malformed relevant payload"):
        validate_snapshot([started], SourceStatus.INCOMPLETE)


def test_historical_timing_rejects_reversed_clocks_and_missing_links(tmp_path: Path) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(
        "indirect-injection-secret-exfiltration", tmp_path
    )
    store = EventStore(run.run_directory / "events.sqlite3")
    try:
        events = store.events(run.run_id)
    finally:
        store.close()
    assert incidents_module._historical_timing(tuple(events)).exclusion_reason is None
    indexed = [
        event.model_copy(update={"timestamp": f"2026-09-13T00:00:{event.sequence:02d}Z"})
        for event in events
    ]
    reversed_clock = [
        event.model_copy(update={"timestamp": "2026-09-13T00:00:00Z"})
        if event.event_type == "incident.created"
        else event
        for event in indexed
    ]
    assert (
        incidents_module._historical_timing(tuple(reversed_clock)).exclusion_reason
        == "clock_order_invalid"
    )
    missing_links = [
        event.model_copy(
            update={
                "payload": {key: value for key, value in event.payload.items() if key != "alert_id"}
            }
        )
        if event.event_type in {"alert.created", "incident.created"}
        else event
        for event in indexed
    ]
    assert (
        incidents_module._historical_timing(tuple(missing_links)).exclusion_reason
        == "legacy_linkage_invalid"
    )
    wrong_sink = next(event for event in indexed if event.event_type == "lab.sink.payload_recorded")
    wrong_sink = wrong_sink.model_copy(
        update={"payload": {**wrong_sink.payload, "canary_id": "wrong-canary"}}
    )
    assert incidents_module._stage_for_event(wrong_sink) is None


def test_failed_lifecycle_keeps_positive_facts_unknown_and_references_consistent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(
        "indirect-injection-secret-exfiltration", tmp_path
    )
    store = EventStore(run.run_directory / "events.sqlite3")
    try:
        events = store.events(run.run_id)
    finally:
        store.close()
    failed_events = [
        *events[:-1],
        events[-1].model_copy(
            update={"event_type": "run.failed", "payload": {"error_type": "Controlled"}}
        ),
    ]
    report = build_investigation(
        investigation_id="investigation_failed",
        source_file="events.sqlite3",
        events=failed_events,
        source_status=SourceStatus.FAILED,
        rules=load_rules(RULES),
        local_processing_seconds=0,
    )

    assert report.incidents[0].outcome.outcome == "unknown"
    assert report.incidents[0].outcome.simulated_impact is True
    incident_data = report.incidents[0].model_dump(mode="json")
    incident_data["evidence"][0]["snapshot_fingerprint"] = "0" * 64
    with pytest.raises(ValidationError, match="one snapshot"):
        Incident.model_validate_json(json.dumps(incident_data))

    monkeypatch.setattr(incidents_module, "MAX_DERIVED_ALERTS", 0)
    with pytest.raises(RuntimeError, match="alert count"):
        build_investigation(
            investigation_id="investigation_limited",
            source_file="events.sqlite3",
            events=events,
            source_status=SourceStatus.COMPLETED,
            rules=load_rules(RULES),
            local_processing_seconds=0,
        )


def _metric_child(
    child_id: str,
    ground_truth: GroundTruth,
    *,
    detected: bool = False,
    impact: bool = False,
    prevention: bool = False,
    timing: tuple[float, float] | None = None,
    failed: bool = False,
) -> EvaluationChildResult:
    matching_rules = ("TEST-RULE",) if detected else ()
    expectation = ExpectedProfileFacts(
        profile=PolicyProfile.VULNERABLE,
        matching_rules=matching_rules,
        simulated_impact=impact,
        prevention=prevention,
        derived_incidents=1 if detected else 0,
    )
    if failed:
        return EvaluationChildResult(
            case_id=child_id,
            trial=1,
            profile=PolicyProfile.VULNERABLE,
            ground_truth=ground_truth,
            status="failed",
            expectation=expectation,
            assertion_passed=False,
            exclusion_reason="controlled_failure",
            timing_exclusion_reason="child_failed",
        )
    return EvaluationChildResult(
        case_id=child_id,
        trial=1,
        profile=PolicyProfile.VULNERABLE,
        ground_truth=ground_truth,
        status="completed",
        run_id=f"run_{child_id}",
        trace_id=f"trace_{child_id}",
        relative_directory=child_id,
        observation=ChildObservation(
            matching_rules=matching_rules,
            simulated_impact=impact,
            prevention=prevention,
            derived_incidents=1 if detected else 0,
            secret_access_observed=ground_truth == "attack",
            outbound_attempt_observed=ground_truth == "attack",
            incident_categories=(AlertCategory.SUSPICIOUS_ACTIVITY,) if detected else (),
        ),
        expectation=expectation,
        assertion_passed=True,
        recorded_alert_seconds=timing[0] if timing is not None else None,
        recorded_incident_seconds=timing[1] if timing is not None else None,
        timing_exclusion_reason=None if timing is not None else "legacy_detection_unavailable",
    )


def test_metric_denominators_failures_zero_samples_and_recorded_timing() -> None:
    children = (
        _metric_child("a1", "attack", detected=True, impact=True, timing=(1, 2)),
        _metric_child("a2", "attack", detected=True, impact=True, timing=(3, 4)),
        _metric_child("a3", "attack", detected=True, prevention=True),
        _metric_child("a4", "attack"),
        _metric_child("a5", "attack", failed=True),
        _metric_child("b1", "benign", detected=True),
        _metric_child("b2", "benign"),
        _metric_child("b3", "benign"),
    )

    metrics = {(item.profile, item.name): item for item in build_metrics(children)}
    vulnerable = PolicyProfile.VULNERABLE
    assert metrics[(vulnerable, "simulated_attack_success_rate")].value == 2 / 4
    assert metrics[(vulnerable, "attack_run_detection_rate")].value == 3 / 4
    assert metrics[(vulnerable, "simulated_impact_detection_rate")].value == 2 / 2
    assert metrics[(vulnerable, "prevention_rate")].value == 1 / 4
    assert metrics[(vulnerable, "benign_run_false_positive_rate")].value == 1 / 3
    assert metrics[(vulnerable, "attack_run_detection_rate")].excluded_count == 1
    strict = metrics[(PolicyProfile.STRICT, "attack_run_detection_rate")]
    assert strict.value is None
    assert strict.unavailable_reason == "no_eligible_samples"
    confusion = build_confusion_counts(children)[0]
    assert (
        confusion.true_positive,
        confusion.false_negative,
        confusion.false_positive,
        confusion.true_negative,
    ) == (3, 1, 1, 2)
    timing = build_timing(children)[0]
    assert (timing.mean_alert_seconds, timing.mean_incident_seconds) == (2, 3)
    assert (timing.sample_count, timing.excluded_count) == (2, 3)


def test_evaluation_deadline_accounts_for_every_not_run_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evaluation_module, "MAX_EVALUATION_SECONDS", -1)

    result = EvaluationService(id_factory=sequential_ids()).evaluate("core-lab-v1", 1, tmp_path)

    assert result.report.status == "partial"
    assert result.report.failed_children == result.report.excluded_children == 6
    assert result.report.completed_children == 0
    assert all(
        child.exclusion_reason == "not_run_suite_deadline" for child in result.report.children
    )
    assert not list(result.evaluation_directory.rglob("events.sqlite3"))

    monkeypatch.setattr(evaluation_module, "MAX_EVALUATION_SUITE_BYTES", 1)
    with pytest.raises(EvaluationResourceLimitExceeded, match="suite"):
        load_evaluation_suite("core-lab-v1")


def test_suite_rejects_unicode_escaped_canary_after_decoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, suite_data = load_evaluation_suite("core-lab-v1")
    canary = load_canary()
    suite_data["description"] = canary
    encoded = (
        json.dumps(suite_data).replace(canary, f"\\u{ord(canary[0]):04x}" + canary[1:]).encode()
    )

    class FakeResource:
        def joinpath(self, *_parts: str) -> FakeResource:
            return self

        def read_bytes(self) -> bytes:
            return encoded

    monkeypatch.setattr(evaluation_module, "files", lambda _package: FakeResource())
    with pytest.raises(evaluation_module.EvaluationInputError, match="decoded lab canary"):
        load_evaluation_suite("core-lab-v1")


def test_packaged_evaluation_runs_exact_closed_matrix(tmp_path: Path) -> None:
    result = EvaluationService(id_factory=sequential_ids()).evaluate("core-lab-v1", 1, tmp_path)

    assert result.report.status == "passed"
    assert result.report.scheduled_children == result.report.completed_children == 6
    assert result.report.failed_children == result.report.assertion_failures == 0
    assert {(child.case_id, child.profile) for child in result.report.children} == {
        ("malicious", PolicyProfile.VULNERABLE),
        ("malicious", PolicyProfile.STRICT),
        ("benign", PolicyProfile.VULNERABLE),
        ("benign", PolicyProfile.STRICT),
        ("missing-canary", PolicyProfile.VULNERABLE),
        ("missing-canary", PolicyProfile.STRICT),
    }
    assert all(child.assertion_passed for child in result.report.children)
    metrics = {(item.profile, item.name): item for item in result.report.metrics}
    assert metrics[(PolicyProfile.VULNERABLE, "simulated_attack_success_rate")].value == 0.5
    assert metrics[(PolicyProfile.STRICT, "prevention_rate")].value == 1.0
    assert metrics[(PolicyProfile.VULNERABLE, "benign_run_false_positive_rate")].value == 0.0
    assert len(result.report.pairs) == 3
    assert result.report.impact_pair_prevention_numerator == 1
    assert result.report.impact_pair_prevention_denominator == 1
    assert result.report.impact_pair_prevention_rate == 1.0
    assert (result.evaluation_directory / "evaluation.json").is_file()
    assert (result.evaluation_directory / "evaluation.md").is_file()
    assert len(list(result.evaluation_directory.rglob("events.sqlite3"))) == 6
    first = next(
        child
        for child in result.report.children
        if child.case_id == "missing-canary" and child.profile is PolicyProfile.VULNERABLE
    )
    assert first.observation is not None
    assert first.observation.secret_access_observed is True
    assert first.observation.outbound_attempt_observed is True
    markdown = (result.evaluation_directory / "evaluation.md").read_text(encoding="utf-8")
    assert "Paired outcomes" in markdown
    assert "Paired prevention on vulnerable-impact cases" in markdown


def test_child_validation_rejects_wrong_metadata_and_multiple_traces(tmp_path: Path) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(
        "indirect-injection-secret-exfiltration", tmp_path / "source"
    )
    investigation = InvestigationService(id_factory=sequential_ids()).investigate(
        run.run_directory / "events.sqlite3", run.run_id, RULES, tmp_path / "investigations"
    )
    case = next(
        case
        for case in load_evaluation_suite("core-lab-v1")[0].cases
        if case.case_id == "malicious"
    )
    events = list(investigation.events)
    wrong_metadata = [
        event.model_copy(update={"payload": {**event.payload, "fixture": "benign"}})
        if event.event_type == "run.started"
        else event
        for event in events
    ]
    with pytest.raises(ValueError, match="fixture"):
        EvaluationService._validate_child(
            case,
            PolicyProfile.VULNERABLE,
            run.run_id,
            run.trace_id,
            investigation.report,
            wrong_metadata,
        )
    other_trace = events[1].model_copy(update={"trace_id": "other_trace"})
    with pytest.raises(ValueError, match="exactly its assigned trace"):
        EvaluationService._validate_child(
            case,
            PolicyProfile.VULNERABLE,
            run.run_id,
            run.trace_id,
            investigation.report.model_copy(update={"input_event_count": len(events) + 1}),
            [*events, other_trace],
        )


def test_global_evidence_failure_stops_later_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def corrupt(*_args: object, **_kwargs: object) -> None:
        raise EvidenceConsistencyError("controlled invalid evidence")

    monkeypatch.setattr(InvestigationService, "investigate", corrupt)
    report = (
        EvaluationService(id_factory=sequential_ids()).evaluate("core-lab-v1", 1, tmp_path).report
    )
    assert report.status == "partial"
    assert report.failed_children == 6
    assert report.children[0].exclusion_reason == "child_EvidenceConsistencyError"
    assert all(
        child.exclusion_reason == "not_run_global_integrity_or_budget"
        for child in report.children[1:]
    )
    assert len(list(tmp_path.rglob("events.sqlite3"))) == 1


def test_final_evaluation_report_obeys_aggregate_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = EvaluationService(id_factory=sequential_ids()).evaluate(
        "core-lab-v1", 1, tmp_path / "baseline"
    )
    report_bytes = sum(
        path.stat().st_size for path in baseline.evaluation_directory.glob("evaluation.*")
    )
    child_bytes = sum(
        path.stat().st_size
        for path in baseline.evaluation_directory.rglob("*")
        if path.is_file() and path.parent != baseline.evaluation_directory
    )
    monkeypatch.setattr(
        evaluation_module, "MAX_EVALUATION_ARTIFACT_BYTES", child_bytes + report_bytes // 2
    )
    with pytest.raises(EvaluationResourceLimitExceeded, match="aggregate limit"):
        EvaluationService(id_factory=sequential_ids()).evaluate(
            "core-lab-v1", 1, tmp_path / "limited"
        )
    assert not list((tmp_path / "limited").rglob("evaluation.json"))


def test_report_pair_rolls_back_only_owned_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_link = os.link
    calls = 0

    def fail_second_link(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("controlled publication failure")
        original_link(source, destination)

    monkeypatch.setattr(os, "link", fail_second_link)
    with pytest.raises(ReportWriteError, match="unable to write"):
        publish_report_pair(tmp_path, "investigation", b"{}", b"safe")
    assert list(tmp_path.iterdir()) == []

    existing_temp = tmp_path / ".investigation.json.tmp"
    existing_temp.write_bytes(b"user-owned")
    with pytest.raises(ReportWriteError, match="unable to write"):
        publish_report_pair(tmp_path, "investigation", b"{}", b"safe")
    assert existing_temp.read_bytes() == b"user-owned"
    assert sorted(path.name for path in tmp_path.iterdir()) == [existing_temp.name]


def test_report_pair_preserves_original_failure_when_cleanup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_unlink = Path.unlink

    def fail_link(_source: Path, _destination: Path) -> None:
        raise OSError("controlled publication failure")

    def fail_one_cleanup(path: Path) -> None:
        if path.name == ".investigation.md.tmp":
            raise OSError("controlled cleanup failure")
        original_unlink(path)

    with monkeypatch.context() as active:
        active.setattr(os, "link", fail_link)
        active.setattr(Path, "unlink", fail_one_cleanup)
        with pytest.raises(ReportWriteError) as captured:
            publish_report_pair(tmp_path, "investigation", b"{}", b"safe")
    assert isinstance(captured.value.__cause__, OSError)
    assert "controlled publication failure" in str(captured.value.__cause__)
    assert any(
        "cleanup failed" in note for note in getattr(captured.value.__cause__, "__notes__", ())
    )
    (tmp_path / ".investigation.md.tmp").unlink()


def test_evaluation_uses_no_socket_or_dns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network API called")

    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "getaddrinfo", fail)

    result = EvaluationService(id_factory=sequential_ids()).evaluate("core-lab-v1", 1, tmp_path)

    assert result.report.status == "passed"


def test_phase_4_reports_refuse_overwrite_and_exclude_raw_canary(tmp_path: Path) -> None:
    evaluation = EvaluationService(id_factory=sequential_ids()).evaluate("core-lab-v1", 1, tmp_path)
    with pytest.raises(ReportWriteError, match="overwrite"):
        write_evaluation_report(evaluation.report, evaluation.evaluation_directory)

    first_child = next(child for child in evaluation.report.children if child.run_id is not None)
    assert first_child.relative_directory is not None
    assert first_child.run_id is not None
    run_directory = evaluation.evaluation_directory / first_child.relative_directory
    investigation_directory = next((run_directory / "investigation").iterdir())
    investigation_data = json.loads(
        (investigation_directory / "investigation.json").read_text(encoding="utf-8")
    )
    report = (
        InvestigationService(id_factory=sequential_ids())
        .investigate(
            run_directory / "events.sqlite3",
            first_child.run_id,
            RULES,
            tmp_path / "duplicate-source-analysis",
        )
        .report
    )
    with pytest.raises(ReportWriteError, match="overwrite"):
        write_investigation_report(report, investigation_directory)
    unsafe_directory = tmp_path / "unsafe-investigation"
    unsafe_directory.mkdir()
    with pytest.raises(ReportWriteError, match="raw lab canary"):
        write_investigation_report(
            report.model_copy(update={"source_file": load_canary()}), unsafe_directory
        )
    oversized_directory = tmp_path / "oversized-investigation"
    oversized_directory.mkdir()
    with pytest.raises(ReportWriteError, match="size"):
        write_investigation_report(
            report.model_copy(update={"safety_and_limitations": ("x" * MAX_REPORT_BYTES,)}),
            oversized_directory,
        )
    unsafe_evaluation_directory = tmp_path / "unsafe-evaluation"
    unsafe_evaluation_directory.mkdir()
    with pytest.raises(ReportWriteError, match="raw lab canary"):
        write_evaluation_report(
            evaluation.report.model_copy(update={"evaluation_id": load_canary()}),
            unsafe_evaluation_directory,
        )
    raw_canary = load_canary().encode()
    assert raw_canary not in json.dumps(investigation_data).encode()
    assert all(
        raw_canary not in path.read_bytes()
        for path in evaluation.evaluation_directory.rglob("*")
        if path.is_file()
    )


def test_phase_4_cli_and_suite_input_contract(tmp_path: Path) -> None:
    suite, _ = load_evaluation_suite("core-lab-v1")
    assert len(suite.cases) == 3
    assert {case.fixture for case in suite.cases} == set(DocumentFixture)
    assert main(["evaluate", "--suite", "core-lab-v1", "--output-dir", str(tmp_path)]) == 0
    assert (
        main(
            [
                "evaluate",
                "--suite",
                "core-lab-v1",
                "--repetitions",
                "0",
                "--output-dir",
                str(tmp_path / "invalid"),
            ]
        )
        == 2
    )
