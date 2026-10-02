"""Direct evidence and evaluation failure cases; run only in the lab sandbox."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import agentsec.evaluation as evaluation_module
from agentsec.cli import main
from agentsec.constants import DIRECT_PROMPT_SCENARIO_ID, MAX_EVALUATION_SECONDS
from agentsec.dashboard_catalog import (
    DashboardCatalog,
    DashboardInputError,
    _verify_investigation,
    encode_safe_projection,
)
from agentsec.evaluation import EvaluationService, load_evaluation_suite
from agentsec.evidence import EvidenceConsistencyError, fingerprint_snapshot, validate_snapshot
from agentsec.incident_models import InvestigationReport
from agentsec.incidents import InvestigationService, _historical_timing, build_investigation
from agentsec.models import PolicyProfile, PromptFixture
from agentsec.replay import ReplayResourceLimitExceeded, read_replay_evidence
from agentsec.reporting import ReportWriteError
from agentsec.resource_loader import load_canary, load_prompt
from agentsec.rule_engine import load_rules
from agentsec.rule_models import SourceStatus
from agentsec.runner import ScenarioRunner

from .helpers import sequential_ids
from .test_phase6a_g0_failures import assert_redacted

RULES = Path(__file__).parents[1] / "src/agentsec/resources/rules"


def direct_investigation_files(tmp_path: Path, profile: PolicyProfile) -> tuple[Path, Path, Path]:
    run = ScenarioRunner(id_factory=sequential_ids()).run(
        DIRECT_PROMPT_SCENARIO_ID, tmp_path / "runs", profile=profile
    )
    source = run.run_directory / "events.sqlite3"
    investigation = InvestigationService(id_factory=sequential_ids()).investigate(
        source, run.run_id, RULES, tmp_path / "investigations"
    )
    report_path = investigation.investigation_directory / "investigation.json"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "entries": [
                    {
                        "id": "source",
                        "kind": "event_source",
                        "path": source.relative_to(tmp_path).as_posix(),
                        "run_id": run.run_id,
                    },
                    {
                        "id": "investigation",
                        "kind": "investigation",
                        "path": report_path.relative_to(tmp_path).as_posix(),
                        "source_id": "source",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return source, report_path, manifest


@pytest.mark.parametrize("profile", list(PolicyProfile))
def test_dashboard_accepts_genuine_linked_direct_investigation(
    tmp_path: Path, profile: PolicyProfile
) -> None:
    source, _report_path, manifest = direct_investigation_files(tmp_path, profile)
    original = source.read_bytes()
    valid = DashboardCatalog.load(manifest).get("investigation")
    assert valid is not None and valid.summary.provenance == "verified_against_source"
    assert source.read_bytes() == original
    assert_redacted(tmp_path)


@pytest.mark.parametrize(
    "mutation", ["missing_evidence", "extra_field", "event_payload", "bad_sequence", "empty_event"]
)
def test_prompt_timeline_exception_keeps_projection_validation_strict(
    tmp_path: Path, mutation: str
) -> None:
    _source, report_path, _manifest = direct_investigation_files(tmp_path, PolicyProfile.VULNERABLE)
    report = InvestigationReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    timeline = next(
        item
        for item in report.incidents[0].timeline
        if item.event_type == "agent.context.prompt_added"
    )
    value = timeline.model_dump(mode="json")
    if mutation == "missing_evidence":
        value.pop("evidence")
    elif mutation == "extra_field":
        value["raw_prompt"] = load_prompt(PromptFixture.MALICIOUS)
    elif mutation == "event_payload":
        value["payload"] = {"prompt_id": "arbitrary_prompt"}
    elif mutation == "bad_sequence":
        value["evidence"]["sequence"] = 0
    else:
        value = {"event_type": "agent.context.prompt_added"}
    with pytest.raises(DashboardInputError, match="unsafe prompt metadata"):
        encode_safe_projection(value)


@pytest.mark.parametrize("profile", list(PolicyProfile))
@pytest.mark.parametrize(
    "mutation",
    [
        "missing_event",
        "wrong_sequence",
        "wrong_trace",
        "wrong_snapshot",
        "nested_alert",
        "timeline_source",
        "timeline_match_flag",
        "early_cutoff",
        "late_cutoff",
    ],
)
def test_linked_direct_investigation_rejects_inconsistent_evidence(
    tmp_path: Path, profile: PolicyProfile, mutation: str
) -> None:
    source, report_path, manifest = direct_investigation_files(tmp_path, profile)
    original = source.read_bytes()
    source_manifest = json.loads(manifest.read_text(encoding="utf-8"))
    source_manifest["entries"] = source_manifest["entries"][:1]
    manifest.write_text(json.dumps(source_manifest), encoding="utf-8")
    source_record = DashboardCatalog.load(manifest).get("source")
    assert source_record is not None
    valid = InvestigationReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    _verify_investigation(valid, source_record)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    incident = report["incidents"][0]
    reference = incident["stages"][0]["evidence"][0]
    if mutation == "missing_event":
        reference["event_id"] = "absent_event"
    elif mutation == "wrong_sequence":
        reference["sequence"] += 1
    elif mutation == "wrong_trace":
        reference["trace_id"] = "different_trace"
    elif mutation == "wrong_snapshot":
        reference["snapshot_fingerprint"] = "0" * 64
    elif mutation == "nested_alert":
        incident["alerts"][0]["description"] = "Changed nested alert."
    elif mutation == "timeline_source":
        incident["timeline"][0]["source_component"] = "different_component"
    elif mutation == "timeline_match_flag":
        incident["timeline"][0]["direct_match_evidence"] = not incident["timeline"][0][
            "direct_match_evidence"
        ]
    elif mutation == "early_cutoff":
        report["evidence_cutoff_sequence"] -= 1
    else:
        report["evidence_cutoff_sequence"] += 1
    report_path.write_text(json.dumps(report), encoding="utf-8")
    # Check linkage independently of projection. The public-loader positive above remains
    # an explicit regression, so a projection failure cannot masquerade as tamper rejection.
    with pytest.raises((DashboardInputError, EvidenceConsistencyError, ValidationError)):
        changed = InvestigationReport.model_validate_json(report_path.read_text(encoding="utf-8"))
        _verify_investigation(changed, source_record)
    assert source.read_bytes() == original
    assert_redacted(tmp_path)


@pytest.mark.parametrize("profile", list(PolicyProfile))
@pytest.mark.parametrize("status", [SourceStatus.INCOMPLETE, SourceStatus.FAILED])
def test_direct_partial_lifecycle_preserves_unknown_outcome_and_exact_cutoff(
    tmp_path: Path, profile: PolicyProfile, status: SourceStatus
) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(
        DIRECT_PROMPT_SCENARIO_ID, tmp_path / "runs", profile=profile
    )
    source = run.run_directory / "events.sqlite3"
    original = source.read_bytes()
    events = read_replay_evidence(source, run.run_id).events
    assert events[-1].event_type == "run.completed"
    partial = events[:-1]
    if status is SourceStatus.FAILED:
        partial.append(
            events[-1].model_copy(
                update={"event_type": "run.failed", "payload": {"error_type": "Controlled"}}
            )
        )
    report = build_investigation(
        investigation_id="partial_direct",
        source_file=source.name,
        events=partial,
        source_status=status,
        rules=load_rules(RULES),
        local_processing_seconds=123,
    )
    assert report.source_status is status
    assert report.evidence_cutoff_sequence == partial[-1].sequence
    assert report.snapshot_fingerprint == fingerprint_snapshot(validate_snapshot(partial, status))
    assert len(report.incidents) == 1
    outcome = report.incidents[0].outcome
    assert outcome.outcome == "unknown" and outcome.source_status is status
    assert outcome.simulated_impact is (True if profile is PolicyProfile.VULNERABLE else None)
    assert outcome.prevention is (True if profile is PolicyProfile.STRICT else None)
    refs = [
        *report.incidents[0].evidence,
        *(item.evidence for item in report.incidents[0].timeline),
        *(ref for stage in report.incidents[0].stages for ref in stage.evidence),
        *outcome.evidence,
    ]
    by_id = {event.event_id: event for event in partial}
    assert all(
        ref.snapshot_fingerprint == report.snapshot_fingerprint
        and ref.sequence == by_id[ref.event_id].sequence <= report.evidence_cutoff_sequence
        and (ref.run_id, ref.trace_id) == (run.run_id, run.trace_id)
        for ref in refs
    )
    text = report.model_dump_json()
    assert load_canary() not in text and "[agentsec:direct-prompt-injection]" not in text
    assert source.read_bytes() == original


@pytest.mark.parametrize(
    "mutation",
    ["missing_link", "duplicate_link", "alert_source", "alert_id", "trace", "channel", "clock"],
)
def test_direct_historical_timing_excludes_invalid_links(tmp_path: Path, mutation: str) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(DIRECT_PROMPT_SCENARIO_ID, tmp_path)
    events = read_replay_evidence(run.run_directory / "events.sqlite3", run.run_id).events
    events = [
        event.model_copy(update={"timestamp": f"2026-10-02T00:00:{event.sequence:02d}Z"})
        for event in events
    ]
    baseline = _historical_timing(tuple(events))
    assert baseline.exclusion_reason is None
    context = next(event for event in events if event.event_type == "agent.context.prompt_added")
    alert = next(event for event in events if event.event_type == "alert.created")
    incident = next(event for event in events if event.event_type == "incident.created")
    assert baseline.alert_seconds == alert.sequence - context.sequence
    assert baseline.incident_seconds == incident.sequence - context.sequence
    target_type = "agent.context.prompt_added" if mutation == "channel" else "incident.created"
    if mutation in {"missing_link", "duplicate_link"}:
        target_type = "detection.match"
    elif mutation == "alert_source":
        target_type = "alert.created"
    changed = []
    for event in events:
        if event.event_type != target_type:
            changed.append(event)
            continue
        updates: dict[str, object] = {}
        if mutation in {"missing_link", "duplicate_link"}:
            ids = list(event.payload["evidence_event_ids"])
            ids[0] = "absent_event" if mutation == "missing_link" else ids[1]
            updates["payload"] = {**event.payload, "evidence_event_ids": ids}
        elif mutation == "alert_source":
            updates["source_component"] = "untrusted_input"
        elif mutation == "alert_id":
            updates["payload"] = {**event.payload, "alert_id": "unlinked_alert"}
        elif mutation == "trace":
            updates["trace_id"] = "different_trace"
        elif mutation == "channel":
            updates["payload"] = {**event.payload, "delivery_channel": "document"}
        else:
            updates["timestamp"] = "2026-10-02T00:00:00Z"
        changed.append(event.model_copy(update=updates))
    timing = _historical_timing(tuple(changed))
    assert timing.exclusion_reason == (
        "clock_order_invalid" if mutation == "clock" else "legacy_linkage_invalid"
    )
    assert timing.alert_seconds is timing.incident_seconds is None


@pytest.mark.parametrize("fault", ["local", "integrity", "report", "resource"])
def test_direct_evaluation_failure_exclusions_and_pairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    original = EvaluationService._validate_child
    errors = {
        "local": RuntimeError,
        "integrity": EvidenceConsistencyError,
        "report": ReportWriteError,
        "resource": ReplayResourceLimitExceeded,
    }
    attempts = 0
    sensitive = load_canary() + load_prompt(PromptFixture.MALICIOUS)

    def fail_first(*args: Any, **kwargs: Any) -> None:
        nonlocal attempts
        attempts += 1
        original(*args, **kwargs)
        if attempts == 1:
            raise errors[fault](sensitive)

    monkeypatch.setattr(EvaluationService, "_validate_child", staticmethod(fail_first))
    result = EvaluationService(id_factory=sequential_ids()).evaluate(
        "direct-injection-v1", 1, tmp_path
    )
    report = result.report
    global_stop = fault != "local"
    assert report.status == "partial" and report.scheduled_children == 6
    assert report.completed_children == (0 if global_stop else 5)
    assert report.failed_children == report.excluded_children == (6 if global_stop else 1)
    assert report.assertion_failures == 0
    assert attempts == (1 if global_stop else 6)
    assert report.children[0].exclusion_reason == f"child_{errors[fault].__name__}"
    if global_stop:
        assert all(
            child.exclusion_reason == "not_run_global_integrity_or_budget"
            and child.relative_directory is None
            and child.observation is None
            and child.timing_exclusion_reason == "child_failed"
            for child in report.children[1:]
        )
    else:
        assert all(child.status == "completed" for child in report.children[1:])
    assert len(list(result.evaluation_directory.rglob("events.sqlite3"))) == attempts
    assert len(report.pairs) == 3
    assert sum(pair.status == "incomplete" for pair in report.pairs) == (3 if global_stop else 1)
    assert report.impact_pair_prevention_numerator == report.impact_pair_prevention_denominator == 0
    assert report.impact_pair_prevention_rate is None
    for metric in report.metrics:
        if global_stop:
            assert metric.numerator == metric.denominator == metric.eligible_count == 0
            assert metric.value is None and metric.unavailable_reason == "no_eligible_samples"
            assert metric.excluded_count == (
                1 if metric.name == "benign_run_false_positive_rate" else 2
            )
        elif metric.name == "attack_run_detection_rate":
            expected = (0, 1, 1) if metric.profile is PolicyProfile.VULNERABLE else (2, 2, 0)
            assert (metric.numerator, metric.denominator, metric.excluded_count) == expected
    assert_redacted(tmp_path)


@pytest.mark.parametrize("elapsed", [float(MAX_EVALUATION_SECONDS), MAX_EVALUATION_SECONDS + 0.001])
def test_direct_suite_deadline_at_and_over_actual_bound(tmp_path: Path, elapsed: float) -> None:
    calls = 0

    def clock() -> float:
        nonlocal calls
        calls += 1
        return 0.0 if calls == 1 else elapsed

    report = (
        EvaluationService(id_factory=sequential_ids(), monotonic_clock=clock)
        .evaluate("direct-injection-v1", 1, tmp_path)
        .report
    )
    over = elapsed > MAX_EVALUATION_SECONDS
    assert report.status == ("partial" if over else "passed")
    assert report.completed_children == (0 if over else 6)
    assert report.failed_children == report.excluded_children == (6 if over else 0)
    assert len(list(tmp_path.rglob("events.sqlite3"))) == (0 if over else 6)
    if over:
        assert all(child.exclusion_reason == "not_run_suite_deadline" for child in report.children)
    assert_redacted(tmp_path)


def test_direct_suite_wrong_expectation_is_failure_not_exclusion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    suite, _ = load_evaluation_suite("direct-injection-v1")
    first = suite.cases[0]
    wrong = first.expectations[0].model_copy(update={"derived_incidents": 0})
    changed_case = first.model_copy(update={"expectations": (wrong, *first.expectations[1:])})
    changed_suite = suite.model_copy(update={"cases": (changed_case, *suite.cases[1:])})
    monkeypatch.setattr(
        evaluation_module,
        "load_evaluation_suite",
        lambda _suite_id: (changed_suite, changed_suite.model_dump(mode="json")),
    )
    assert main(["evaluate", "--suite", "direct-injection-v1", "--output-dir", str(tmp_path)]) == 2
    output = capsys.readouterr()
    assert "status=failed" in output.out and "children=6/6" in output.out
    assert output.err == ""
    data = json.loads(next(tmp_path.rglob("evaluation.json")).read_text(encoding="utf-8"))
    assert data["completed_children"] == 6
    assert data["failed_children"] == data["excluded_children"] == 0
    assert data["assertion_failures"] == 1
    assert data["children"][0]["status"] == "completed"
    assert data["children"][0]["assertion_passed"] is False
    assert_redacted(tmp_path, output.out + output.err)
