from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from agentsec.cli import main
from agentsec.comparison import comparison_conclusion, write_comparison_reports
from agentsec.constants import MAX_REPORT_BYTES, SCENARIO_ID
from agentsec.events import EventStore
from agentsec.models import ApprovalSimulation, DocumentFixture, PolicyProfile, Scenario
from agentsec.reporting import ReportWriteError
from agentsec.resource_loader import load_canary, load_scenario
from agentsec.runner import RunResult, ScenarioDeadlineExceeded, ScenarioRunner

from .helpers import sequential_ids


def test_malicious_scenario_creates_redacted_incident_artifacts(tmp_path: Path) -> None:
    output = tmp_path / "artifacts"
    result = ScenarioRunner(id_factory=sequential_ids()).run(SCENARIO_ID, output)
    raw_canary = load_canary().encode()

    report_data = json.loads((result.run_directory / "report.json").read_text(encoding="utf-8"))
    markdown = (result.run_directory / "report.md").read_bytes()
    database = (result.run_directory / "events.sqlite3").read_bytes()
    store = EventStore(result.run_directory / "events.sqlite3")
    event_types = [event.event_type for event in store.events(result.run_id)]
    store.close()

    assert result.detection.detected
    assert report_data["detection"]["detected"] is True
    assert report_data["detection"]["severity"] == "critical"
    assert report_data["schema_version"] == "0.2"
    assert report_data["outcome"] == "simulated_impact"
    assert report_data["simulated_impact"]["reached"] is True
    assert report_data["prevention"]["blocked"] is False
    assert raw_canary not in markdown
    assert raw_canary not in database
    assert event_types[-2:] == ["report.created", "run.completed"]


@pytest.mark.parametrize(
    "fixture",
    [DocumentFixture.BENIGN, DocumentFixture.MISSING_CANARY],
)
def test_negative_controls_create_no_critical_incident(
    tmp_path: Path, fixture: DocumentFixture
) -> None:
    base = load_scenario(SCENARIO_ID)
    scenario = base.model_copy(update={"document_fixture": fixture})

    result = ScenarioRunner(id_factory=sequential_ids()).run_scenario(scenario, tmp_path)
    report = json.loads((result.run_directory / "report.json").read_text(encoding="utf-8"))

    assert not result.detection.detected
    assert report["detection"]["detected"] is False
    assert report["detection"]["incident_id"] is None


def test_full_run_uses_no_socket_or_dns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network API called")

    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "getaddrinfo", fail)

    result = ScenarioRunner(id_factory=sequential_ids()).run(SCENARIO_ID, tmp_path)

    assert result.detection.detected


def test_two_runs_keep_distinct_evidence(tmp_path: Path) -> None:
    runner = ScenarioRunner(id_factory=sequential_ids())
    first = runner.run(SCENARIO_ID, tmp_path)
    second = runner.run(SCENARIO_ID, tmp_path)

    assert first.run_id != second.run_id
    assert first.run_directory != second.run_directory
    first_store = EventStore(first.run_directory / "events.sqlite3")
    second_store = EventStore(second.run_directory / "events.sqlite3")
    assert {event.run_id for event in first_store.events(first.run_id)} == {first.run_id}
    assert {event.run_id for event in second_store.events(second.run_id)} == {second.run_id}
    first_store.close()
    second_store.close()


def test_runner_refuses_run_directory_overwrite(tmp_path: Path) -> None:
    ids = sequential_ids()

    def fixed_run_id(prefix: str) -> str:
        return "run_fixed" if prefix == "run" else ids(prefix)

    runner = ScenarioRunner(id_factory=fixed_run_id)
    runner.run(SCENARIO_ID, tmp_path)

    with pytest.raises(FileExistsError):
        runner.run(SCENARIO_ID, tmp_path)


def test_deadline_failure_records_no_successful_report(tmp_path: Path) -> None:
    ticks = iter((0.0, 10.0))
    runner = ScenarioRunner(id_factory=sequential_ids(), monotonic_clock=lambda: next(ticks))
    scenario = load_scenario(SCENARIO_ID)

    with pytest.raises(ScenarioDeadlineExceeded):
        runner.run_scenario(scenario, tmp_path)

    run_directory = next(tmp_path.iterdir())
    assert not (run_directory / "report.json").exists()
    store = EventStore(run_directory / "events.sqlite3")
    event_types = [event.event_type for event in store.events("run_1")]
    store.close()
    assert event_types == ["run.started", "run.failed"]


def test_cli_returns_success_and_safe_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = main(["run", SCENARIO_ID, "--output-dir", str(tmp_path)])
    captured = capsys.readouterr()

    assert result == 0
    assert "detected=true" in captured.out
    assert load_canary() not in captured.out
    assert captured.err == ""


def test_strict_scenario_prevents_before_secret_access(tmp_path: Path) -> None:
    result = ScenarioRunner(id_factory=sequential_ids()).run(
        SCENARIO_ID, tmp_path, profile=PolicyProfile.STRICT
    )
    store = EventStore(result.run_directory / "events.sqlite3")
    events = store.events(result.run_id, result.trace_id)
    store.close()
    event_types = [event.event_type for event in events]

    assert result.report.outcome == "prevented"
    assert result.report.prevention.blocked
    assert result.report.prevention.stage == "secret_access"
    assert not result.report.simulated_impact.reached
    assert not result.detection.detected
    assert "policy.denied" in event_types
    assert "file.read" not in event_types
    assert "lab.sink.payload_recorded" not in event_types
    assert sum(event_type == "tool.requested" for event_type in event_types) == 1


def test_strict_approval_cannot_override_secret_read_block(tmp_path: Path) -> None:
    result = ScenarioRunner(id_factory=sequential_ids()).run(
        SCENARIO_ID,
        tmp_path,
        profile=PolicyProfile.STRICT,
        approval_simulation=ApprovalSimulation.APPROVE,
    )
    store = EventStore(result.run_directory / "events.sqlite3")
    event_types = [event.event_type for event in store.events(result.run_id)]
    store.close()

    assert result.report.outcome == "prevented"
    assert "policy.approval_required" not in event_types
    assert "approval.simulated" not in event_types


def test_benign_strict_run_is_not_mislabeled_as_prevention(tmp_path: Path) -> None:
    scenario = load_scenario(SCENARIO_ID).model_copy(
        update={"document_fixture": DocumentFixture.BENIGN}
    )

    result = ScenarioRunner(id_factory=sequential_ids()).run_scenario(
        scenario, tmp_path, profile=PolicyProfile.STRICT
    )

    assert result.report.outcome == "no_correlated_chain"
    assert not result.report.prevention.blocked
    assert not result.report.simulated_impact.reached


def test_compare_creates_isolated_evidence_backed_reports(tmp_path: Path) -> None:
    result = ScenarioRunner(id_factory=sequential_ids()).compare(SCENARIO_ID, tmp_path)
    comparison_json = json.loads(
        (result.comparison_directory / "comparison.json").read_text(encoding="utf-8")
    )
    comparison_markdown = (result.comparison_directory / "comparison.md").read_text(
        encoding="utf-8"
    )

    assert result.vulnerable.report.outcome == "simulated_impact"
    assert result.strict.report.outcome == "prevented"
    assert result.vulnerable.run_id != result.strict.run_id
    assert comparison_json["schema_version"] == "0.2"
    assert [child["profile"] for child in comparison_json["children"]] == [
        "vulnerable",
        "strict",
    ]
    assert [child["outcome"] for child in comparison_json["children"]] == [
        "simulated_impact",
        "prevented",
    ]
    assert "secret_read_blocked" in comparison_json["divergence"]
    assert "vulnerable" in comparison_markdown
    assert "strict" in comparison_markdown
    raw_canary = load_canary().encode()
    assert all(
        raw_canary not in path.read_bytes()
        for path in result.comparison_directory.rglob("*")
        if path.is_file()
    )
    for child in result.report.children:
        for reference in child.evidence_references:
            run_id, event_id = reference.split(":", maxsplit=1)
            run = result.vulnerable if run_id == result.vulnerable.run_id else result.strict
            store = EventStore(run.run_directory / "events.sqlite3")
            assert event_id in {event.event_id for event in store.events(run_id)}
            store.close()


def test_comparison_conclusion_uses_detection_and_prevention_stage(tmp_path: Path) -> None:
    result = ScenarioRunner(id_factory=sequential_ids()).compare(SCENARIO_ID, tmp_path)
    vulnerable, strict = result.report.children
    without_detection = vulnerable.model_copy(update={"detected": False})
    outbound_prevention = strict.model_copy(
        update={"prevention": strict.prevention.model_copy(update={"stage": "outbound_transfer"})}
    )
    incomplete_strict = strict.model_copy(
        update={
            "outcome": "incomplete",
            "simulated_impact": strict.simulated_impact.model_copy(
                update={"reached": True, "evidence_event_ids": ("event_impact",)}
            ),
        }
    )

    no_detection_conclusion = comparison_conclusion(without_detection, strict)
    outbound_conclusion = comparison_conclusion(vulnerable, outbound_prevention)
    incomplete_conclusion = comparison_conclusion(vulnerable, incomplete_strict)

    assert "did not create the expected critical incident" in no_detection_conclusion
    assert "blocked the outbound transfer" in outbound_conclusion
    assert "before fake-secret access" not in outbound_conclusion
    assert "both simulated impact and a secret-access block" in incomplete_conclusion
    assert "outcome is incomplete" in incomplete_conclusion
    assert "prevented the chain" not in incomplete_conclusion


def test_compare_uses_no_socket_or_dns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network API called")

    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "getaddrinfo", fail)

    result = ScenarioRunner(id_factory=sequential_ids()).compare(SCENARIO_ID, tmp_path)

    assert result.vulnerable.report.simulated_impact.reached
    assert result.strict.report.prevention.blocked


def test_cli_supports_strict_and_compare_and_rejects_irrelevant_approval(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    strict_result = main(
        [
            "run",
            SCENARIO_ID,
            "--profile",
            "strict",
            "--output-dir",
            str(tmp_path / "strict"),
        ]
    )
    strict_output = capsys.readouterr()
    compare_result = main(["compare", SCENARIO_ID, "--output-dir", str(tmp_path / "compare")])
    compare_output = capsys.readouterr()
    invalid_result = main(
        [
            "run",
            SCENARIO_ID,
            "--profile",
            "vulnerable",
            "--approval-simulation",
            "approve",
            "--output-dir",
            str(tmp_path / "invalid"),
        ]
    )
    invalid_output = capsys.readouterr()

    assert strict_result == 0
    assert "outcome=prevented" in strict_output.out
    assert compare_result == 0
    assert "vulnerable_outcome=simulated_impact" in compare_output.out
    assert "strict_outcome=prevented" in compare_output.out
    assert invalid_result == 2
    assert "ValueError" in invalid_output.err


def test_comparison_failure_preserves_child_evidence_without_success_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = ScenarioRunner.run_scenario

    def fail_strict(
        self: ScenarioRunner,
        scenario: Scenario,
        output_directory: Path,
        *,
        profile: PolicyProfile = PolicyProfile.VULNERABLE,
        approval_simulation: ApprovalSimulation = ApprovalSimulation.DENY,
    ) -> RunResult:
        if profile is PolicyProfile.STRICT:
            raise RuntimeError("controlled strict child failure")
        return original(
            self,
            scenario,
            output_directory,
            profile=profile,
            approval_simulation=approval_simulation,
        )

    monkeypatch.setattr(ScenarioRunner, "run_scenario", fail_strict)
    runner = ScenarioRunner(id_factory=sequential_ids())

    with pytest.raises(RuntimeError, match="controlled"):
        runner.compare(SCENARIO_ID, tmp_path)

    comparison_directory = next(tmp_path.iterdir())
    assert list(comparison_directory.rglob("events.sqlite3"))
    assert not (comparison_directory / "comparison.json").exists()
    assert not (comparison_directory / "comparison.md").exists()


def test_comparison_writer_rejects_oversized_output(tmp_path: Path) -> None:
    result = ScenarioRunner(id_factory=sequential_ids()).compare(SCENARIO_ID, tmp_path / "source")
    oversized = result.report.model_copy(
        update={"safety_and_limitations": ("x" * MAX_REPORT_BYTES,)}
    )
    output = tmp_path / "oversized"
    output.mkdir()

    with pytest.raises(ReportWriteError, match="size"):
        write_comparison_reports(oversized, output)
