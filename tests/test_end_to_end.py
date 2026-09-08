from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from agentsec.cli import main
from agentsec.constants import SCENARIO_ID
from agentsec.events import EventStore
from agentsec.models import DocumentFixture
from agentsec.resource_loader import load_canary, load_scenario
from agentsec.runner import ScenarioDeadlineExceeded, ScenarioRunner

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
