from __future__ import annotations

import json
import socket
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

import agentsec.replay as replay_module
from agentsec.adapters import LabHttpSinkAdapter, VirtualFileAdapter
from agentsec.cli import main
from agentsec.constants import MAX_REPORT_BYTES, SCENARIO_ID
from agentsec.detection_reporting import write_replay_report
from agentsec.events import EventCollector, EventStore
from agentsec.replay import (
    ReplayInputError,
    ReplayResourceLimitExceeded,
    ReplayService,
    read_replay_evidence,
)
from agentsec.reporting import ReportWriteError
from agentsec.resource_loader import load_canary
from agentsec.rule_engine import load_rules
from agentsec.rule_models import SourceStatus
from agentsec.rule_testing import execute_rule_tests
from agentsec.runner import ScenarioRunner

from .helpers import sequential_ids

RESOURCE_ROOT = Path(__file__).parents[1] / "src" / "agentsec" / "resources"
RULES = RESOURCE_ROOT / "rules"
FIXTURES = RESOURCE_ROOT / "rule_fixtures"


def test_rule_fixture_command_writes_complete_coverage_report(tmp_path: Path) -> None:
    result = execute_rule_tests(RULES, FIXTURES, tmp_path / "rule-tests")
    data = json.loads((result.output_directory / "rule-tests.json").read_text(encoding="utf-8"))

    assert result.report.status == "passed"
    assert data["covered_rules"] == data["total_rules"] == 3
    assert data["assertions_passed"] == data["assertions_total"] == 6
    assert (result.output_directory / "rule-tests.md").is_file()


def test_replay_is_read_only_deterministic_and_invokes_no_runtime_adapters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(SCENARIO_ID, tmp_path / "source")
    source = run.run_directory / "events.sqlite3"
    before = source.read_bytes()

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("runtime adapter or network API called during replay")

    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(VirtualFileAdapter, "read", fail)
    monkeypatch.setattr(LabHttpSinkAdapter, "record", fail)

    replay = ReplayService(id_factory=sequential_ids(), monotonic_clock=lambda: 1.0).replay(
        source, run.run_id, RULES, tmp_path / "replays"
    )

    assert source.read_bytes() == before
    assert replay.report.source_status is SourceStatus.COMPLETED
    assert replay.report.total_matches == 2
    assert replay.report.local_processing_seconds == 0
    assert replay.report.evaluated_event_count < replay.report.input_event_count
    assert [evaluation.rule_id for evaluation in replay.report.evaluations] == [
        "ASL-CORR-002",
        "ASL-EVENT-001",
        "ASL-SEQ-001",
    ]
    for evaluation in replay.report.evaluations:
        for match in evaluation.matches:
            assert match.run_id == run.run_id
            assert match.evidence_event_ids
    assert (replay.replay_directory / "replay.json").is_file()
    assert (replay.replay_directory / "replay.md").is_file()


def test_imported_events_view_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "view.sqlite3"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE VIEW events AS SELECT 'run_1' AS run_id")
    with pytest.raises(ReplayInputError, match="canonical events table"):
        read_replay_evidence(path, "run_1")


def test_imported_query_work_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "large-scan.sqlite3"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "CREATE TABLE events (event_id TEXT, run_id TEXT, trace_id TEXT, "
            "sequence INTEGER, timestamp TEXT, event_type TEXT, source_component TEXT, "
            "tool_call_id TEXT, schema_version TEXT, payload_json TEXT)"
        )
        connection.executemany(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                (
                    f"evt_{sequence}",
                    "run_1",
                    "trace_1",
                    sequence,
                    "2026-09-13T00:00:00Z",
                    "noise",
                    "fixture",
                    None,
                    "0.2",
                    "{}",
                )
                for sequence in range(1, 1501)
            ),
        )
        connection.commit()
    monkeypatch.setattr(replay_module, "_MAX_SQLITE_VM_STEPS", 0)
    with pytest.raises(ReplayResourceLimitExceeded, match="query exceeds"):
        read_replay_evidence(path, "run_1")


def test_replay_labels_failed_and_incomplete_sources_without_prevention_claim(
    tmp_path: Path,
) -> None:
    failed_path = tmp_path / "failed.sqlite3"
    failed_store = EventStore(failed_path)
    failed_collector = EventCollector(
        failed_store, "run_failed", "trace_1", id_factory=sequential_ids()
    )
    failed_collector.emit("run.started", "controller", {})
    failed_collector.emit("run.failed", "controller", {"error_type": "Controlled"})
    failed_store.close()

    failed = ReplayService(id_factory=sequential_ids()).replay(
        failed_path, "run_failed", RULES, tmp_path / "failed-output"
    )
    markdown = (failed.replay_directory / "replay.md").read_text(encoding="utf-8")
    assert failed.report.source_status is SourceStatus.FAILED
    assert "prevention" not in markdown.lower()

    incomplete_path = tmp_path / "incomplete.sqlite3"
    incomplete_store = EventStore(incomplete_path)
    EventCollector(incomplete_store, "run_incomplete", "trace_1", id_factory=sequential_ids()).emit(
        "run.started", "controller", {}
    )
    incomplete_store.close()
    incomplete = read_replay_evidence(incomplete_path, "run_incomplete")
    assert incomplete.source_status is SourceStatus.INCOMPLETE


def test_replay_rejects_missing_malformed_and_conflicting_sources(tmp_path: Path) -> None:
    missing = tmp_path / "missing.sqlite3"
    with pytest.raises(ReplayInputError, match="does not exist"):
        read_replay_evidence(missing, "run_1")
    assert not missing.exists()

    malformed = tmp_path / "malformed.sqlite3"
    malformed.write_bytes(b"not a sqlite database")
    with pytest.raises(ReplayInputError, match="supported canonical"):
        read_replay_evidence(malformed, "run_1")

    conflicting = tmp_path / "conflicting.sqlite3"
    store = EventStore(conflicting)
    collector = EventCollector(store, "run_1", "trace_1", id_factory=sequential_ids())
    collector.emit("run.completed", "controller", {})
    collector.emit("run.failed", "controller", {})
    store.close()
    with pytest.raises(ReplayInputError, match="conflicting lifecycle"):
        read_replay_evidence(conflicting, "run_1")


def test_replay_rejects_unknown_event_version(tmp_path: Path) -> None:
    database = tmp_path / "unknown.sqlite3"
    store = EventStore(database)
    store.close()
    connection = sqlite3.connect(database)
    connection.execute(
        """
        INSERT INTO events (
            event_id, run_id, trace_id, sequence, timestamp, event_type,
            source_component, tool_call_id, schema_version, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "evt_1",
            "run_1",
            "trace_1",
            1,
            "2026-09-09T00:00:00Z",
            "run.started",
            "controller",
            None,
            "9.9",
            "{}",
        ),
    )
    connection.commit()
    connection.close()

    with pytest.raises(ReplayInputError, match="invalid evidence"):
        read_replay_evidence(database, "run_1")


def test_replay_report_rejects_overwrite_oversize_and_raw_canary(tmp_path: Path) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(SCENARIO_ID, tmp_path / "source")
    replay = ReplayService(id_factory=sequential_ids()).replay(
        run.run_directory / "events.sqlite3",
        run.run_id,
        RULES,
        tmp_path / "replays",
    )
    with pytest.raises(ReportWriteError, match="overwrite"):
        write_replay_report(replay.report, replay.replay_directory)

    oversized_directory = tmp_path / "oversized"
    oversized_directory.mkdir()
    oversized = replay.report.model_copy(
        update={"safety_and_limitations": ("x" * MAX_REPORT_BYTES,)}
    )
    with pytest.raises(ReportWriteError, match="size"):
        write_replay_report(oversized, oversized_directory)

    canary_directory = tmp_path / "canary"
    canary_directory.mkdir()
    contains_canary = replay.report.model_copy(update={"source_file": load_canary()})
    with pytest.raises(ReportWriteError, match="raw lab canary"):
        write_replay_report(contains_canary, canary_directory)


def test_phase_3_cli_validate_test_and_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(SCENARIO_ID, tmp_path / "source")

    class UnexpectedScenarioRunner:
        def __init__(self) -> None:
            raise AssertionError("detection-only CLI instantiated the scenario runtime")

    monkeypatch.setattr("agentsec.cli.ScenarioRunner", UnexpectedScenarioRunner)
    validated = main(["rules", "validate", "--rules", str(RULES)])
    tested = main(
        [
            "rules",
            "test",
            "--rules",
            str(RULES),
            "--fixtures",
            str(FIXTURES),
            "--output-dir",
            str(tmp_path / "rule-tests"),
        ]
    )
    replayed = main(
        [
            "replay",
            "--events",
            str(run.run_directory / "events.sqlite3"),
            "--run-id",
            run.run_id,
            "--rules",
            str(RULES),
            "--output-dir",
            str(tmp_path / "replay"),
        ]
    )

    assert validated == tested == replayed == 0
    assert len(load_rules(RULES)) == 3


def test_phase_3_cli_distinguishes_invalid_input_from_resource_limits(tmp_path: Path) -> None:
    invalid_rules = tmp_path / "invalid-rules"
    invalid_rules.mkdir()
    (invalid_rules / "invalid.json").write_text("{}", encoding="utf-8")
    oversized_rules = tmp_path / "oversized-rules"
    oversized_rules.mkdir()
    (oversized_rules / "oversized.json").write_bytes(b"x" * (64 * 1024 + 1))

    assert main(["rules", "validate", "--rules", str(invalid_rules)]) == 2
    assert main(["rules", "validate", "--rules", str(oversized_rules)]) == 1
