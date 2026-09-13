"""Read-only SQLite replay over bounded canonical event evidence."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

from pydantic import ValidationError

from .constants import (
    MAX_EVENT_PAYLOAD_BYTES,
    MAX_REPLAY_DATABASE_BYTES,
    MAX_REPLAY_EVENTS,
)
from .events import default_id_factory
from .models import Event
from .rule_engine import evaluate_rules, load_rules
from .rule_models import ReplayReport, SourceStatus

_DERIVED_EVENT_TYPES = {
    "alert.created",
    "incident.created",
    "report.created",
}
_MAX_SQLITE_VM_STEPS = 5_000_000


class ReplayInputError(ValueError):
    """Raised for missing, malformed, or conflicting source evidence."""


class ReplayResourceLimitExceeded(RuntimeError):
    """Raised when replay evidence exceeds a fixed resource limit."""


@dataclass(frozen=True, slots=True)
class ReplayEvidence:
    events: list[Event]
    evaluated_events: list[Event]
    source_status: SourceStatus
    evidence_cutoff_sequence: int


@dataclass(frozen=True, slots=True)
class ReplayResult:
    replay_directory: Path
    report: ReplayReport


def _safe_source_name(path: Path) -> str:
    name = path.name
    if not name or len(name) > 255 or any(ord(character) < 32 for character in name):
        raise ReplayInputError("source filename is invalid")
    return name


def read_replay_evidence(path: Path, run_id: str) -> ReplayEvidence:
    if not path.is_file():
        raise ReplayInputError("event database does not exist")
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ReplayInputError("unable to inspect event database") from error
    if size > MAX_REPLAY_DATABASE_BYTES:
        raise ReplayResourceLimitExceeded("event database exceeds fixed limit")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", run_id):
        raise ReplayInputError("run ID is invalid")

    uri = f"{path.resolve().as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
        connection.row_factory = sqlite3.Row
        connection.enable_load_extension(False)
        connection.execute("PRAGMA query_only = ON")
        progress_calls = 0

        def bound_query() -> int:
            nonlocal progress_calls
            progress_calls += 1
            return int(progress_calls * 1000 > _MAX_SQLITE_VM_STEPS)

        connection.set_progress_handler(bound_query, 1000)
        connection.execute("BEGIN")
        schema = connection.execute(
            "SELECT type FROM sqlite_master WHERE name = ?", ("events",)
        ).fetchone()
        if schema is None or schema["type"] != "table":
            raise ReplayInputError("event database must contain a canonical events table")
        rows = connection.execute(
            """
            SELECT event_id, run_id, trace_id, sequence, timestamp, event_type,
                   source_component, tool_call_id, schema_version, payload_json
            FROM events
            WHERE run_id = ?
            ORDER BY sequence
            LIMIT ?
            """,
            (run_id, MAX_REPLAY_EVENTS + 1),
        ).fetchall()
    except sqlite3.Error as error:
        if "interrupted" in str(error).lower():
            raise ReplayResourceLimitExceeded(
                "event database query exceeds fixed work limit"
            ) from error
        raise ReplayInputError("event database is not a supported canonical store") from error
    finally:
        if "connection" in locals():
            connection.close()

    if not rows:
        raise ReplayInputError("selected run has no events")
    if len(rows) > MAX_REPLAY_EVENTS:
        raise ReplayResourceLimitExceeded("selected run exceeds fixed event limit")
    events: list[Event] = []
    try:
        for row in rows:
            payload_json = str(row["payload_json"])
            if len(payload_json.encode("utf-8")) > MAX_EVENT_PAYLOAD_BYTES:
                raise ReplayResourceLimitExceeded("event payload exceeds fixed limit")
            events.append(
                Event.model_validate(
                    {
                        "schema_version": row["schema_version"],
                        "event_id": row["event_id"],
                        "run_id": row["run_id"],
                        "trace_id": row["trace_id"],
                        "sequence": row["sequence"],
                        "timestamp": row["timestamp"],
                        "event_type": row["event_type"],
                        "source_component": row["source_component"],
                        "tool_call_id": row["tool_call_id"],
                        "payload": json.loads(payload_json),
                    }
                )
            )
    except (json.JSONDecodeError, ValidationError, UnicodeError, TypeError) as error:
        raise ReplayInputError("event database contains invalid evidence") from error

    event_ids = [event.event_id for event in events]
    sequences = [event.sequence for event in events]
    if len(event_ids) != len(set(event_ids)) or len(sequences) != len(set(sequences)):
        raise ReplayInputError("event database contains duplicate evidence identities")
    completed = [event for event in events if event.event_type == "run.completed"]
    failed = [event for event in events if event.event_type == "run.failed"]
    if len(completed) > 1 or len(failed) > 1 or (completed and failed):
        raise ReplayInputError("event database contains conflicting lifecycle evidence")
    source_status = (
        SourceStatus.COMPLETED
        if completed
        else SourceStatus.FAILED
        if failed
        else SourceStatus.INCOMPLETE
    )
    evaluated = [
        event
        for event in events
        if not event.event_type.startswith("detection.")
        and event.event_type not in _DERIVED_EVENT_TYPES
    ]
    return ReplayEvidence(events, evaluated, source_status, max(sequences))


class ReplayService:
    def __init__(
        self,
        *,
        id_factory: Callable[[str], str] = default_id_factory,
        monotonic_clock: Callable[[], float] = monotonic,
    ) -> None:
        self._id_factory = id_factory
        self._monotonic_clock = monotonic_clock

    def replay(
        self,
        source: Path,
        run_id: str,
        rules_directory: Path,
        output_directory: Path,
    ) -> ReplayResult:
        from .detection_reporting import write_replay_report

        rules = load_rules(rules_directory)
        evidence = read_replay_evidence(source, run_id)
        started = self._monotonic_clock()
        evaluations = evaluate_rules(rules, evidence.evaluated_events)
        elapsed = max(self._monotonic_clock() - started, 0.0)
        report = ReplayReport(
            replay_id=self._id_factory("replay"),
            source_file=_safe_source_name(source),
            source_run_id=run_id,
            source_status=evidence.source_status,
            evidence_cutoff_sequence=evidence.evidence_cutoff_sequence,
            input_event_count=len(evidence.events),
            evaluated_event_count=len(evidence.evaluated_events),
            evaluations=evaluations,
            total_matches=sum(len(evaluation.matches) for evaluation in evaluations),
            duplicate_matches_removed=sum(
                evaluation.duplicate_matches_removed for evaluation in evaluations
            ),
            local_processing_seconds=elapsed,
            safety_and_limitations=(
                "Replay reads one existing SQLite run without invoking agents or adapters.",
                "Local processing time excludes input and report output and is not MTTD or MTTR.",
                "Synthetic fixture matches do not establish real-world detection accuracy.",
            ),
        )
        output_directory.mkdir(parents=True, exist_ok=True)
        replay_directory = output_directory / report.replay_id
        replay_directory.mkdir(exist_ok=False)
        write_replay_report(report, replay_directory)
        return ReplayResult(replay_directory, report)
