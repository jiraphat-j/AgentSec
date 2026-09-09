"""Trusted event construction and canonical SQLite persistence."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .constants import MAX_EVENT_PAYLOAD_BYTES, MAX_EVENTS, MAX_OPERATIONAL_EVENTS
from .models import Event, EventSchemaVersion


class EventLimitExceeded(RuntimeError):
    """Raised before the event store can exceed its fixed ceiling."""


class EvidenceLeakError(RuntimeError):
    """Raised when a forbidden raw value reaches persisted evidence."""


class EventPayloadTooLarge(RuntimeError):
    """Raised when one persisted payload exceeds the fixed ceiling."""


class EventStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._connection = sqlite3.connect(path)
        self._connection.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_component TEXT NOT NULL,
                tool_call_id TEXT,
                schema_version TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                UNIQUE(run_id, sequence)
            );
            CREATE INDEX IF NOT EXISTS idx_events_run_trace
                ON events(run_id, trace_id, sequence);
            CREATE INDEX IF NOT EXISTS idx_events_type
                ON events(event_type, run_id, trace_id);
            CREATE TRIGGER IF NOT EXISTS events_no_update
                BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS events_no_delete
                BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
            """
        )
        self._connection.commit()

    def _append(self, event: Event) -> None:
        payload_json = json.dumps(
            event.payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO events (
                    event_id, run_id, trace_id, sequence, timestamp, event_type,
                    source_component, tool_call_id, schema_version, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.run_id,
                    event.trace_id,
                    event.sequence,
                    event.timestamp,
                    event.event_type,
                    event.source_component,
                    event.tool_call_id,
                    event.schema_version,
                    payload_json,
                ),
            )

    def events(self, run_id: str, trace_id: str | None = None) -> list[Event]:
        parameters: tuple[str, ...]
        if trace_id is None:
            query = "SELECT * FROM events WHERE run_id = ? ORDER BY sequence"
            parameters = (run_id,)
        else:
            query = "SELECT * FROM events WHERE run_id = ? AND trace_id = ? ORDER BY sequence"
            parameters = (run_id, trace_id)
        rows = self._connection.execute(query, parameters).fetchall()
        return [self._event_from_row(row) for row in rows]

    def max_sequence(self, run_id: str) -> int:
        row = self._connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) AS value FROM events WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return 0
        return int(row["value"])

    def close(self) -> None:
        self._connection.close()

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> Event:
        return Event.model_validate(
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
                "payload": json.loads(row["payload_json"]),
            }
        )


def default_id_factory(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def default_clock() -> datetime:
    return datetime.now(UTC)


class EventCollector:
    def __init__(
        self,
        store: EventStore,
        run_id: str,
        trace_id: str,
        *,
        forbidden_values: Iterable[str] = (),
        id_factory: Callable[[str], str] = default_id_factory,
        clock: Callable[[], datetime] = default_clock,
        schema_version: EventSchemaVersion = "0.2",
    ) -> None:
        self.store = store
        self.run_id = run_id
        self.trace_id = trace_id
        self._forbidden_values = tuple(value for value in forbidden_values if value)
        self._id_factory = id_factory
        self._clock = clock
        if schema_version not in {"0.1", "0.2"}:
            raise ValueError("unsupported event schema version")
        self._schema_version = schema_version
        self._next_sequence = store.max_sequence(run_id) + 1

    def emit(
        self,
        event_type: str,
        source_component: str,
        payload: dict[str, object] | None = None,
        *,
        tool_call_id: str | None = None,
        finalization: bool = False,
    ) -> Event:
        ceiling = MAX_EVENTS if finalization else MAX_OPERATIONAL_EVENTS
        if self._next_sequence > ceiling:
            raise EventLimitExceeded(f"event ceiling {ceiling} reached")
        safe_payload = payload or {}
        serialized = json.dumps(
            safe_payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        if len(serialized.encode("utf-8")) > MAX_EVENT_PAYLOAD_BYTES:
            raise EventPayloadTooLarge("event payload exceeds fixed size limit")
        if any(value in serialized for value in self._forbidden_values):
            raise EvidenceLeakError("raw canary rejected from persisted evidence")
        event = Event(
            schema_version=self._schema_version,
            event_id=self._id_factory("evt"),
            run_id=self.run_id,
            trace_id=self.trace_id,
            sequence=self._next_sequence,
            timestamp=self._clock().isoformat().replace("+00:00", "Z"),
            event_type=event_type,
            source_component=source_component,
            tool_call_id=tool_call_id,
            payload=safe_payload,
        )
        self.store._append(event)
        self._next_sequence += 1
        return event
