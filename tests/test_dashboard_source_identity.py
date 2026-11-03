"""A5 public-loader/API evidence using only synthetic, in-process SQLite inputs."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from agentsec.constants import SCENARIO_ID
from agentsec.dashboard_api import create_dashboard_app
from agentsec.dashboard_catalog import DashboardCatalog
from agentsec.dashboard_models import ArtifactKind, Provenance
from agentsec.events import EventCollector, EventStore
from agentsec.models import Event, EventSchemaVersion

from .helpers import fixed_clock, sequential_ids

type Row = tuple[str, str, str, dict[str, object]]


def _rows(trace: str, tool: str) -> tuple[Row, ...]:
    return (
        (
            trace,
            "run.started",
            "scenario-controller",
            {
                "scenario_id": SCENARIO_ID,
                "fixture": "benign",
                "profile": "vulnerable",
                "policy_version": "policy-v1",
            },
        ),
        (trace, "tool.requested", "tool-gateway", {"tool": tool}),
        (trace, "tool.executed", "tool-gateway", {"tool": tool}),
        (
            trace,
            "run.completed",
            "scenario-controller",
            {"detected": False, "prevented": False, "simulated_impact": False},
        ),
    )


def _write_source(
    path: Path,
    run_id: str,
    rows: tuple[Row, ...],
    *,
    schema_version: EventSchemaVersion = "0.2",
    event_ids: tuple[str, ...] | None = None,
) -> tuple[Event, ...]:
    identities = iter(event_ids) if event_ids is not None else None
    generated_id = sequential_ids()

    def identify(prefix: str) -> str:
        return next(identities) if identities is not None else generated_id(prefix)

    events = []
    store = EventStore(path)
    try:
        for trace, event_type, component, payload in rows:
            # Re-read the run's next sequence when switching between trace collectors.
            collector = EventCollector(
                store,
                run_id,
                trace,
                id_factory=identify,
                clock=fixed_clock,
                schema_version=schema_version,
            )
            events.append(collector.emit(event_type, component, payload))
    finally:
        store.close()
    return tuple(events)


def _manifest(root: Path, entries: list[dict[str, str]]) -> Path:
    path = root / "manifest.json"
    path.write_text(json.dumps({"schema_version": "1.0", "entries": entries}), encoding="utf-8")
    return path


def _entry(item_id: str, path: Path, run_id: str) -> dict[str, str]:
    return {"id": item_id, "kind": "event_source", "path": path.name, "run_id": run_id}


def _snapshot(root: Path) -> tuple[set[Path], dict[Path, bytes]]:
    inventory = set(root.rglob("*"))
    return inventory, {path: path.read_bytes() for path in inventory if path.is_file()}


def _assert_page(
    client: TestClient, route: str, expected: list[dict[str, Any]], **filters: str
) -> None:
    received = []
    total = len(expected)
    for offset in (*range(0, total, 2), total, total + 2):
        response = client.get(route, params={"offset": offset, "limit": 2, **filters})
        assert response.status_code == 200
        page = response.json()
        assert page == {
            "items": expected[offset : offset + 2],
            "total": total,
            "offset": offset,
            "limit": 2,
        }
        received.extend(page["items"])
    assert received == expected


def test_duplicate_event_ids_resolve_only_in_selected_catalog_source(tmp_path: Path) -> None:
    sources = {}
    expected = {}
    entries = []
    for side, tool in (("left", "read_file"), ("right", "http_post")):
        path = tmp_path / f"{side}.sqlite3"
        sources[side] = _write_source(
            path,
            f"run_{side}",
            _rows(f"trace_{side}", tool),
            event_ids=("evt_start", "evt_shared", f"evt_only_{side}", "evt_end"),
        )
        expected[side] = [event.model_dump(mode="json") for event in sources[side]]
        entries.append(_entry(f"source_{side}", path, f"run_{side}"))
    assert expected["left"][1]["event_id"] == expected["right"][1]["event_id"] == "evt_shared"
    assert expected["left"][1] != expected["right"][1]
    manifest = _manifest(tmp_path, entries)
    before = _snapshot(tmp_path)
    catalog = DashboardCatalog.load(manifest)
    assert len(catalog.records) == 2
    for side in sources:
        record = catalog.get(f"source_{side}")
        assert record is not None
        assert record.summary.kind is ArtifactKind.EVENT_SOURCE
        assert record.summary.provenance is Provenance.VERIFIED
        assert record.events == sources[side]
        assert record.data["run_id"] == f"run_{side}"
        assert record.data["trace_ids"] == [f"trace_{side}"]
        assert record.data["event_count"] == 4
    records_before = deepcopy(catalog.records)

    with TestClient(create_dashboard_app(catalog), base_url="http://127.0.0.1:8765") as client:
        # Alternate repeatedly to expose any lookup/cache keyed by event ID alone.
        for side in ("right", "left", "right", "left"):
            route = f"/api/v1/runs/source_{side}/events"
            detail = client.get(f"{route}/evt_shared")
            assert detail.status_code == 200
            assert detail.json() == expected[side][1]
            _assert_page(client, route, expected[side])
            other = "right" if side == "left" else "left"
            missing = client.get(f"{route}/evt_only_{other}")
            assert missing.status_code == 404
            assert missing.json() == {"error": {"code": "not_found"}}
            wrong_identity = client.get(f"/api/v1/runs/run_{side}/events/evt_shared")
            assert wrong_identity.status_code == 404  # Routes use opaque catalog IDs.
    assert _snapshot(tmp_path) == before
    assert catalog.records == records_before


def test_legacy_event_identity_survives_public_loader_and_api(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    events = _write_source(
        path, "legacy_run", _rows("legacy_trace", "read_file"), schema_version="0.1"
    )
    expected = [event.model_dump(mode="json") for event in events]
    assert all(item["schema_version"] == "0.1" for item in expected)
    manifest = _manifest(tmp_path, [_entry("legacy_source", path, "legacy_run")])
    before = _snapshot(tmp_path)
    catalog = DashboardCatalog.load(manifest)
    assert catalog.records[0].events == events
    assert catalog.records[0].summary.provenance is Provenance.VERIFIED
    records_before = deepcopy(catalog.records)

    with TestClient(create_dashboard_app(catalog), base_url="http://127.0.0.1:8765") as client:
        route = "/api/v1/runs/legacy_source/events"
        _assert_page(client, route, expected)
        detail = client.get(f"{route}/{events[1].event_id}")
        assert detail.status_code == 200
        assert detail.json() == expected[1]
        _assert_page(client, route, [expected[1]], event_type="tool.requested")
    assert _snapshot(tmp_path) == before
    assert catalog.records == records_before


def test_multi_trace_filters_preserve_source_sequence_and_exact_identity(tmp_path: Path) -> None:
    path = tmp_path / "multi.sqlite3"
    lifecycle = _rows("trace_controller", "read_file")
    rows: tuple[Row, ...] = (
        lifecycle[0],
        ("trace_a", "tool.requested", "tool-gateway", {"tool": "read_file"}),
        ("trace_b", "tool.requested", "tool-gateway", {"tool": "http_post"}),
        ("trace_a", "tool.executed", "tool-gateway", {"tool": "read_file"}),
        ("trace_b", "tool.executed", "tool-gateway", {"tool": "http_post"}),
        lifecycle[-1],
    )
    events = _write_source(path, "multi_run", rows)
    expected = [event.model_dump(mode="json") for event in events]
    assert [item["sequence"] for item in expected] == [1, 2, 3, 4, 5, 6]
    manifest = _manifest(tmp_path, [_entry("multi_source", path, "multi_run")])
    before = _snapshot(tmp_path)
    catalog = DashboardCatalog.load(manifest)
    assert catalog.records[0].events == events
    assert catalog.records[0].data["trace_ids"] == ["trace_a", "trace_b", "trace_controller"]
    records_before = deepcopy(catalog.records)

    with TestClient(create_dashboard_app(catalog), base_url="http://127.0.0.1:8765") as client:
        route = "/api/v1/runs/multi_source/events"
        _assert_page(client, route, expected)
        for trace in ("trace_b", "trace_a", "trace_controller"):
            selected = [item for item in expected if item["trace_id"] == trace]
            _assert_page(client, route, selected, trace_id=trace)
            requested = [item for item in selected if item["event_type"] == "tool.requested"]
            _assert_page(client, route, requested, trace_id=trace, event_type="tool.requested")
            for item in selected:
                detail = client.get(f"{route}/{item['event_id']}")
                assert detail.status_code == 200
                assert detail.json() == item
        _assert_page(client, route, [], trace_id="missing_trace")
        _assert_page(client, route, [], event_type="missing.event")
        _assert_page(client, route, [], trace_id="trace_a", event_type="run.completed")
        _assert_page(client, route, expected)  # Filtered requests must not mutate later reads.
    assert _snapshot(tmp_path) == before
    assert catalog.records == records_before
