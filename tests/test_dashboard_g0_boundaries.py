"""G0 regressions for dashboard path, redaction, and resource boundaries."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import IO, Any

import httpx
import pytest
from pydantic import ValidationError

import agentsec.dashboard_api as api
import agentsec.dashboard_catalog as catalog_module
from agentsec.constants import (
    MAX_DASHBOARD_ENTRIES,
    MAX_DASHBOARD_MANIFEST_BYTES,
    MAX_DASHBOARD_QUERY_BYTES,
    MAX_DASHBOARD_RESPONSE_BYTES,
    MAX_DASHBOARD_RUNS,
    MAX_REPORT_BYTES,
    MAX_RULE_BYTES,
)
from agentsec.dashboard_catalog import (
    DashboardCatalog,
    DashboardInputError,
    DashboardResourceLimitExceeded,
    encode_safe_projection,
)
from agentsec.dashboard_models import DashboardManifest
from agentsec.events import EventCollector, EventStore
from agentsec.resource_loader import load_canary

from .helpers import sequential_ids


def write_manifest(path: Path, entries: list[dict[str, object]]) -> None:
    path.write_text(json.dumps({"schema_version": "1.0", "entries": entries}), encoding="utf-8")


def write_rule_test(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "status": "passed",
                "total_rules": 0,
                "covered_rules": 0,
                "assertions_passed": 0,
                "assertions_total": 0,
                "results": [],
            }
        ),
        encoding="utf-8",
    )


def write_source(path: Path, *, tool: str | None = None) -> None:
    store = EventStore(path)
    collector = EventCollector(store, "run_1", "trace_1", id_factory=sequential_ids())
    collector.emit("run.started", "scenario-controller", {"profile": "vulnerable"})
    if tool is not None:
        collector.emit("tool.requested", "tool-gateway", {"tool": tool})
    store.close()


def source_entries(count: int) -> list[dict[str, object]]:
    return [
        {
            "id": f"source_{index}",
            "kind": "event_source",
            "path": "events.sqlite3",
            "run_id": "run_1",
        }
        for index in range(count)
    ]


def test_manifest_size_accepts_exact_ceiling_and_rejects_one_byte_over(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    data = b'{"schema_version":"1.0","entries":[]}'
    exact = data + b" " * (MAX_DASHBOARD_MANIFEST_BYTES - len(data))
    path.write_bytes(exact)
    assert DashboardCatalog.load(path).records == ()
    assert path.read_bytes() == exact
    path.write_bytes(exact + b" ")
    with pytest.raises(DashboardResourceLimitExceeded, match="manifest exceeds"):
        DashboardCatalog.load(path)
    assert path.read_bytes() == exact + b" "


def test_manifest_entry_count_at_and_over_configured_ceiling(tmp_path: Path) -> None:
    write_rule_test(tmp_path / "report.json")
    entries: list[dict[str, object]] = [
        {"id": f"report_{index}", "kind": "rule_test", "path": "report.json"}
        for index in range(MAX_DASHBOARD_ENTRIES + 1)
    ]
    path = tmp_path / "manifest.json"
    write_manifest(path, entries[:-1])
    assert len(DashboardCatalog.load(path).records) == MAX_DASHBOARD_ENTRIES
    write_manifest(path, entries)
    with pytest.raises(DashboardInputError, match="manifest failed validation"):
        DashboardCatalog.load(path)
    with pytest.raises(ValidationError):
        DashboardManifest.model_validate_json(path.read_bytes())


def test_source_count_at_and_over_configured_ceiling(tmp_path: Path) -> None:
    write_source(tmp_path / "events.sqlite3")
    path = tmp_path / "manifest.json"
    write_manifest(path, source_entries(MAX_DASHBOARD_RUNS))
    assert len(DashboardCatalog.load(path).records) == MAX_DASHBOARD_RUNS
    write_manifest(path, source_entries(MAX_DASHBOARD_RUNS + 1))
    with pytest.raises(DashboardResourceLimitExceeded, match="run count"):
        DashboardCatalog.load(path)


@pytest.mark.parametrize("kind", ["rule", "rule_test"])
def test_selected_json_file_at_and_over_configured_ceiling(tmp_path: Path, kind: str) -> None:
    artifact = tmp_path / "artifact.json"
    if kind == "rule":
        resource = Path(__file__).parents[1] / "src/agentsec/resources/rules/asl-corr-003-v1.json"
        data = resource.read_bytes()
        ceiling = MAX_RULE_BYTES
    else:
        write_rule_test(artifact)
        data = artifact.read_bytes()
        ceiling = MAX_REPORT_BYTES
    exact = data + b" " * (ceiling - len(data))
    artifact.write_bytes(exact)
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, [{"id": "artifact", "kind": kind, "path": artifact.name}])
    assert DashboardCatalog.load(manifest).get("artifact") is not None
    artifact.write_bytes(exact + b" ")
    with pytest.raises(DashboardResourceLimitExceeded, match="selected artifact"):
        DashboardCatalog.load(manifest)


def test_cumulative_selected_bytes_at_and_over_reduced_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "report.json"
    write_rule_test(artifact)
    manifest = tmp_path / "manifest.json"
    write_manifest(
        manifest,
        [
            {"id": "first", "kind": "rule_test", "path": artifact.name},
            {"id": "second", "kind": "rule_test", "path": artifact.name},
        ],
    )
    exact = artifact.stat().st_size * 2
    monkeypatch.setattr(catalog_module, "MAX_DASHBOARD_INPUT_BYTES", exact)
    assert len(DashboardCatalog.load(manifest).records) == 2
    monkeypatch.setattr(catalog_module, "MAX_DASHBOARD_INPUT_BYTES", exact - 1)
    with pytest.raises(DashboardResourceLimitExceeded, match="aggregate limit"):
        DashboardCatalog.load(manifest)


def test_cumulative_events_at_and_over_reduced_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_source(tmp_path / "events.sqlite3")
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, source_entries(2))
    monkeypatch.setattr(catalog_module, "MAX_DASHBOARD_EVENTS", 2)
    assert len(DashboardCatalog.load(manifest).records) == 2
    monkeypatch.setattr(catalog_module, "MAX_DASHBOARD_EVENTS", 1)
    with pytest.raises(DashboardResourceLimitExceeded, match="event count"):
        DashboardCatalog.load(manifest)


def test_projection_bytes_at_and_over_reduced_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_rule_test(tmp_path / "report.json")
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, [{"id": "report", "kind": "rule_test", "path": "report.json"}])
    record = DashboardCatalog.load(manifest).get("report")
    assert record is not None
    exact = len(encode_safe_projection(record.data))
    monkeypatch.setattr(catalog_module, "MAX_DASHBOARD_PROJECTION_BYTES", exact)
    assert DashboardCatalog.load(manifest).get("report") is not None
    monkeypatch.setattr(catalog_module, "MAX_DASHBOARD_PROJECTION_BYTES", exact - 1)
    with pytest.raises(DashboardResourceLimitExceeded, match="projections"):
        DashboardCatalog.load(manifest)


@pytest.mark.parametrize("elapsed", [30.0, 30.001])
def test_startup_deadline_at_and_over_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, elapsed: float
) -> None:
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, [])
    ticks = iter((0.0, elapsed))
    monkeypatch.setattr(catalog_module, "monotonic", lambda: next(ticks))
    if elapsed == 30.0:
        assert DashboardCatalog.load(manifest).records == ()
    else:
        with pytest.raises(DashboardResourceLimitExceeded, match="deadline"):
            DashboardCatalog.load(manifest)


@pytest.mark.skipif(
    os.name == "nt", reason="Linux symlink evidence; Windows reparse CI is separate"
)
@pytest.mark.parametrize("link_parent", [False, True])
def test_selected_file_and_parent_symlinks_are_rejected(tmp_path: Path, link_parent: bool) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    artifact = outside / "report.json"
    write_rule_test(artifact)
    root = tmp_path / "dashboard"
    root.mkdir()
    if link_parent:
        (root / "linked").symlink_to(outside, target_is_directory=True)
        selected = "linked/report.json"
    else:
        (root / "linked.json").symlink_to(artifact)
        selected = "linked.json"
    manifest = root / "manifest.json"
    write_manifest(manifest, [{"id": "report", "kind": "rule_test", "path": selected}])
    original = artifact.read_bytes()
    with pytest.raises(DashboardInputError, match="link or reparse"):
        DashboardCatalog.load(manifest)
    assert artifact.read_bytes() == original


def test_open_file_identity_swap_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "report.json"
    write_rule_test(artifact)
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(artifact.read_bytes())
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, [{"id": "report", "kind": "rule_test", "path": artifact.name}])
    original_open = Path.open
    swapped = False

    def replace_before_open(
        path: Path,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> IO[Any]:
        nonlocal swapped
        if path == artifact and not swapped:
            swapped = True
            replacement.replace(artifact)
        return original_open(path, mode, buffering, encoding, errors, newline)

    monkeypatch.setattr(Path, "open", replace_before_open)
    with pytest.raises(DashboardInputError, match="changed during dashboard startup"):
        DashboardCatalog.load(manifest)
    assert swapped


def test_unicode_escaped_canary_is_rejected_after_sqlite_json_decoding(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "events.sqlite3"
    write_source(source)
    escaped = "".join(f"\\u{ord(character):04x}" for character in load_canary())
    with closing(sqlite3.connect(source)) as connection, connection:
        connection.execute(
            """INSERT INTO events (
                event_id, run_id, trace_id, sequence, timestamp, event_type,
                source_component, tool_call_id, schema_version, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "evt_encoded",
                "run_1",
                "trace_1",
                2,
                "2026-10-01T00:00:00Z",
                "tool.requested",
                "tool-gateway",
                None,
                "0.2",
                '{"tool":"' + escaped + '"}',
            ),
        )
    assert load_canary().encode() not in source.read_bytes()
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, source_entries(1))
    with pytest.raises(DashboardInputError, match="raw lab canary"):
        DashboardCatalog.load(manifest)
    captured = capsys.readouterr()
    assert load_canary() not in captured.out + captured.err


def test_response_bytes_at_and_over_configured_ceiling() -> None:
    envelope_bytes = len(encode_safe_projection({"value": ""}))
    value = "x" * (MAX_DASHBOARD_RESPONSE_BYTES - envelope_bytes)
    assert len(api._json({"value": value}).body) == MAX_DASHBOARD_RESPONSE_BYTES
    rejected = api._json({"value": value + "x"})
    assert rejected.status_code == 503
    assert json.loads(bytes(rejected.body)) == {"error": {"code": "response_limit_exceeded"}}


def test_query_bytes_and_page_size_at_and_over_configured_ceilings() -> None:
    async def check() -> None:
        app = api.create_dashboard_app(DashboardCatalog(()))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8765"
        ) as client:
            exact = "offset=" + "0" * (MAX_DASHBOARD_QUERY_BYTES - len("offset="))
            assert (await client.get(f"/api/v1/catalog?{exact}")).status_code == 200
            over = await client.get(f"/api/v1/catalog?{exact}0")
            assert over.status_code == 422
            assert over.json() == {"error": {"code": "invalid_query"}}
            assert (await client.get("/api/v1/catalog?limit=200")).status_code == 200
            assert (await client.get("/api/v1/catalog?limit=201")).status_code == 422

    asyncio.run(check())


def test_eight_concurrent_requests_ninth_rejected_and_capacity_recovers() -> None:
    async def check() -> None:
        app = api.create_dashboard_app(DashboardCatalog(()))
        release = asyncio.Event()
        all_entered = asyncio.Event()
        entered = 0

        @app.get("/held")
        async def held() -> dict[str, bool]:
            nonlocal entered
            entered += 1
            if entered == 8:
                all_entered.set()
            await release.wait()
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8765"
        ) as client:
            pending = [asyncio.create_task(client.get("/held")) for _ in range(8)]
            try:
                await asyncio.wait_for(all_entered.wait(), timeout=5)
                rejected = await asyncio.wait_for(client.get("/api/v1/catalog"), timeout=5)
                assert rejected.status_code == 503
                assert rejected.json() == {"error": {"code": "request_limit_exceeded"}}
            finally:
                release.set()
                responses = await asyncio.wait_for(asyncio.gather(*pending), timeout=5)
            assert all(response.status_code == 200 for response in responses)
            assert (await client.get("/api/v1/catalog")).status_code == 200

    asyncio.run(check())
