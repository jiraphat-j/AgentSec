"""G0 regressions for dashboard path, redaction, and resource boundaries."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import subprocess
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
    MAX_DASHBOARD_EVENTS,
    MAX_DASHBOARD_INPUT_BYTES,
    MAX_DASHBOARD_MANIFEST_BYTES,
    MAX_DASHBOARD_PROJECTION_BYTES,
    MAX_DASHBOARD_QUERY_BYTES,
    MAX_DASHBOARD_RESPONSE_BYTES,
    MAX_DASHBOARD_RUNS,
    MAX_REPLAY_DATABASE_BYTES,
    MAX_REPLAY_EVENTS,
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


def source_digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


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


def test_cumulative_selected_bytes_at_and_over_actual_cap(tmp_path: Path) -> None:
    source = tmp_path / "events.sqlite3"
    write_source(source)
    # SQLite's header describes its canonical pages; trailing padding is inert input bytes.
    with source.open("r+b") as handle:
        handle.truncate(MAX_REPLAY_DATABASE_BYTES)
    original_source_digest = source_digest(source)
    artifact = tmp_path / "report.json"
    write_rule_test(artifact)
    data = artifact.read_bytes()
    artifact.write_bytes(data + b" " * (MAX_REPORT_BYTES - len(data)))
    report_count, remainder = divmod(
        MAX_DASHBOARD_INPUT_BYTES - source.stat().st_size, artifact.stat().st_size
    )
    assert remainder == 0
    entries = source_entries(1) + [
        {"id": f"report_{index}", "kind": "rule_test", "path": artifact.name}
        for index in range(report_count)
    ]
    assert len(entries) + 1 <= MAX_DASHBOARD_ENTRIES
    assert (
        source.stat().st_size + report_count * artifact.stat().st_size == MAX_DASHBOARD_INPUT_BYTES
    )
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, entries)
    assert len(DashboardCatalog.load(manifest).records) == len(entries)
    extra = tmp_path / "extra.json"
    write_rule_test(extra)
    write_manifest(manifest, [*entries, {"id": "extra", "kind": "rule_test", "path": extra.name}])
    with pytest.raises(DashboardResourceLimitExceeded, match="aggregate limit"):
        DashboardCatalog.load(manifest)
    assert source.stat().st_size == MAX_REPLAY_DATABASE_BYTES
    assert source_digest(source) == original_source_digest
    assert artifact.read_bytes() == data + b" " * (MAX_REPORT_BYTES - len(data))


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


def test_cumulative_events_at_and_one_over_actual_cap(tmp_path: Path) -> None:
    source = tmp_path / "events.sqlite3"
    write_source(source)
    with closing(sqlite3.connect(source)) as connection, connection:
        connection.executemany(
            """INSERT INTO events (
                event_id, run_id, trace_id, sequence, timestamp, event_type,
                source_component, tool_call_id, schema_version, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    f"evt_boundary_{sequence}",
                    "run_1",
                    "trace_1",
                    sequence,
                    "2026-10-02T00:00:00Z",
                    "test.safe_metadata",
                    "test",
                    None,
                    "0.2",
                    "{}",
                )
                for sequence in range(2, MAX_REPLAY_EVENTS + 1)
            ],
        )
    count, remainder = divmod(MAX_DASHBOARD_EVENTS, MAX_REPLAY_EVENTS)
    assert remainder == 0 and count + 1 <= MAX_DASHBOARD_RUNS
    original = source.read_bytes()
    manifest = tmp_path / "manifest.json"
    entries = source_entries(count)
    write_manifest(manifest, entries)
    catalog = DashboardCatalog.load(manifest)
    assert sum(len(record.events) for record in catalog.records) == MAX_DASHBOARD_EVENTS
    extra = tmp_path / "extra.sqlite3"
    write_source(extra)
    original_extra = extra.read_bytes()
    write_manifest(
        manifest,
        [*entries, {"id": "extra", "kind": "event_source", "path": extra.name, "run_id": "run_1"}],
    )
    with pytest.raises(DashboardResourceLimitExceeded, match="event count"):
        DashboardCatalog.load(manifest)
    assert source.read_bytes() == original
    assert extra.read_bytes() == original_extra


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


def test_projection_bytes_at_and_over_actual_cap(tmp_path: Path) -> None:
    # A schema-valid rule-test string has no independent fixture-name length cap.
    value: dict[str, Any] = {
        "schema_version": "1.0",
        "status": "failed",
        "total_rules": 1,
        "covered_rules": 0,
        "assertions_passed": 0,
        "assertions_total": 1,
        "results": [
            {
                "fixture": "",
                "rule_id": "ASL-TEST-001",
                "rule_version": 1,
                "passed": False,
                "expected_evidence": [],
                "actual_evidence": [],
            }
        ],
    }
    envelope = len(encode_safe_projection(value))
    value["results"][0]["fixture"] = "x" * (MAX_REPORT_BYTES - envelope)
    encoded = encode_safe_projection(value)
    assert len(encoded) == MAX_REPORT_BYTES
    artifact = tmp_path / "report.json"
    artifact.write_bytes(encoded)
    count, remainder = divmod(MAX_DASHBOARD_PROJECTION_BYTES, len(encoded))
    assert remainder == 0 and count + 1 <= MAX_DASHBOARD_ENTRIES
    entries: list[dict[str, object]] = [
        {"id": f"report_{index}", "kind": "rule_test", "path": artifact.name}
        for index in range(count)
    ]
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest, entries)
    catalog = DashboardCatalog.load(manifest)
    assert sum(len(encode_safe_projection(record.data)) for record in catalog.records) == (
        MAX_DASHBOARD_PROJECTION_BYTES
    )
    extra = tmp_path / "extra.json"
    write_rule_test(extra)
    write_manifest(manifest, [*entries, {"id": "extra", "kind": "rule_test", "path": extra.name}])
    with pytest.raises(DashboardResourceLimitExceeded, match="projections"):
        DashboardCatalog.load(manifest)
    assert artifact.read_bytes() == encoded


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


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse evidence requires NTFS")
def test_windows_regular_selected_file_is_accepted(tmp_path: Path) -> None:
    root = tmp_path / "dashboard"
    root.mkdir()
    artifact = root / "report.json"
    write_rule_test(artifact)
    original = artifact.read_bytes()
    manifest = root / "manifest.json"
    write_manifest(manifest, [{"id": "report", "kind": "rule_test", "path": artifact.name}])

    assert DashboardCatalog.load(manifest).get("report") is not None
    assert artifact.read_bytes() == original


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse evidence requires NTFS")
def test_windows_selected_file_symlink_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    artifact = outside / "report.json"
    write_rule_test(artifact)
    original = artifact.read_bytes()
    root = tmp_path / "dashboard"
    root.mkdir()
    selected = root / "linked.json"
    manifest = root / "manifest.json"
    write_manifest(manifest, [{"id": "report", "kind": "rule_test", "path": selected.name}])

    selected.symlink_to(artifact)
    try:
        assert selected.is_symlink()
        assert getattr(selected.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400
        with pytest.raises(DashboardInputError, match="link or reparse"):
            DashboardCatalog.load(manifest)
    finally:
        selected.unlink()
    assert not selected.exists()
    assert artifact.read_bytes() == original


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse evidence requires NTFS")
def test_windows_selected_parent_junction_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    artifact = outside / "report.json"
    write_rule_test(artifact)
    original = artifact.read_bytes()
    root = tmp_path / "dashboard"
    root.mkdir()
    junction = root / "linked"
    manifest = root / "manifest.json"
    write_manifest(manifest, [{"id": "report", "kind": "rule_test", "path": "linked/report.json"}])

    try:
        subprocess.run(
            ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert junction.is_junction()
        assert getattr(junction.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400
        with pytest.raises(DashboardInputError, match="link or reparse"):
            DashboardCatalog.load(manifest)
    finally:
        if junction.is_junction():
            junction.rmdir()
    assert not junction.exists()
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
