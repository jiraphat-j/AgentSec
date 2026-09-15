from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import agentsec.dashboard_catalog as dashboard_catalog
from agentsec.dashboard_catalog import DashboardCatalog, DashboardInputError
from agentsec.dashboard_models import ArtifactKind, DashboardManifestEntry
from agentsec.events import EventCollector, EventStore
from agentsec.incidents import InvestigationService
from agentsec.resource_loader import load_canary
from agentsec.runner import ScenarioRunner

from .helpers import fixed_clock, sequential_ids

RESOURCE_ROOT = Path(__file__).parents[1] / "src" / "agentsec" / "resources"
RULES = RESOURCE_ROOT / "rules"


def _write_manifest(path: Path, entries: list[dict[str, object]]) -> None:
    path.write_text(json.dumps({"schema_version": "1.0", "entries": entries}), encoding="utf-8")


def test_catalog_loads_verified_source_report_and_investigation(tmp_path: Path) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(
        "indirect-injection-secret-exfiltration", tmp_path / "artifacts"
    )
    investigation = InvestigationService(id_factory=sequential_ids()).investigate(
        run.run_directory / "events.sqlite3",
        run.run_id,
        RULES,
        tmp_path / "investigations",
    )
    manifest = tmp_path / "dashboard.json"
    _write_manifest(
        manifest,
        [
            {
                "id": "source",
                "kind": "event_source",
                "path": (run.run_directory / "events.sqlite3").relative_to(tmp_path).as_posix(),
                "run_id": run.run_id,
            },
            {
                "id": "report",
                "kind": "run_report",
                "path": (run.run_directory / "report.json").relative_to(tmp_path).as_posix(),
                "source_id": "source",
            },
            {
                "id": "investigation",
                "kind": "investigation",
                "path": (investigation.investigation_directory / "investigation.json")
                .relative_to(tmp_path)
                .as_posix(),
                "source_id": "source",
            },
        ],
    )

    catalog = DashboardCatalog.load(manifest)

    assert [record.summary.provenance for record in catalog.records] == [
        "verified_against_source",
        "verified_against_source",
        "verified_against_source",
    ]
    source = catalog.get("source")
    assert source is not None
    assert [event.sequence for event in source.events] == sorted(
        event.sequence for event in source.events
    )
    assert source.data["run_id"] == run.run_id


@pytest.mark.parametrize(
    "path",
    ["../events.sqlite3", "/etc/passwd", "C:/secret", "C:secret", "\\\\host\\share"],
)
def test_manifest_rejects_unsafe_paths(path: str) -> None:
    with pytest.raises(ValidationError, match="confined relative POSIX path"):
        DashboardManifestEntry(
            id="source", kind=ArtifactKind.EVENT_SOURCE, path=path, run_id="run_1"
        )


def test_catalog_rejects_duplicate_json_keys_and_raw_canary(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"1.0","schema_version":"1.0","entries":[]}', encoding="utf-8"
    )
    with pytest.raises(DashboardInputError, match="duplicate"):
        DashboardCatalog.load(duplicate)

    unsafe_report = tmp_path / "unsafe.json"
    unsafe_report.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "status": "passed",
                "total_rules": 0,
                "covered_rules": 0,
                "assertions_passed": 0,
                "assertions_total": 0,
                "results": [],
                "unexpected": load_canary(),
            }
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest, [{"id": "unsafe", "kind": "rule_test", "path": "unsafe.json"}])
    with pytest.raises(DashboardInputError, match="schema validation"):
        DashboardCatalog.load(manifest)


def test_report_only_artifact_is_explicit(tmp_path: Path) -> None:
    result = ScenarioRunner(id_factory=sequential_ids()).run(
        "indirect-injection-secret-exfiltration", tmp_path / "artifacts"
    )
    manifest = tmp_path / "manifest.json"
    _write_manifest(
        manifest,
        [
            {
                "id": "report-only",
                "kind": "run_report",
                "path": (result.run_directory / "report.json").relative_to(tmp_path).as_posix(),
            }
        ],
    )

    record = DashboardCatalog.load(manifest).get("report-only")

    assert record is not None
    assert record.summary.provenance == "report_only"
    timeline = record.data["timeline"]
    assert isinstance(timeline, list)
    assert all("body" not in event["payload"] for event in timeline)


def test_verified_report_rejects_any_canonical_content_change(tmp_path: Path) -> None:
    result = ScenarioRunner(id_factory=sequential_ids()).run(
        "indirect-injection-secret-exfiltration", tmp_path / "artifacts"
    )
    report_path = result.run_directory / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["executive_summary"] = "Altered after generation."
    report_path.write_text(json.dumps(report), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    _write_manifest(
        manifest,
        [
            {
                "id": "source",
                "kind": "event_source",
                "path": (result.run_directory / "events.sqlite3").relative_to(tmp_path).as_posix(),
                "run_id": result.run_id,
            },
            {
                "id": "report",
                "kind": "run_report",
                "path": report_path.relative_to(tmp_path).as_posix(),
                "source_id": "source",
            },
        ],
    )

    with pytest.raises(DashboardInputError, match="contents do not match"):
        DashboardCatalog.load(manifest)


def test_verified_investigation_rejects_altered_timeline_metadata(tmp_path: Path) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(
        "indirect-injection-secret-exfiltration", tmp_path / "artifacts"
    )
    investigation = InvestigationService(id_factory=sequential_ids()).investigate(
        run.run_directory / "events.sqlite3",
        run.run_id,
        RULES,
        tmp_path / "investigations",
    )
    investigation_path = investigation.investigation_directory / "investigation.json"
    report = json.loads(investigation_path.read_text(encoding="utf-8"))
    report["incidents"][0]["timeline"][0]["source_component"] = "altered-component"
    investigation_path.write_text(json.dumps(report), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    _write_manifest(
        manifest,
        [
            {
                "id": "source",
                "kind": "event_source",
                "path": (run.run_directory / "events.sqlite3").relative_to(tmp_path).as_posix(),
                "run_id": run.run_id,
            },
            {
                "id": "investigation",
                "kind": "investigation",
                "path": investigation_path.relative_to(tmp_path).as_posix(),
                "source_id": "source",
            },
        ],
    )

    with pytest.raises(DashboardInputError, match="timeline metadata was altered"):
        DashboardCatalog.load(manifest)


def test_catalog_rejects_source_changed_during_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(
        "indirect-injection-secret-exfiltration", tmp_path / "artifacts"
    )
    source = run.run_directory / "events.sqlite3"
    manifest = tmp_path / "manifest.json"
    _write_manifest(
        manifest,
        [
            {
                "id": "source",
                "kind": "event_source",
                "path": source.relative_to(tmp_path).as_posix(),
                "run_id": run.run_id,
            }
        ],
    )
    original = dashboard_catalog.read_replay_evidence

    def mutate_after_read(path: Path, run_id: str) -> object:
        evidence = original(path, run_id)
        with path.open("ab") as handle:
            handle.write(b"\x00")
        return evidence

    monkeypatch.setattr(dashboard_catalog, "read_replay_evidence", mutate_after_read)

    with pytest.raises(DashboardInputError, match="changed during dashboard startup"):
        DashboardCatalog.load(manifest)


def test_catalog_rejects_raw_canary_in_safe_event_projection(tmp_path: Path) -> None:
    source = tmp_path / "events.sqlite3"
    store = EventStore(source)
    collector = EventCollector(
        store,
        "run_1",
        "trace_1",
        id_factory=sequential_ids(),
        clock=fixed_clock,
    )
    collector.emit(
        "run.started",
        "scenario-controller",
        {
            "scenario_id": "indirect-injection-secret-exfiltration",
            "fixture": "malicious",
            "profile": "vulnerable",
            "policy_version": "policy-v1",
        },
    )
    collector.emit("tool.requested", "tool-gateway", {"tool": load_canary()})
    store.close()
    manifest = tmp_path / "manifest.json"
    _write_manifest(
        manifest,
        [{"id": "source", "kind": "event_source", "path": source.name, "run_id": "run_1"}],
    )

    with pytest.raises(DashboardInputError, match="raw lab canary"):
        DashboardCatalog.load(manifest)
