from __future__ import annotations

import builtins
import socket
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from agentsec.cli import main
from agentsec.dashboard_api import create_dashboard_app
from agentsec.dashboard_catalog import CatalogRecord, DashboardCatalog
from agentsec.dashboard_models import ArtifactKind, CatalogSummary, Provenance
from agentsec.models import Event
from agentsec.resource_loader import load_canary


def _catalog() -> DashboardCatalog:
    event = Event(
        event_id="evt_1",
        run_id="run_1",
        trace_id="trace_1",
        sequence=1,
        timestamp="2026-09-15T00:00:00Z",
        event_type="tool.requested",
        source_component="tool-gateway",
        tool_call_id="call_1",
        payload={"tool": "http_post", "body": "must-not-be-served"},
    )
    return DashboardCatalog(
        (
            CatalogRecord(
                CatalogSummary(
                    id="source",
                    kind=ArtifactKind.EVENT_SOURCE,
                    provenance=Provenance.VERIFIED,
                    title="Run run_1",
                    status="incomplete",
                ),
                {"id": "source", "run_id": "run_1", "status": "incomplete"},
                (event,),
            ),
        )
    )


def test_api_is_read_only_same_origin_and_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("API construction opened a socket")

    with monkeypatch.context() as context:
        context.setattr(socket, "socket", fail)
        app = create_dashboard_app(_catalog(), port=8765)
    client = TestClient(app, base_url="http://127.0.0.1:8765")

    response = client.get("/api/v1/runs/source/events")
    assert response.status_code == 200
    event = response.json()["items"][0]
    assert event["payload"] == {"tool": "http_post"}
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert client.post("/api/v1/catalog").status_code == 405
    assert (
        client.get("/api/v1/catalog", headers={"Origin": "https://example.test"}).status_code == 403
    )
    assert (
        client.get("/api/v1/catalog", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    )
    assert client.get("/api/v1/catalog", headers={"Host": "example.test"}).status_code == 400


def test_api_pagination_errors_and_assets_are_bounded() -> None:
    client = TestClient(
        create_dashboard_app(_catalog(), port=8765), base_url="http://127.0.0.1:8765"
    )

    assert client.get("/").status_code == 200
    assert client.get("/assets/app.js").headers["content-type"].startswith("text/javascript")
    assert client.get("/api/v1/catalog?limit=201").json() == {"error": {"code": "invalid_query"}}
    assert client.get("/api/v1/runs/missing").status_code == 404
    assert client.get("/api/v1/unknown").status_code == 404


def test_api_rejects_raw_canary_even_for_directly_constructed_catalog() -> None:
    event = Event(
        event_id="evt_unsafe",
        run_id="run_1",
        trace_id="trace_1",
        sequence=1,
        timestamp="2026-09-15T00:00:00Z",
        event_type="tool.requested",
        source_component="tool-gateway",
        payload={"tool": load_canary()},
    )
    catalog = DashboardCatalog(
        (
            CatalogRecord(
                CatalogSummary(
                    id="source",
                    kind=ArtifactKind.EVENT_SOURCE,
                    provenance=Provenance.VERIFIED,
                    title="Run run_1",
                    status="incomplete",
                ),
                {"id": "source", "run_id": "run_1"},
                (event,),
            ),
        )
    )
    client = TestClient(create_dashboard_app(catalog, port=8765), base_url="http://127.0.0.1:8765")

    response = client.get("/api/v1/runs/source/events")

    assert response.status_code == 503
    assert response.json() == {"error": {"code": "unsafe_projection_rejected"}}


def test_nested_collections_are_paginated_and_removed_from_detail() -> None:
    record = CatalogRecord(
        CatalogSummary(
            id="investigation",
            kind=ArtifactKind.INVESTIGATION,
            provenance=Provenance.REPORT_ONLY,
            title="Investigation sample",
            status="completed",
        ),
        {
            "investigation_id": "investigation_1",
            "derived_alerts": [{"stable_key": "a"}, {"stable_key": "b"}],
            "incidents": [{"stable_key": "i"}],
            "rule_evaluations": [{"rule_id": "r"}],
        },
    )
    client = TestClient(
        create_dashboard_app(DashboardCatalog((record,)), port=8765),
        base_url="http://127.0.0.1:8765",
    )

    detail = client.get("/api/v1/investigations/investigation").json()["data"]
    page = client.get("/api/v1/investigations/investigation/alerts?limit=1").json()

    assert "derived_alerts" not in detail
    assert detail["nested_collection_counts"]["alerts"] == 2
    assert page == {"items": [{"stable_key": "a"}], "total": 2, "offset": 0, "limit": 1}


def test_api_covers_filters_children_nested_routes_and_strict_queries() -> None:
    investigation = CatalogRecord(
        CatalogSummary(
            id="investigation",
            kind=ArtifactKind.INVESTIGATION,
            provenance=Provenance.REPORT_ONLY,
            title="Investigation sample",
            status="completed",
        ),
        {
            "derived_alerts": [{"stable_key": "alert-a"}],
            "incidents": [{"stable_key": "incident-a"}],
            "rule_evaluations": [{"rule_id": "rule-a"}],
        },
    )
    evaluation = CatalogRecord(
        CatalogSummary(
            id="evaluation",
            kind=ArtifactKind.EVALUATION,
            provenance=Provenance.REPORT_ONLY,
            title="Evaluation sample",
            status="partial",
        ),
        {
            "children": [{"case_id": "case-a"}],
            "metrics": [{"name": "prevention_rate"}],
            "pairs": [],
            "confusion_counts": [],
            "timing": [],
        },
    )
    report = CatalogRecord(
        CatalogSummary(
            id="report",
            kind=ArtifactKind.RUN_REPORT,
            provenance=Provenance.REPORT_ONLY,
            title="Report run_1",
            status="completed",
        ),
        {"run_id": "run_1", "timeline": [{"event_id": "reported-event"}]},
    )
    catalog = DashboardCatalog((*_catalog().records, investigation, evaluation, report))
    client = TestClient(create_dashboard_app(catalog), base_url="http://127.0.0.1:8765")

    assert client.get("/assets/styles.css").status_code == 200
    assert client.get("/api/v1/runs").json()["total"] == 2
    assert client.get("/api/v1/runs/source").json()["summary"]["id"] == "source"
    assert client.get("/api/v1/runs/source/events/evt_1").json()["event_id"] == "evt_1"
    assert client.get("/api/v1/runs/source/events/missing").status_code == 404
    assert client.get("/api/v1/runs/source/events?trace_id=trace_1").json()["total"] == 1
    assert client.get("/api/v1/runs/source/events?event_type=missing").json()["total"] == 0
    assert client.get("/api/v1/runs/source/events?trace_id=").status_code == 422
    assert client.get("/api/v1/runs/report/timeline").json()["total"] == 1
    assert client.get("/api/v1/investigations/investigation/alerts/alert-0").status_code == 200
    assert (
        client.get("/api/v1/investigations/investigation/incidents/incident-0").status_code == 200
    )
    assert client.get("/api/v1/investigations/investigation/alerts/bad").status_code == 404
    assert client.get("/api/v1/evaluations/evaluation/children").json()["total"] == 1
    assert client.get("/api/v1/investigations/evaluation/children").status_code == 404
    assert client.get("/api/v1/evaluations/investigation/alerts").status_code == 404
    assert client.get("/api/v1/evaluations/evaluation/unknown").status_code == 404
    assert client.get("/api/v1/catalog?unexpected=true").status_code == 422
    assert client.get("/api/v1/catalog?limit=1&limit=2").status_code == 422
    assert client.get("/api/v1/catalog?" + "x=" + "a" * 2048).status_code == 422


@pytest.mark.parametrize("port", [0, 65536])
def test_dashboard_rejects_invalid_ports(port: int) -> None:
    with pytest.raises(ValueError, match="between 1 and 65535"):
        create_dashboard_app(_catalog(), port=port)


def test_dashboard_cli_gives_missing_extra_hint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    original_import = builtins.__import__

    def reject_uvicorn(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "uvicorn":
            raise ImportError("simulated missing dashboard extra")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_uvicorn)

    result = main(["dashboard", "--manifest", str(tmp_path / "missing.json")])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == (
        "error: dashboard dependencies unavailable; install agentsec-lab[dashboard]\n"
    )
