from __future__ import annotations

import socket

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

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
