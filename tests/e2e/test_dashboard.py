# ruff: noqa: E402 -- optional modules are skipped before importing dependent modules.
from __future__ import annotations

import socket
import threading
from contextlib import closing
from typing import Any

import pytest

playwright = pytest.importorskip("playwright.sync_api")
uvicorn = pytest.importorskip("uvicorn")

from agentsec.dashboard_api import create_dashboard_app
from agentsec.dashboard_catalog import CatalogRecord, DashboardCatalog
from agentsec.dashboard_models import ArtifactKind, CatalogSummary, Provenance
from agentsec.models import Event


@pytest.mark.dashboard_e2e
def test_empty_dashboard_keyboard_flow(page: Any) -> None:
    catalog = DashboardCatalog(())
    with closing(socket.socket()) as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    server = uvicorn.Server(
        uvicorn.Config(
            create_dashboard_app(catalog, port=port),
            host="127.0.0.1",
            port=port,
            log_level="error",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        page.goto(f"http://127.0.0.1:{port}")
        playwright.expect(page.get_by_role("heading", name="AgentSec Lab")).to_be_visible()
        playwright.expect(
            page.get_by_text("No artifacts of this type are selected.")
        ).to_be_visible()
        page.get_by_role("button", name="Runs").focus()
        page.keyboard.press("Enter")
        playwright.expect(page.get_by_role("heading", name="runs")).to_be_visible()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
    assert not thread.is_alive()


@pytest.mark.dashboard_e2e
def test_representative_investigation_and_evaluation_flow(page: Any) -> None:
    reference = {
        "snapshot_fingerprint": "a" * 64,
        "run_id": "run_1",
        "trace_id": "trace_1",
        "event_id": "evt_1",
        "sequence": 1,
    }
    event = Event(
        event_id="evt_1",
        run_id="run_1",
        trace_id="trace_1",
        sequence=1,
        timestamp="2026-09-15T00:00:00Z",
        event_type="tool.requested",
        source_component="tool-gateway",
        payload={"tool": "read_file"},
    )
    records = (
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
        CatalogRecord(
            CatalogSummary(
                id="investigation",
                kind=ArtifactKind.INVESTIGATION,
                provenance=Provenance.VERIFIED,
                title="Investigation sample",
                status="completed",
            ),
            {
                "investigation_id": "investigation_1",
                "catalog_source_id": "source",
                "derived_alerts": [
                    {
                        "rule_id": "rule_1",
                        "rule_version": 1,
                        "severity": "high",
                        "description": "Synthetic alert",
                        "evidence": [reference],
                    }
                ],
                "incidents": [
                    {
                        "severity": "high",
                        "status": "new",
                        "outcome": {"outcome": "unknown"},
                        "root_cause_hypothesis": "Synthetic hypothesis",
                        "timeline": [{"evidence": reference, "event_type": "tool.requested"}],
                    }
                ],
                "rule_evaluations": [{"rule_id": "rule_1", "matches": 1}],
            },
        ),
        CatalogRecord(
            CatalogSummary(
                id="evaluation",
                kind=ArtifactKind.EVALUATION,
                provenance=Provenance.REPORT_ONLY,
                title="Evaluation sample",
                status="partial",
            ),
            {
                "evaluation_id": "evaluation_1",
                "children": [
                    {
                        "case_id": "case_1",
                        "trial": 1,
                        "profile": "strict",
                        "status": "failed",
                        "assertion_passed": False,
                        "exclusion_reason": "fixture_failed",
                    }
                ],
                "metrics": [],
                "pairs": [],
                "confusion_counts": [],
                "timing": [],
            },
        ),
    )
    with closing(socket.socket()) as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    server = uvicorn.Server(
        uvicorn.Config(
            create_dashboard_app(DashboardCatalog(records), port=port),
            host="127.0.0.1",
            port=port,
            log_level="error",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        page.goto(f"http://127.0.0.1:{port}")
        page.get_by_role("button", name="Run run_1").click()
        playwright.expect(
            page.get_by_role("heading", name="Sequence-ordered timeline")
        ).to_be_visible()
        page.get_by_role("button", name="Overview").click()
        page.get_by_role("button", name="Investigation sample").click()
        playwright.expect(page.get_by_role("heading", name="alerts")).to_be_visible()
        playwright.expect(page.get_by_role("heading", name="incidents")).to_be_visible()
        page.get_by_role("button", name="Event 1: evt_1").first.click()
        playwright.expect(page.get_by_role("heading", name="Evidence evt_1")).to_be_visible()
        page.get_by_role("button", name="Back").click()
        playwright.expect(page.get_by_role("heading", name="Investigation sample")).to_be_visible()
        page.get_by_role("button", name="Overview").click()
        page.get_by_role("button", name="Evaluation sample").click()
        playwright.expect(page.get_by_text("Excluded: fixture_failed")).to_be_visible()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
    assert not thread.is_alive()
