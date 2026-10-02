# ruff: noqa: E402 -- optional modules are skipped before importing dependent modules.
from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

playwright = pytest.importorskip("playwright.sync_api")
uvicorn = pytest.importorskip("uvicorn")

from uvicorn import Server

from agentsec.constants import DIRECT_PROMPT_SCENARIO_ID
from agentsec.dashboard_api import create_dashboard_app
from agentsec.dashboard_catalog import CatalogRecord, DashboardCatalog
from agentsec.dashboard_models import ArtifactKind, CatalogSummary, Provenance
from agentsec.events import EventCollector, EventStore
from agentsec.models import Event, PromptFixture
from agentsec.resource_loader import load_canary, load_prompt
from agentsec.runner import ScenarioRunner
from tests.helpers import sequential_ids


def wait_for_server(server: Server, thread: threading.Thread) -> None:
    deadline = time.monotonic() + 10
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started and thread.is_alive()


@pytest.fixture(autouse=True)
def block_external_browser_requests(page: Any) -> None:
    def allow_loopback_only(route: Any) -> None:
        target = urlsplit(route.request.url)
        if target.scheme in {"http", "https"} and target.hostname == "127.0.0.1":
            route.continue_()
            return
        route.abort()

    page.route("**/*", allow_loopback_only)


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
        wait_for_server(server, thread)
        page.goto(f"http://127.0.0.1:{port}")
        playwright.expect(page.get_by_role("heading", name="AgentSec Lab")).to_be_visible()
        playwright.expect(
            page.get_by_text("No artifacts of this type are selected.")
        ).to_be_visible()
        page.get_by_role("button", name="Runs").focus()
        page.keyboard.press("Enter")
        playwright.expect(page.get_by_role("heading", name="runs")).to_be_visible()

        def delay_runs(route: Any) -> None:
            time.sleep(0.2)
            route.continue_()

        page.route("**/api/v1/runs?*", delay_runs)
        page.evaluate(
            """() => {
                const buttons = [...document.querySelectorAll('nav button')];
                buttons.find(button => button.textContent === 'Runs').click();
                buttons.find(button => button.textContent === 'Overview').click();
            }"""
        )
        playwright.expect(page.get_by_role("heading", name="Overview")).to_be_visible()
        page.wait_for_timeout(300)
        playwright.expect(page.get_by_role("heading", name="Overview")).to_be_visible()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
    assert not thread.is_alive()


@pytest.mark.dashboard_e2e
def test_manifest_loaded_direct_evidence_and_hostile_text_remain_inert(
    page: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(
        DIRECT_PROMPT_SCENARIO_ID, tmp_path / "artifacts"
    )
    direct_source = run.run_directory / "events.sqlite3"
    hostile = (
        '<script>globalThis.__hostileExecuted=true;fetch("https://example.invalid/probe")</script>'
        '<svg onload="globalThis.__hostileExecuted=true"></svg>'
        '<img src="https://example.invalid/image" onerror="globalThis.__hostileExecuted=true">'
        '<a href="javascript:globalThis.__hostileExecuted=true">attack</a>'
        "[markdown](https://example.invalid/link)\x1b\t\n"
    )
    hostile_source = tmp_path / "hostile.sqlite3"
    store = EventStore(hostile_source)
    collector = EventCollector(store, "run_hostile", "trace_hostile", id_factory=sequential_ids())
    collector.emit("run.started", "scenario-controller", {"profile": "vulnerable"})
    collector.emit("tool.requested", "tool-gateway", {"tool": hostile, "body": load_canary()})
    hostile_event = store.events("run_hostile")[-1]
    store.close()
    sources = (direct_source, run.run_directory / "report.json", hostile_source)
    source_hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "entries": [
                    {
                        "id": "direct",
                        "kind": "event_source",
                        "path": direct_source.relative_to(tmp_path).as_posix(),
                        "run_id": run.run_id,
                    },
                    {
                        "id": "direct_report",
                        "kind": "run_report",
                        "path": (run.run_directory / "report.json")
                        .relative_to(tmp_path)
                        .as_posix(),
                        "source_id": "direct",
                    },
                    {
                        "id": "hostile",
                        "kind": "event_source",
                        "path": hostile_source.name,
                        "run_id": "run_hostile",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    catalog = DashboardCatalog.load(manifest)
    direct = catalog.get("direct")
    assert direct is not None and direct.snapshot_fingerprint is not None
    prompt_event = next(
        event for event in direct.events if event.event_type == "agent.context.prompt_added"
    )

    with closing(socket.socket()) as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    origin = f"http://127.0.0.1:{port}"
    server = uvicorn.Server(
        uvicorn.Config(
            create_dashboard_app(catalog, port=port), host="127.0.0.1", port=port, log_level="error"
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    blocked: list[str] = []
    requested: list[str] = []
    errors: list[str] = []

    def exact_origin_only(route: Any) -> None:
        if route.request.url.startswith(origin + "/"):
            route.continue_()
        else:
            blocked.append(route.request.url)
            route.abort()

    page.unroute("**/*")
    page.context.route("**/*", exact_origin_only)
    page.context.on("request", lambda request: requested.append(request.url))
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.add_init_script("globalThis.__hostileExecuted = false")
    thread.start()
    try:
        wait_for_server(server, thread)
        page.goto(origin)
        page.get_by_role("button", name=f"Run {run.run_id}", exact=True).click()
        playwright.expect(
            page.get_by_role("heading", name="Sequence-ordered timeline")
        ).to_be_visible()
        page.locator(f'button[data-evidence-id="{prompt_event.event_id}"]').click()
        playwright.expect(
            page.get_by_role("heading", name=f"Evidence {prompt_event.event_id}")
        ).to_be_visible()
        response = page.request.get(f"{origin}/api/v1/runs/direct/events/{prompt_event.event_id}")
        assert response.status == 200
        assert response.json()["payload"] == prompt_event.payload
        content = page.content() + response.text()
        for forbidden in (
            load_prompt(PromptFixture.MALICIOUS),
            "[agentsec:direct-prompt-injection]",
            load_canary(),
        ):
            assert forbidden not in content
        assert "packaged_prompt_fixture" in page.locator("#view").inner_text()

        page.get_by_role("button", name="Runs", exact=True).click()
        page.get_by_role("button", name="Run run_hostile", exact=True).click()
        playwright.expect(
            page.get_by_role("heading", name="Sequence-ordered timeline")
        ).to_be_visible()
        page.locator(f'button[data-evidence-id="{hostile_event.event_id}"]').click()
        playwright.expect(
            page.get_by_role("heading", name=f"Evidence {hostile_event.event_id}")
        ).to_be_visible()
        rendered = page.locator("#view").inner_text()
        assert "<script>" in rendered and "<svg onload=" in rendered
        assert "[markdown](https://example.invalid/link)" in rendered
        assert page.locator("#view script, #view svg, #view img, #view a[href]").count() == 0
        assert page.evaluate("globalThis.__hostileExecuted") is False
        assert page.url.rstrip("/") == origin
        assert len(page.context.pages) == 1
        assert load_canary() not in page.content()
        assert requested and all(url.startswith(origin + "/") for url in requested)
        assert blocked == [] and errors == []
    finally:
        server.should_exit = True
        thread.join(timeout=10)
    assert not thread.is_alive()
    assert {
        path: hashlib.sha256(path.read_bytes()).hexdigest() for path in sources
    } == source_hashes
    captured = capsys.readouterr()
    assert load_canary() not in captured.out + captured.err


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
                        "stages": [
                            {"stage": "tool_request", "evidence": [reference]},
                            {"stage": "outbound_attempt", "evidence": [reference]},
                        ],
                        "timeline": [{"evidence": reference, "event_type": "tool.requested"}],
                        "recommended_remediation": ["Keep the Tool Gateway policy enabled."],
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
                "metrics": [
                    {
                        "profile": "strict",
                        "name": "prevention_rate",
                        "numerator": 1,
                        "denominator": 2,
                        "value": 0.5,
                        "eligible_count": 2,
                        "excluded_count": 0,
                    },
                    {
                        "profile": "strict",
                        "name": "benign_false_positive_rate",
                        "numerator": 0,
                        "denominator": 0,
                        "value": None,
                        "eligible_count": 0,
                        "excluded_count": 1,
                        "unavailable_reason": "no_eligible_benign_runs",
                    },
                ],
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
        wait_for_server(server, thread)
        page.goto(f"http://127.0.0.1:{port}")
        page.get_by_role("button", name="Run run_1").click()
        playwright.expect(
            page.get_by_role("heading", name="Sequence-ordered timeline")
        ).to_be_visible()
        trace_filter = page.get_by_placeholder("Exact trace ID")
        type_filter = page.get_by_placeholder("Exact event type")
        trace_filter.fill("trace_1")
        type_filter.fill("tool.requested")
        page.get_by_role("button", name="Apply filters").click()
        page.get_by_role("button", name="Open evidence").click()
        playwright.expect(page.get_by_role("heading", name="Evidence evt_1")).to_be_visible()
        page.get_by_role("button", name="Back").click()
        playwright.expect(trace_filter).to_have_value("trace_1")
        playwright.expect(type_filter).to_have_value("tool.requested")
        playwright.expect(page.get_by_role("button", name="Open evidence")).to_be_focused()
        page.get_by_role("button", name="Overview").click()
        page.get_by_role("button", name="Investigation sample").click()
        playwright.expect(page.get_by_role("heading", name="alerts")).to_be_visible()
        playwright.expect(page.get_by_role("heading", name="incidents")).to_be_visible()
        playwright.expect(
            page.get_by_role("img", name="Recorded attack chain: tool_request, outbound_attempt")
        ).to_be_visible()
        page.get_by_role("button", name="Event 1: evt_1").first.click()
        playwright.expect(page.get_by_role("heading", name="Evidence evt_1")).to_be_visible()
        page.get_by_role("button", name="Back").click()
        playwright.expect(page.get_by_role("heading", name="Investigation sample")).to_be_visible()
        page.get_by_role("button", name="Overview").click()
        page.get_by_role("button", name="Evaluation sample").click()
        playwright.expect(page.get_by_text("Excluded: fixture_failed")).to_be_visible()
        playwright.expect(
            page.get_by_role("progressbar", name="prevention_rate 1/2")
        ).to_be_visible()
        unavailable = page.get_by_role("progressbar", name="benign_false_positive_rate Unavailable")
        playwright.expect(unavailable).to_be_visible()
        assert unavailable.get_attribute("value") is None
    finally:
        server.should_exit = True
        thread.join(timeout=10)
    assert not thread.is_alive()


@pytest.mark.dashboard_e2e
def test_direct_prompt_projection_redacts_browser_content(page: Any) -> None:
    raw_prompt = load_prompt(PromptFixture.MALICIOUS)
    canary = load_canary()
    event = Event(
        event_id="evt_prompt",
        run_id="run_direct",
        trace_id="trace_direct",
        sequence=1,
        timestamp="2026-09-15T00:00:00Z",
        event_type="agent.context.prompt_added",
        source_component="scenario-controller",
        payload={
            "prompt_id": PromptFixture.MALICIOUS.value,
            "source": "packaged_prompt_fixture",
            "trust": "untrusted",
            "delivery_channel": "direct_prompt",
            "raw_prompt": raw_prompt,
            "fake_canary": canary,
        },
    )
    catalog = DashboardCatalog(
        (
            CatalogRecord(
                CatalogSummary(
                    id="direct",
                    kind=ArtifactKind.EVENT_SOURCE,
                    provenance=Provenance.VERIFIED,
                    title="Run run_direct",
                    status="incomplete",
                ),
                {"id": "direct", "run_id": "run_direct"},
                (event,),
            ),
        )
    )
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
    requests: list[str] = []
    page.on("request", lambda request: requests.append(request.url))
    thread.start()
    try:
        wait_for_server(server, thread)
        page.goto(f"http://127.0.0.1:{port}")
        page.get_by_role("button", name="Run run_direct").click()
        playwright.expect(
            page.get_by_role("heading", name="Sequence-ordered timeline")
        ).to_be_visible()
        page.get_by_role("button", name="Open evidence").click()
        playwright.expect(page.get_by_role("heading", name="Evidence evt_prompt")).to_be_visible()
        visible = page.locator("#view").inner_text()
        assert "malicious" in visible
        assert "packaged_prompt_fixture" in visible
        assert "direct_prompt" in visible
        for forbidden in (raw_prompt, "[agentsec:direct-prompt-injection]", canary):
            assert forbidden not in page.content()
        assert requests
        assert all(urlsplit(url).hostname == "127.0.0.1" for url in requests)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
    assert not thread.is_alive()
