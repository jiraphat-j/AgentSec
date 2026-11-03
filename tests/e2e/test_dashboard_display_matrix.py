# ruff: noqa: E402 -- skip optional browser modules before importing dependent modules.
"""Prepared A6/A7 browser matrix; requires concrete human execution approval."""

from __future__ import annotations

import json
import re
import socket
import threading
from collections.abc import Iterator
from contextlib import closing, contextmanager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from pydantic import BaseModel

playwright = pytest.importorskip("playwright.sync_api")
uvicorn = pytest.importorskip("uvicorn")

from agentsec.constants import SCENARIO_ID
from agentsec.dashboard_api import create_dashboard_app
from agentsec.dashboard_catalog import DashboardCatalog
from agentsec.dashboard_models import ArtifactKind
from agentsec.evaluation_models import EvaluationChildResult, EvaluationReport
from agentsec.events import EventCollector, EventStore
from agentsec.incidents import InvestigationService, build_investigation
from agentsec.metrics import build_confusion_counts, build_metrics, build_pairs, build_timing
from agentsec.models import Event, Report
from agentsec.rule_engine import load_rules
from agentsec.rule_models import RuleTestFixture, SourceStatus
from agentsec.rule_testing import load_rule_fixtures, run_rule_tests
from tests.e2e.test_dashboard import wait_for_server
from tests.helpers import fixed_clock, sequential_ids
from tests.test_dashboard_artifact_redaction import genuine_artifacts as genuine_artifacts

RESOURCES = Path(__file__).parents[2] / "src/agentsec/resources"
pytestmark = pytest.mark.dashboard_e2e


@dataclass(frozen=True)
class DisplayInputs:
    catalog: DashboardCatalog
    models: dict[str, BaseModel]
    events: dict[str, tuple[Event, ...]]


def _source(root: Path, state: str) -> tuple[Path, tuple[Event, ...]]:
    path = root / f"{state}.sqlite3"
    store = EventStore(path)
    collector = EventCollector(
        store, f"run_{state}", f"trace_{state}", id_factory=sequential_ids(), clock=fixed_clock
    )
    try:
        events = [
            collector.emit(
                "run.started",
                "scenario-controller",
                {
                    "scenario_id": SCENARIO_ID,
                    "fixture": "benign",
                    "profile": "vulnerable",
                    "policy_version": "policy-v1",
                },
            )
        ]
        if state == "completed":
            events.append(
                collector.emit(
                    "run.completed",
                    "scenario-controller",
                    {
                        "detected": False,
                        "prevented": False,
                        "simulated_impact": False,
                    },
                )
            )
        elif state == "failed":
            events.append(
                collector.emit(
                    "run.failed",
                    "scenario-controller",
                    {
                        "error_type": "SyntheticFailure",
                    },
                )
            )
        else:
            assert state == "incomplete"
    finally:
        store.close()
    return path, tuple(events)


def _evaluation_variants(
    original: EvaluationReport, clock_reason: str
) -> tuple[EvaluationReport, EvaluationReport]:
    # Preserve observations while excluding invalid recorded intervals from timing aggregates.
    clock_children = tuple(
        EvaluationChildResult.model_validate(
            {
                **child.model_dump(mode="python"),
                "recorded_alert_seconds": None,
                "recorded_incident_seconds": None,
                "timing_exclusion_reason": clock_reason,
            }
        )
        if child.recorded_alert_seconds is not None
        else child
        for child in original.children
    )
    clock_report = EvaluationReport.model_validate(
        {
            **original.model_dump(mode="python"),
            "evaluation_id": "evaluation_invalid_clock",
            "children": clock_children,
            "timing": build_timing(clock_children),
        }
    )
    # An explicitly synthetic all-failed matrix exercises unavailable values and incomplete pairs.
    failed_children = tuple(
        EvaluationChildResult.model_validate(
            {
                **child.model_dump(mode="python"),
                "status": "failed",
                "run_id": None,
                "trace_id": None,
                "relative_directory": None,
                "observation": None,
                "assertion_passed": False,
                "exclusion_reason": "synthetic_child_failure",
                "recorded_alert_seconds": None,
                "recorded_incident_seconds": None,
                "timing_exclusion_reason": "child_failed",
            }
        )
        for child in original.children
    )
    unavailable = EvaluationReport.model_validate(
        {
            **original.model_dump(mode="python"),
            "evaluation_id": "evaluation_unavailable",
            "status": "partial",
            "completed_children": 0,
            "failed_children": len(failed_children),
            "excluded_children": len(failed_children),
            "assertion_failures": 0,
            "children": failed_children,
            "metrics": build_metrics(failed_children),
            "confusion_counts": build_confusion_counts(failed_children),
            "timing": build_timing(failed_children),
            "pairs": build_pairs(failed_children),
            "impact_pair_prevention_numerator": 0,
            "impact_pair_prevention_denominator": 0,
            "impact_pair_prevention_rate": None,
            "rule_run_counts": (),
            "incident_category_counts": (),
        }
    )
    assert all(
        metric.denominator == 0 and metric.excluded_count > 0 for metric in unavailable.metrics
    )
    assert all(pair.status == "incomplete" for pair in unavailable.pairs)
    assert all(
        timing.sample_count == 0 and timing.excluded_count > 0 for timing in clock_report.timing
    )
    return clock_report, unavailable


@pytest.fixture
def display_inputs(
    tmp_path: Path, genuine_artifacts: dict[ArtifactKind, BaseModel]
) -> Iterator[DisplayInputs]:
    rules = load_rules(RESOURCES / "rules")
    fixtures = load_rule_fixtures(RESOURCES / "rule_fixtures")
    wrong = RuleTestFixture.model_validate(
        {
            **fixtures[0].model_dump(mode="python"),
            "expected_evidence": (("evt_expected_only",),),
        }
    )
    failed_rule_test = run_rule_tests(rules, (wrong, *fixtures[1:]))
    assert failed_rule_test.status == "failed"
    run_report = genuine_artifacts[ArtifactKind.RUN_REPORT]
    evaluation = genuine_artifacts[ArtifactKind.EVALUATION]
    assert isinstance(run_report, Report) and isinstance(evaluation, EvaluationReport)
    assert 0 < evaluation.impact_pair_prevention_denominator < len(evaluation.pairs)
    assert any(0 < metric.numerator < metric.denominator for metric in evaluation.metrics)
    clock_events = [
        Event.model_validate(
            {
                **event.model_dump(mode="python"),
                "timestamp": "2026-09-01T00:00:00Z"
                if event.event_type == "alert.created"
                else event.timestamp,
            }
        )
        for event in run_report.timeline
    ]
    # Reports capture this evidence prefix before run.completed is emitted.
    clock = build_investigation(
        investigation_id="investigation_invalid_clock",
        source_file="synthetic-clock.sqlite3",
        events=clock_events,
        source_status=SourceStatus.INCOMPLETE,
        rules=rules,
        local_processing_seconds=0,
    )
    clock_reason = clock.historical_timing.exclusion_reason
    assert clock_reason == "clock_order_invalid"
    invalid_clock, unavailable = _evaluation_variants(evaluation, clock_reason)
    kinds = {
        "comparison": ArtifactKind.COMPARISON,
        "rule": ArtifactKind.RULE,
        "rule_test": ArtifactKind.RULE_TEST,
        "rule_test_failed": ArtifactKind.RULE_TEST,
        "run_report": ArtifactKind.RUN_REPORT,
        "evaluation": ArtifactKind.EVALUATION,
        "invalid_clock": ArtifactKind.EVALUATION,
        "unavailable": ArtifactKind.EVALUATION,
        "clock_investigation": ArtifactKind.INVESTIGATION,
    }
    models: dict[str, BaseModel] = {
        "comparison": genuine_artifacts[ArtifactKind.COMPARISON],
        "rule": genuine_artifacts[ArtifactKind.RULE],
        "rule_test": genuine_artifacts[ArtifactKind.RULE_TEST],
        "rule_test_failed": failed_rule_test,
        "run_report": run_report,
        "evaluation": evaluation,
        "invalid_clock": invalid_clock,
        "unavailable": unavailable,
        "clock_investigation": clock,
    }
    entries: list[dict[str, str]] = []
    source_events = {}
    investigator = InvestigationService(id_factory=sequential_ids())
    for state in ("completed", "failed", "incomplete"):
        path, events = _source(tmp_path, state)
        source_events[state] = events
        entries.append(
            {
                "id": f"source_{state}",
                "kind": "event_source",
                "path": path.name,
                "run_id": f"run_{state}",
            }
        )
        zero = investigator.investigate(
            path, f"run_{state}", RESOURCES / "rules", tmp_path / "derived"
        ).report
        assert zero.status == "completed" and zero.source_status.value == state
        assert not zero.derived_alerts and not zero.incidents
        assert all(not result.matches for result in zero.rule_evaluations)
        models[f"zero_{state}"] = zero
        kinds[f"zero_{state}"] = ArtifactKind.INVESTIGATION
    for item_id, model in models.items():
        artifact = tmp_path / f"{item_id}.json"
        artifact.write_text(model.model_dump_json(), encoding="utf-8")
        entry = {"id": item_id, "kind": kinds[item_id].value, "path": artifact.name}
        if item_id.startswith("zero_"):
            entry["source_id"] = f"source_{item_id.removeprefix('zero_')}"
        entries.append(entry)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": "1.0", "entries": entries}), encoding="utf-8")
    inventory = set(tmp_path.rglob("*"))
    before = {path: path.read_bytes() for path in inventory if path.is_file()}
    originals = {key: model.model_dump(mode="json") for key, model in models.items()}
    catalog = DashboardCatalog.load(manifest)
    records = deepcopy(catalog.records)
    try:
        yield DisplayInputs(catalog, models, source_events)
    finally:
        assert set(tmp_path.rglob("*")) == inventory
        assert {path: path.read_bytes() for path in before} == before
        assert catalog.records == records
        assert {key: model.model_dump(mode="json") for key, model in models.items()} == originals


@contextmanager
def _serve(page: Any, catalog: DashboardCatalog) -> Iterator[str]:
    """Same loopback/thread lifecycle as the existing harness; never execute before review."""
    with closing(socket.socket()) as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    origin = f"http://127.0.0.1:{port}"
    blocked: list[str] = []
    requests: list[str] = []

    def guard(route: Any) -> None:
        target = urlsplit(route.request.url)
        requests.append(route.request.url)
        if target.scheme == "http" and target.netloc == f"127.0.0.1:{port}":
            route.continue_()
        else:
            blocked.append(route.request.url)
            route.abort()

    page.context.route("**/*", guard)
    page.set_default_timeout(10000)
    page.set_default_navigation_timeout(10000)
    server = uvicorn.Server(
        uvicorn.Config(
            create_dashboard_app(catalog, port=port), host="127.0.0.1", port=port, log_level="error"
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        wait_for_server(server, thread)
        yield origin
        assert requests
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        page.context.unroute("**/*", guard)
        assert not thread.is_alive()
        assert not blocked


def _open(page: Any, origin: str, title: str, provenance: str, status: str) -> None:
    page.goto(origin)
    page.get_by_role("button", name=title, exact=True).click()
    playwright.expect(page.locator("#view-title")).to_have_text(title)
    playwright.expect(page.locator("#status")).to_have_text("Detail loaded.")
    playwright.expect(page.locator("#view > p .tag")).to_have_text([provenance, status])


def _table(page: Any, table: Any, expected: dict[str, Any]) -> None:
    rows = table.locator("tbody > tr")
    playwright.expect(rows).to_have_count(len(expected))
    for key, value in expected.items():
        label = re.compile(f"^{re.escape(key.replace('_', ' '))}$")
        row = rows.filter(has=page.locator("th").filter(has_text=label))
        playwright.expect(row).to_have_count(1)
        actual = row.locator("td").inner_text()
        if value is None:
            assert actual == "Unavailable"
        elif isinstance(value, str):
            assert actual == value
        else:
            assert json.loads(actual) == value


def test_saved_artifact_views_equal_validated_models(
    page: Any, display_inputs: DisplayInputs
) -> None:
    with _serve(page, display_inputs.catalog) as origin:
        for item_id, label, identity in (
            ("comparison", "Comparison", "comparison_id"),
            ("rule", "Rule", "rule_id"),
            ("rule_test", "Rule Test", None),
            ("rule_test_failed", "Rule Test", None),
            ("run_report", "Run Report", "run_id"),
        ):
            data = display_inputs.models[item_id].model_dump(mode="json")
            title = f"{label} {data[identity] if identity else item_id}"
            _open(page, origin, title, "report_only", data.get("status", "available"))
            if item_id == "run_report":
                timeline = data.pop("timeline")
                data["nested_collection_counts"] = {"timeline": len(timeline)}
                rows = page.locator("#run-timeline tbody tr")
                playwright.expect(rows).to_have_count(len(timeline))
                for index, event in enumerate(timeline):
                    playwright.expect(rows.nth(index).locator("td")).to_have_text(
                        [
                            str(event["sequence"]),
                            event["timestamp"],
                            event["event_type"],
                            event["source_component"],
                            "Reported only",
                        ]
                    )
                playwright.expect(page.get_by_role("button", name="Open evidence")).to_have_count(0)
            _table(page, page.locator("#view > table"), data)


def test_zero_match_and_source_states_stay_distinct(
    page: Any, display_inputs: DisplayInputs
) -> None:
    with _serve(page, display_inputs.catalog) as origin:
        for state in ("failed", "incomplete"):
            _open(page, origin, f"Run run_{state}", "verified_against_source", state)
            events = display_inputs.events[state]
            rows = page.locator("#run-timeline tbody tr")
            playwright.expect(rows).to_have_count(len(events))
            for index, event in enumerate(events):
                playwright.expect(rows.nth(index).locator("td").nth(2)).to_have_text(
                    event.event_type
                )
        for state in ("completed", "failed", "incomplete"):
            zero = display_inputs.models[f"zero_{state}"].model_dump(mode="json")
            _open(
                page,
                origin,
                f"Investigation {zero['investigation_id']}",
                "verified_against_source",
                "completed",
            )
            detail = dict(zero)
            detail["catalog_source_id"] = f"source_{state}"
            detail["nested_collection_counts"] = {
                name: len(detail.pop(field))
                for name, field in (
                    ("alerts", "derived_alerts"),
                    ("incidents", "incidents"),
                    ("rule-evaluations", "rule_evaluations"),
                )
            }
            assert detail["source_status"] == state and detail["status"] == "completed"
            _table(page, page.locator("#view > table"), detail)
            for name, field in (("alerts", "derived_alerts"), ("incidents", "incidents")):
                assert zero[field] == []
                playwright.expect(
                    page.locator(f"#nested-{name}").get_by_text(f"No {name} recorded.", exact=True)
                ).to_be_visible()
                playwright.expect(page.locator(f"#nested-{name} article")).to_have_count(0)
            tables = page.locator("#nested-rule-evaluations > table")
            playwright.expect(tables).to_have_count(len(zero["rule_evaluations"]))
            for index, result in enumerate(zero["rule_evaluations"]):
                assert result["matches"] == []
                _table(page, tables.nth(index), result)


def test_evaluation_fractions_pairs_and_recorded_timing_match_models(
    page: Any, display_inputs: DisplayInputs
) -> None:
    with _serve(page, display_inputs.catalog) as origin:
        for item_id in ("evaluation", "invalid_clock", "unavailable"):
            data = display_inputs.models[item_id].model_dump(mode="json")
            _open(
                page, origin, f"Evaluation {data['evaluation_id']}", "report_only", data["status"]
            )
            detail = {
                key: value
                for key, value in data.items()
                if key not in {"metrics", "children", "pairs", "confusion_counts", "timing"}
            }
            detail["nested_collection_counts"] = {
                name: len(data[field])
                for name, field in (
                    ("metrics", "metrics"),
                    ("children", "children"),
                    ("pairs", "pairs"),
                    ("confusion-counts", "confusion_counts"),
                    ("timing", "timing"),
                )
            }
            _table(page, page.locator("#view > table"), detail)
            cards = page.locator("#nested-metrics > article")
            playwright.expect(cards).to_have_count(10)
            for index, metric in enumerate(data["metrics"]):
                card = cards.nth(index)
                _table(page, card.locator("table"), metric)
                fraction = (
                    f"{metric['numerator']}/{metric['denominator']}"
                    if metric["denominator"]
                    else "Unavailable"
                )
                playwright.expect(card.locator("h4")).to_have_text(
                    f"{metric['profile']}: {metric['name'].replace('_', ' ')}"
                )
                progress = card.get_by_role(
                    "progressbar", name=f"{metric['name']} {fraction}", exact=True
                )
                playwright.expect(card.locator("caption")).to_have_text(
                    f"Exact metric values: {fraction}"
                )
                if metric["denominator"]:
                    assert float(progress.get_attribute("value")) == metric["value"]
                else:
                    assert progress.get_attribute("value") is None
            for name, field in (
                ("pairs", "pairs"),
                ("confusion-counts", "confusion_counts"),
                ("timing", "timing"),
            ):
                tables = page.locator(f"#nested-{name} > table")
                playwright.expect(tables).to_have_count(len(data[field]))
                for index, expected in enumerate(data[field]):
                    _table(page, tables.nth(index), expected)
            children = page.locator("#nested-children > article")
            playwright.expect(children).to_have_count(len(data["children"]))
            for index, child in enumerate(data["children"]):
                card = children.nth(index)
                playwright.expect(card.locator("h4")).to_have_text(
                    f"{child['case_id']} · trial {child['trial']} · {child['profile']}"
                )
                assertion = "passed" if child["assertion_passed"] else "failed"
                playwright.expect(
                    card.get_by_text(
                        f"Status: {child['status']}; assertion: {assertion}", exact=True
                    )
                ).to_be_visible()
                if child["exclusion_reason"]:
                    playwright.expect(
                        card.get_by_text(f"Excluded: {child['exclusion_reason']}", exact=True)
                    ).to_be_visible()
        clock = display_inputs.models["clock_investigation"].model_dump(mode="json")
        _open(
            page, origin, f"Investigation {clock['investigation_id']}", "report_only", "completed"
        )
        rows = page.locator("#view > table > tbody > tr")
        timing = rows.filter(has=page.get_by_text("historical timing", exact=True)).locator("td")
        assert json.loads(timing.inner_text()) == clock["historical_timing"]
        assert clock["historical_timing"]["exclusion_reason"] == "clock_order_invalid"
        assert clock["historical_timing"]["basis"] == "recorded_legacy"
        assert clock["historical_timing"]["alert_seconds"] is None
        assert clock["historical_timing"]["incident_seconds"] is None
