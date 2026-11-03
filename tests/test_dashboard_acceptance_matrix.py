"""AgentSec A1 request-boundary acceptance matrix tests."""

import copy
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentsec.dashboard_api import create_dashboard_app
from agentsec.dashboard_catalog import CatalogRecord, DashboardCatalog
from agentsec.rule_models import RuleTestReport

SYNTHETIC_MARKER = "synthetic-raw-file-marker"
RAW_ARTIFACT_JSON = (
    '{"schema_version":"1.0","status":"failed","total_rules":1,"covered_rules":0,'
    '"assertions_passed":0,"assertions_total":1,"results":[{"fixture":'
    f'"{SYNTHETIC_MARKER}","rule_id":"ASL-TEST-001","rule_version":1,"passed":false,'
    '"expected_evidence":[],"actual_evidence":[]}]}'
)
MANIFEST_JSON = (
    '{"schema_version":"1.0","entries":[{"id":"artifact","kind":"rule_test",'
    '"path":"artifact.json"}]}'
)
EXPECTED_CATALOG_SUMMARY: dict[str, Any] = {
    "id": "artifact",
    "kind": "rule_test",
    "provenance": "report_only",
    "title": "Rule Test artifact",
    "status": "failed",
}
CROSS_SITE_ERROR: dict[str, Any] = {"error": {"code": "cross_site_request_rejected"}}
METHOD_NOT_ALLOWED_ERROR: dict[str, Any] = {"error": {"code": "method_not_allowed"}}


@dataclass(frozen=True, slots=True)
class BoundaryCase:
    case_id: str
    method: str
    path: str
    headers: dict[str, str]
    expected_status: int
    expected_body: dict[str, Any] | None = None
    check_no_cors_headers: bool = False


CASES: list[BoundaryCase] = [
    BoundaryCase(
        "get-origin-correct",
        "GET",
        "/api/v1/catalog",
        {"Origin": "http://127.0.0.1:8765"},
        200,
    ),
    BoundaryCase(
        "get-origin-wrong-port",
        "GET",
        "/api/v1/catalog",
        {"Origin": "http://127.0.0.1:8766"},
        403,
        CROSS_SITE_ERROR,
    ),
    BoundaryCase("get-fetch-site-absent", "GET", "/api/v1/catalog", {}, 200),
    BoundaryCase(
        "get-fetch-site-none",
        "GET",
        "/api/v1/catalog",
        {"Sec-Fetch-Site": "none"},
        200,
    ),
    BoundaryCase(
        "get-fetch-site-same-origin",
        "GET",
        "/api/v1/catalog",
        {"Sec-Fetch-Site": "same-origin"},
        200,
    ),
    BoundaryCase(
        "get-fetch-site-same-site",
        "GET",
        "/api/v1/catalog",
        {"Sec-Fetch-Site": "same-site"},
        403,
        CROSS_SITE_ERROR,
    ),
    BoundaryCase("head-catalog", "HEAD", "/api/v1/catalog", {}, 200),
    BoundaryCase(
        "options-preflight-put",
        "OPTIONS",
        "/api/v1/catalog",
        {"Origin": "http://127.0.0.1:8765", "Access-Control-Request-Method": "PUT"},
        405,
        METHOD_NOT_ALLOWED_ERROR,
        check_no_cors_headers=True,
    ),
    BoundaryCase("put-catalog", "PUT", "/api/v1/catalog", {}, 405, METHOD_NOT_ALLOWED_ERROR),
    BoundaryCase(
        "patch-catalog",
        "PATCH",
        "/api/v1/catalog",
        {},
        405,
        METHOD_NOT_ALLOWED_ERROR,
    ),
    BoundaryCase(
        "delete-catalog",
        "DELETE",
        "/api/v1/catalog",
        {},
        405,
        METHOD_NOT_ALLOWED_ERROR,
    ),
    BoundaryCase("get-disabled-docs", "GET", "/docs", {}, 404),
    BoundaryCase("get-disabled-redoc", "GET", "/redoc", {}, 404),
    BoundaryCase("get-disabled-openapi", "GET", "/openapi.json", {}, 404),
    BoundaryCase("get-disabled-assets-report", "GET", "/assets/report.json", {}, 404),
    BoundaryCase("get-disabled-report", "GET", "/report.json", {}, 404),
    BoundaryCase(
        "get-disabled-assets-traversal",
        "GET",
        "/assets/%2e%2e/report.json",
        {},
        404,
    ),
]


HEAD_CASES: list[BoundaryCase] = [
    BoundaryCase("head-index", "HEAD", "/", {}, 200),
    BoundaryCase("head-styles", "HEAD", "/assets/styles.css", {}, 200),
    BoundaryCase("head-script", "HEAD", "/assets/app.js", {}, 200),
    BoundaryCase("head-catalog-route", "HEAD", "/api/v1/catalog", {}, 200),
    BoundaryCase("head-collection", "HEAD", "/api/v1/rule-tests", {}, 200),
    BoundaryCase("head-detail", "HEAD", "/api/v1/rule-tests/artifact", {}, 200),
    BoundaryCase("head-events-missing", "HEAD", "/api/v1/runs/missing/events", {}, 404),
    BoundaryCase("head-event-missing", "HEAD", "/api/v1/runs/missing/events/missing", {}, 404),
    BoundaryCase("head-timeline-missing", "HEAD", "/api/v1/runs/missing/timeline", {}, 404),
    BoundaryCase(
        "head-alert-missing", "HEAD", "/api/v1/investigations/missing/alerts/missing", {}, 404
    ),
    BoundaryCase(
        "head-incident-missing", "HEAD", "/api/v1/investigations/missing/incidents/missing", {}, 404
    ),
    BoundaryCase("head-nested-missing", "HEAD", "/api/v1/investigations/missing/alerts", {}, 404),
    BoundaryCase(
        "head-origin-correct", "HEAD", "/api/v1/catalog", {"Origin": "http://127.0.0.1:8765"}, 200
    ),
    BoundaryCase(
        "head-fetch-site-same-origin",
        "HEAD",
        "/api/v1/catalog",
        {"Sec-Fetch-Site": "same-origin"},
        200,
    ),
    BoundaryCase(
        "head-origin-foreign",
        "HEAD",
        "/api/v1/catalog",
        {"Origin": "https://synthetic.invalid"},
        403,
        CROSS_SITE_ERROR,
    ),
    BoundaryCase(
        "head-origin-wrong-port",
        "HEAD",
        "/api/v1/catalog",
        {"Origin": "http://127.0.0.1:8766"},
        403,
        CROSS_SITE_ERROR,
    ),
    BoundaryCase(
        "head-fetch-site-same-site",
        "HEAD",
        "/api/v1/catalog",
        {"Sec-Fetch-Site": "same-site"},
        403,
        CROSS_SITE_ERROR,
    ),
    BoundaryCase(
        "head-fetch-site-cross-site",
        "HEAD",
        "/api/v1/catalog",
        {"Sec-Fetch-Site": "cross-site"},
        403,
        CROSS_SITE_ERROR,
    ),
    BoundaryCase(
        "head-host-foreign", "HEAD", "/api/v1/catalog", {"Host": "synthetic.invalid"}, 400
    ),
    BoundaryCase(
        "head-query-unknown",
        "HEAD",
        "/api/v1/catalog?unknown=1",
        {},
        422,
        {"error": {"code": "invalid_query"}},
    ),
    BoundaryCase(
        "head-query-duplicate",
        "HEAD",
        "/api/v1/catalog?limit=1&limit=1",
        {},
        422,
        {"error": {"code": "invalid_query"}},
    ),
    BoundaryCase(
        "head-query-limit-over",
        "HEAD",
        "/api/v1/catalog?limit=201",
        {},
        422,
        {"error": {"code": "invalid_query"}},
    ),
    BoundaryCase("head-disabled-docs", "HEAD", "/docs", {}, 404),
    BoundaryCase("head-disabled-redoc", "HEAD", "/redoc", {}, 404),
    BoundaryCase("head-disabled-openapi", "HEAD", "/openapi.json", {}, 404),
    BoundaryCase("head-disabled-report", "HEAD", "/report.json", {}, 404),
    BoundaryCase("head-disabled-assets-report", "HEAD", "/assets/report.json", {}, 404),
    BoundaryCase("head-disabled-assets-traversal", "HEAD", "/assets/%2e%2e/report.json", {}, 404),
]


@dataclass(frozen=True, slots=True)
class BoundaryEnv:
    client: TestClient
    model_data: dict[str, Any]
    artifact_path: Path
    manifest_path: Path
    artifact_bytes: bytes
    manifest_bytes: bytes
    catalog: DashboardCatalog
    catalog_snapshot: tuple[CatalogRecord, ...]


@pytest.fixture
def boundary_env(tmp_path: Path) -> Iterator[BoundaryEnv]:
    artifact_path = tmp_path / "artifact.json"
    artifact_path.write_text(RAW_ARTIFACT_JSON, encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(MANIFEST_JSON, encoding="utf-8")

    model = RuleTestReport.model_validate_json(RAW_ARTIFACT_JSON)
    model_data = model.model_dump(mode="json")

    catalog = DashboardCatalog.load(manifest_path)
    assert catalog.records[0].data == model_data, "catalog record mismatch with model dump"

    artifact_bytes = artifact_path.read_bytes()
    manifest_bytes = manifest_path.read_bytes()
    catalog_snapshot = copy.deepcopy(catalog.records)

    app = create_dashboard_app(catalog)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        yield BoundaryEnv(
            client=client,
            model_data=model_data,
            artifact_path=artifact_path,
            manifest_path=manifest_path,
            artifact_bytes=artifact_bytes,
            manifest_bytes=manifest_bytes,
            catalog=catalog,
            catalog_snapshot=catalog_snapshot,
        )


@pytest.mark.parametrize("case", CASES, ids=[c.case_id for c in CASES])
def test_dashboard_a1_request_boundary(case: BoundaryCase, boundary_env: BoundaryEnv) -> None:
    env = boundary_env
    baseline_resp = env.client.get("/api/v1/rule-tests/artifact")
    assert baseline_resp.status_code == 200, "baseline status != 200"
    assert baseline_resp.json() == {
        "summary": EXPECTED_CATALOG_SUMMARY,
        "data": env.model_data,
    }, "baseline data mismatch"

    resp = env.client.request(case.method, case.path, headers=case.headers)

    csp = resp.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp, "CSP mismatch"
    assert resp.headers.get("x-content-type-options") == "nosniff", "nosniff mismatch"
    assert resp.headers.get("cache-control") == "no-store", "cache-control mismatch"
    assert resp.headers.get("referrer-policy") == "no-referrer", "referrer-policy mismatch"
    assert resp.headers.get("x-frame-options") == "DENY", "x-frame-options mismatch"

    assert env.artifact_path.read_bytes() == env.artifact_bytes, "artifact modified"
    assert env.manifest_path.read_bytes() == env.manifest_bytes, "manifest modified"
    assert env.catalog.records == env.catalog_snapshot, "catalog mutated"

    if resp.status_code != 200 or not case.path.startswith("/api/v1/rule-tests"):
        assert SYNTHETIC_MARKER not in resp.text, "synthetic marker leaked"

    if case.check_no_cors_headers:
        assert not any(k.lower().startswith("access-control-allow-") for k in resp.headers), (
            "unexpected CORS header"
        )

    assert resp.status_code == case.expected_status, (
        f"status {resp.status_code} != {case.expected_status}"
    )

    if case.method == "HEAD":
        assert resp.content == b"", "HEAD body not empty"
    elif case.method == "GET" and case.expected_status == 200 and case.path == "/api/v1/catalog":
        assert resp.json() == {
            "items": [EXPECTED_CATALOG_SUMMARY],
            "total": 1,
            "offset": 0,
            "limit": 50,
        }, "catalog payload mismatch"
    elif case.expected_body is not None:
        assert resp.json() == case.expected_body, "body mismatch"


@pytest.mark.parametrize("case", HEAD_CASES, ids=[c.case_id for c in HEAD_CASES])
def test_dashboard_head_matches_get(case: BoundaryCase, boundary_env: BoundaryEnv) -> None:
    env = boundary_env
    baseline = env.client.get("/api/v1/rule-tests/artifact")
    assert baseline.status_code == 200
    assert baseline.json() == {
        "summary": EXPECTED_CATALOG_SUMMARY,
        "data": env.model_data,
    }

    get_response = env.client.get(case.path, headers=case.headers)
    head_response = env.client.head(case.path, headers=case.headers)

    assert env.artifact_path.read_bytes() == env.artifact_bytes
    assert env.manifest_path.read_bytes() == env.manifest_bytes
    assert env.catalog.records == env.catalog_snapshot
    assert get_response.status_code == case.expected_status
    assert head_response.status_code == case.expected_status
    assert head_response.content == b""
    assert dict(head_response.headers) == dict(get_response.headers)
    assert int(head_response.headers["content-length"]) == len(get_response.content)
    assert "default-src 'self'" in head_response.headers["content-security-policy"]
    assert head_response.headers["x-content-type-options"] == "nosniff"
    assert head_response.headers["cache-control"] == "no-store"
    assert head_response.headers["referrer-policy"] == "no-referrer"
    assert head_response.headers["x-frame-options"] == "DENY"
    assert not any(k.lower().startswith("access-control-allow-") for k in head_response.headers)
    if case.expected_status != 200:
        assert SYNTHETIC_MARKER not in get_response.text
    if case.expected_body is not None:
        assert get_response.json() == case.expected_body
