"""Nested dashboard response guards; execute only in the networkless lab sandbox."""

import copy
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentsec.dashboard_api import create_dashboard_app
from agentsec.dashboard_catalog import CatalogRecord, DashboardCatalog
from agentsec.dashboard_models import ArtifactKind, CatalogSummary, Provenance
from agentsec.resource_loader import load_canary

BASE_URL = "http://127.0.0.1:8765"

SAFE_CANARY = "synthetic-safe-value"
SAFE_METADATA: dict[str, str] = {
    "prompt_id": "malicious",
    "source": "packaged_prompt_fixture",
    "trust": "untrusted",
    "delivery_channel": "direct_prompt",
}
UNSAFE_METADATA_EXTRA = "synthetic-forged-metadata"

PAGINATED_CASES: list[tuple[ArtifactKind, str, str, str]] = [
    (ArtifactKind.INVESTIGATION, "investigations", "alerts", "derived_alerts"),
    (ArtifactKind.INVESTIGATION, "investigations", "incidents", "incidents"),
    (ArtifactKind.INVESTIGATION, "investigations", "rule-evaluations", "rule_evaluations"),
    (ArtifactKind.EVALUATION, "evaluations", "children", "children"),
    (ArtifactKind.EVALUATION, "evaluations", "metrics", "metrics"),
    (ArtifactKind.EVALUATION, "evaluations", "pairs", "pairs"),
    (ArtifactKind.EVALUATION, "evaluations", "confusion-counts", "confusion_counts"),
    (ArtifactKind.EVALUATION, "evaluations", "timing", "timing"),
    (ArtifactKind.RUN_REPORT, "runs", "timeline", "timeline"),
]

CHILD_CASES: list[tuple[str, str, str]] = [
    ("alerts", "derived_alerts", "alert"),
    ("incidents", "incidents", "incident"),
]

VARIANTS: list[str] = ["canary", "metadata"]


def _make_row(index: int, value: object) -> dict[str, object]:
    return {
        "label": f"row-{index}",
        "details": {
            "values": [value],
        },
    }


def _get_variant_values(variant: str) -> tuple[object, object, str]:
    if variant == "canary":
        canary_val = load_canary()
        return SAFE_CANARY, canary_val, str(canary_val)
    if variant == "metadata":
        safe_meta = dict(SAFE_METADATA)
        unsafe_meta = {**SAFE_METADATA, "unsafe_extra": UNSAFE_METADATA_EXTRA}
        return safe_meta, unsafe_meta, UNSAFE_METADATA_EXTRA
    raise ValueError(f"Unknown variant: {variant}")


def _build_catalog(
    kind: ArtifactKind,
    data_key: str,
    rows: list[dict[str, object]],
) -> tuple[DashboardCatalog, CatalogRecord, dict[str, object]]:
    summary = CatalogSummary(
        id="artifact",
        kind=kind,
        provenance=Provenance.REPORT_ONLY,
        title="Synthetic artifact",
        status="available",
    )
    data: dict[str, object] = {data_key: rows}
    record = CatalogRecord(summary, data)
    catalog = DashboardCatalog((record,))
    return catalog, record, data


def _assert_unsafe_response(
    resp: Any,
    unsafe_marker: str,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    assert resp.status_code == 503
    assert resp.json() == {"error": {"code": "unsafe_projection_rejected"}}
    assert resp.headers.get("cache-control") == "no-store"
    assert resp.headers.get("x-content-type-options") == "nosniff"
    csp = resp.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert unsafe_marker not in resp.text
    captured = capsys.readouterr()
    assert unsafe_marker not in captured.out
    assert unsafe_marker not in captured.err
    assert unsafe_marker not in caplog.text


def _paginated_url(collection: str, nested: str, index: int) -> str:
    return f"/api/v1/{collection}/artifact/{nested}?offset={index}&limit=1"


def _expected_paginated_json(row: dict[str, object], index: int) -> dict[str, object]:
    return {
        "items": [row],
        "total": 3,
        "offset": index,
        "limit": 1,
    }


def _child_url(nested: str, prefix: str, index: int) -> str:
    return f"/api/v1/investigations/artifact/{nested}/{prefix}-{index}"


def _expected_child_json(row: dict[str, object], prefix: str, index: int) -> dict[str, object]:
    return {"id": f"{prefix}-{index}", **row}


@pytest.mark.parametrize("kind,collection,nested,data_key", PAGINATED_CASES)
@pytest.mark.parametrize("variant", VARIANTS)
def test_paginated_nested_projection_guards(
    kind: ArtifactKind,
    collection: str,
    nested: str,
    data_key: str,
    variant: str,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    safe_val, unsafe_val, unsafe_marker = _get_variant_values(variant)

    safe_rows: list[dict[str, object]] = [
        _make_row(0, copy.deepcopy(safe_val)),
        _make_row(1, copy.deepcopy(safe_val)),
        _make_row(2, copy.deepcopy(safe_val)),
    ]

    safe_catalog, _, _ = _build_catalog(kind, data_key, safe_rows)
    with TestClient(create_dashboard_app(safe_catalog), base_url=BASE_URL) as safe_client:
        safe_resp = safe_client.get(_paginated_url(collection, nested, 1))
        assert safe_resp.status_code == 200
        assert safe_resp.json() == _expected_paginated_json(safe_rows[1], 1)

    bad_rows: list[dict[str, object]] = copy.deepcopy(safe_rows)
    bad_rows[1] = _make_row(1, copy.deepcopy(unsafe_val))

    bad_catalog, bad_record, bad_data = _build_catalog(kind, data_key, bad_rows)
    canonical_before = json.dumps(bad_data, sort_keys=True)

    with TestClient(create_dashboard_app(bad_catalog), base_url=BASE_URL) as bad_client:
        r0_before = bad_client.get(_paginated_url(collection, nested, 0))
        assert r0_before.status_code == 200
        assert r0_before.json() == _expected_paginated_json(bad_rows[0], 0)

        r2_before = bad_client.get(_paginated_url(collection, nested, 2))
        assert r2_before.status_code == 200
        assert r2_before.json() == _expected_paginated_json(bad_rows[2], 2)

        for _ in range(10):
            r1_bad = bad_client.get(_paginated_url(collection, nested, 1))
            _assert_unsafe_response(r1_bad, unsafe_marker, capsys, caplog)

        r0_after = bad_client.get(_paginated_url(collection, nested, 0))
        assert r0_after.status_code == 200
        assert r0_after.json() == _expected_paginated_json(bad_rows[0], 0)

        r2_after = bad_client.get(_paginated_url(collection, nested, 2))
        assert r2_after.status_code == 200
        assert r2_after.json() == _expected_paginated_json(bad_rows[2], 2)

    assert json.dumps(bad_data, sort_keys=True) == canonical_before
    assert json.dumps(bad_record.data, sort_keys=True) == canonical_before


@pytest.mark.parametrize("nested,data_key,prefix", CHILD_CASES)
@pytest.mark.parametrize("variant", VARIANTS)
def test_child_nested_projection_guards(
    nested: str,
    data_key: str,
    prefix: str,
    variant: str,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    safe_val, unsafe_val, unsafe_marker = _get_variant_values(variant)

    safe_rows: list[dict[str, object]] = [
        _make_row(0, copy.deepcopy(safe_val)),
        _make_row(1, copy.deepcopy(safe_val)),
        _make_row(2, copy.deepcopy(safe_val)),
    ]

    safe_catalog, _, _ = _build_catalog(ArtifactKind.INVESTIGATION, data_key, safe_rows)
    with TestClient(create_dashboard_app(safe_catalog), base_url=BASE_URL) as safe_client:
        safe_resp = safe_client.get(_child_url(nested, prefix, 1))
        assert safe_resp.status_code == 200
        assert safe_resp.json() == _expected_child_json(safe_rows[1], prefix, 1)

    bad_rows: list[dict[str, object]] = copy.deepcopy(safe_rows)
    bad_rows[1] = _make_row(1, copy.deepcopy(unsafe_val))

    bad_catalog, bad_record, bad_data = _build_catalog(
        ArtifactKind.INVESTIGATION,
        data_key,
        bad_rows,
    )
    canonical_before = json.dumps(bad_data, sort_keys=True)

    with TestClient(create_dashboard_app(bad_catalog), base_url=BASE_URL) as bad_client:
        r0_before = bad_client.get(_child_url(nested, prefix, 0))
        assert r0_before.status_code == 200
        assert r0_before.json() == _expected_child_json(bad_rows[0], prefix, 0)

        r2_before = bad_client.get(_child_url(nested, prefix, 2))
        assert r2_before.status_code == 200
        assert r2_before.json() == _expected_child_json(bad_rows[2], prefix, 2)

        for _ in range(10):
            r1_bad = bad_client.get(_child_url(nested, prefix, 1))
            _assert_unsafe_response(r1_bad, unsafe_marker, capsys, caplog)

        r0_after = bad_client.get(_child_url(nested, prefix, 0))
        assert r0_after.status_code == 200
        assert r0_after.json() == _expected_child_json(bad_rows[0], prefix, 0)

        r2_after = bad_client.get(_child_url(nested, prefix, 2))
        assert r2_after.status_code == 200
        assert r2_after.json() == _expected_child_json(bad_rows[2], prefix, 2)

    assert json.dumps(bad_data, sort_keys=True) == canonical_before
    assert json.dumps(bad_record.data, sort_keys=True) == canonical_before
