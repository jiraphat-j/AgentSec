"""Public dashboard response-byte limits; execute only in the networkless lab sandbox."""

import json
from collections.abc import Callable
from copy import deepcopy
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pytest import CaptureFixture, LogCaptureFixture

from agentsec.constants import MAX_DASHBOARD_RESPONSE_BYTES
from agentsec.dashboard_api import create_dashboard_app
from agentsec.dashboard_catalog import CatalogRecord, DashboardCatalog
from agentsec.dashboard_models import ArtifactKind, CatalogSummary, Provenance

PAGINATED_ROUTES: list[tuple[ArtifactKind, str, str, str]] = [
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

CHILD_ROUTES: list[tuple[str, str, str]] = [
    ("alerts", "derived_alerts", "alert"),
    ("incidents", "incidents", "incident"),
]


def _assert_security_headers(response: Any) -> None:
    cache_control = response.headers.get("cache-control", "")
    assert "no-store" in cache_control, (
        f"Expected no-store in Cache-Control, got: {cache_control!r}"
    )
    assert response.headers.get("x-content-type-options") == "nosniff"
    csp = response.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp, f"Expected default-src 'self' in CSP, got: {csp!r}"


def _verify_boundary_lifecycle(
    *,
    kind: ArtifactKind,
    data_key: str,
    encoding_mode: str,
    make_url: Callable[[int], str],
    make_expected: Callable[[int, dict[str, object]], dict[str, object]],
    capsys: CaptureFixture[str],
    caplog: LogCaptureFixture,
) -> None:
    row0: dict[str, object] = {"nested": {"layer": [{"field": "small-0"}]}}
    row2: dict[str, object] = {"nested": {"layer": [{"field": "small-2"}]}}
    empty_row1: dict[str, object] = {"nested": {"layer": [{"field": ""}]}}

    empty_envelope = make_expected(1, empty_row1)
    empty_bytes = json.dumps(
        empty_envelope,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    base_len = len(empty_bytes)
    needed_text_bytes = MAX_DASHBOARD_RESPONSE_BYTES - base_len

    marker = "synthetic-response-field"
    marker_bytes = len(marker.encode("utf-8"))
    rem_bytes = needed_text_bytes - marker_bytes

    if encoding_mode == "ascii":
        text = marker + ("x" * rem_bytes)
    else:
        num_e = rem_bytes // 2
        num_x = rem_bytes % 2
        text = marker + ("é" * num_e) + ("x" * num_x)

    if encoding_mode == "utf8":
        assert len(text.encode("utf-8")) != len(text)
        assert "é" in text
    assert marker in text

    row1: dict[str, object] = {"nested": {"layer": [{"field": text}]}}
    positive_data: dict[str, object] = {data_key: [row0, row1, row2]}

    expected_1 = make_expected(1, row1)
    expected_bytes_1 = json.dumps(
        expected_1,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert len(expected_bytes_1) == MAX_DASHBOARD_RESPONSE_BYTES

    canonical_before = json.dumps(positive_data, sort_keys=True, ensure_ascii=False)
    pos_summary = CatalogSummary(
        id="artifact",
        kind=kind,
        provenance=Provenance.REPORT_ONLY,
        title="Synthetic artifact",
        status="available",
    )
    pos_record = CatalogRecord(summary=pos_summary, data=positive_data)
    pos_catalog = DashboardCatalog((pos_record,))

    with TestClient(
        create_dashboard_app(pos_catalog),
        base_url="http://127.0.0.1:8765",
    ) as pos_client:
        pos_resp = pos_client.get(make_url(1))
        assert pos_resp.status_code == 200
        _assert_security_headers(pos_resp)
        assert len(pos_resp.content) == MAX_DASHBOARD_RESPONSE_BYTES
        assert pos_resp.content == expected_bytes_1
        assert pos_resp.json() == expected_1
        if encoding_mode == "utf8":
            assert b"\xc3\xa9" in pos_resp.content
            assert b"\\u00e9" not in pos_resp.content

    canonical_after = json.dumps(positive_data, sort_keys=True, ensure_ascii=False)
    assert canonical_before == canonical_after

    bad_data = deepcopy(positive_data)
    bad_text = text + "x"
    bad_row1: dict[str, object] = {"nested": {"layer": [{"field": bad_text}]}}
    bad_rows = bad_data[data_key]
    assert isinstance(bad_rows, list)
    bad_rows[1] = bad_row1

    expected_bad_envelope = make_expected(1, bad_row1)
    expected_bad_bytes = json.dumps(
        expected_bad_envelope,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert len(expected_bad_bytes) == MAX_DASHBOARD_RESPONSE_BYTES + 1

    bad_canonical_before = json.dumps(bad_data, sort_keys=True, ensure_ascii=False)
    bad_summary = CatalogSummary(
        id="artifact",
        kind=kind,
        provenance=Provenance.REPORT_ONLY,
        title="Synthetic artifact",
        status="available",
    )
    bad_record = CatalogRecord(summary=bad_summary, data=bad_data)
    bad_catalog = DashboardCatalog((bad_record,))

    expected_0 = make_expected(0, row0)
    expected_bytes_0 = json.dumps(
        expected_0,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")

    expected_2 = make_expected(2, row2)
    expected_bytes_2 = json.dumps(
        expected_2,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")

    with TestClient(
        create_dashboard_app(bad_catalog),
        base_url="http://127.0.0.1:8765",
    ) as bad_client:
        resp_0_before = bad_client.get(make_url(0))
        assert resp_0_before.status_code == 200
        _assert_security_headers(resp_0_before)
        assert resp_0_before.content == expected_bytes_0
        assert resp_0_before.json() == expected_0

        resp_2_before = bad_client.get(make_url(2))
        assert resp_2_before.status_code == 200
        _assert_security_headers(resp_2_before)
        assert resp_2_before.content == expected_bytes_2
        assert resp_2_before.json() == expected_2

        for _ in range(2):
            err_resp = bad_client.get(make_url(1))
            assert err_resp.status_code == 503
            assert err_resp.json() == {"error": {"code": "response_limit_exceeded"}}
            _assert_security_headers(err_resp)
            assert marker not in err_resp.text
            captured = capsys.readouterr()
            assert marker not in captured.out
            assert marker not in captured.err
            assert marker not in caplog.text

        resp_0_after = bad_client.get(make_url(0))
        assert resp_0_after.status_code == 200
        _assert_security_headers(resp_0_after)
        assert resp_0_after.content == expected_bytes_0
        assert resp_0_after.json() == expected_0

        resp_2_after = bad_client.get(make_url(2))
        assert resp_2_after.status_code == 200
        _assert_security_headers(resp_2_after)
        assert resp_2_after.content == expected_bytes_2
        assert resp_2_after.json() == expected_2

    bad_canonical_after = json.dumps(bad_data, sort_keys=True, ensure_ascii=False)
    assert bad_canonical_before == bad_canonical_after


@pytest.mark.parametrize("kind,collection,nested,data_key", PAGINATED_ROUTES)
@pytest.mark.parametrize("encoding_mode", ["ascii", "utf8"])
def test_dashboard_paginated_response_limits(
    kind: ArtifactKind,
    collection: str,
    nested: str,
    data_key: str,
    encoding_mode: str,
    capsys: CaptureFixture[str],
    caplog: LogCaptureFixture,
) -> None:
    def make_url(idx: int) -> str:
        return f"/api/v1/{collection}/artifact/{nested}?offset={idx}&limit=1"

    def make_expected(idx: int, row: dict[str, object]) -> dict[str, object]:
        return {"items": [row], "total": 3, "offset": idx, "limit": 1}

    _verify_boundary_lifecycle(
        kind=kind,
        data_key=data_key,
        encoding_mode=encoding_mode,
        make_url=make_url,
        make_expected=make_expected,
        capsys=capsys,
        caplog=caplog,
    )


@pytest.mark.parametrize("nested,data_key,prefix", CHILD_ROUTES)
@pytest.mark.parametrize("encoding_mode", ["ascii", "utf8"])
def test_dashboard_child_response_limits(
    nested: str,
    data_key: str,
    prefix: str,
    encoding_mode: str,
    capsys: CaptureFixture[str],
    caplog: LogCaptureFixture,
) -> None:
    def make_url(idx: int) -> str:
        return f"/api/v1/investigations/artifact/{nested}/{prefix}-{idx}"

    def make_expected(idx: int, row: dict[str, object]) -> dict[str, object]:
        return {"id": f"{prefix}-{idx}", **row}

    _verify_boundary_lifecycle(
        kind=ArtifactKind.INVESTIGATION,
        data_key=data_key,
        encoding_mode=encoding_mode,
        make_url=make_url,
        make_expected=make_expected,
        capsys=capsys,
        caplog=caplog,
    )
