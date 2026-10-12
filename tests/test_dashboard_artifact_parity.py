"""Genuine public-loader/API parity; execute only in the lab sandbox."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from agentsec.dashboard_api import create_dashboard_app
from agentsec.dashboard_catalog import DashboardCatalog
from agentsec.dashboard_models import ArtifactKind

from .test_dashboard_artifact_redaction import genuine_artifacts as genuine_artifacts

ARTIFACT_ROUTES = {
    ArtifactKind.COMPARISON: ("comparisons", "Comparison", "comparison_id"),
    ArtifactKind.EVALUATION: ("evaluations", "Evaluation", "evaluation_id"),
    ArtifactKind.RULE: ("rules", "Rule", "rule_id"),
    ArtifactKind.RULE_TEST: ("rule-tests", "Rule Test", None),
}
EVALUATION_COLLECTIONS = {
    "children": "children",
    "metrics": "metrics",
    "pairs": "pairs",
    "confusion-counts": "confusion_counts",
    "timing": "timing",
}


def _write_inputs(root: Path, model: BaseModel, kind: ArtifactKind) -> Path:
    artifact = root / "artifact.json"
    artifact.write_text(model.model_dump_json(), encoding="utf-8")
    manifest = root / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "entries": [{"id": "artifact", "kind": kind.value, "path": artifact.name}],
            }
        ),
        encoding="utf-8",
    )
    return manifest


def _input_snapshot(root: Path) -> tuple[set[Path], dict[Path, bytes]]:
    inventory = set(root.rglob("*"))
    return inventory, {path: path.read_bytes() for path in inventory if path.is_file()}


def _expected_summary(kind: ArtifactKind, canonical: dict[str, Any]) -> dict[str, Any]:
    _, label, identity_key = ARTIFACT_ROUTES[kind]
    identity = "artifact" if identity_key is None else canonical[identity_key]
    status = "available" if kind is ArtifactKind.RULE else canonical["status"]
    return {
        "id": "artifact",
        "kind": kind.value,
        "provenance": "report_only",
        "title": f"{label} {identity}",
        "status": status,
    }


def _expected_detail_data(kind: ArtifactKind, canonical: dict[str, Any]) -> dict[str, Any]:
    data = deepcopy(canonical)
    if kind is ArtifactKind.EVALUATION:
        counts = {}
        for collection, field in EVALUATION_COLLECTIONS.items():
            values = data.pop(field)
            assert isinstance(values, list)
            counts[collection] = len(values)
        data["nested_collection_counts"] = counts
    return data


@pytest.mark.parametrize("kind", tuple(ARTIFACT_ROUTES))
def test_genuine_artifact_public_loader_and_api_parity(
    tmp_path: Path,
    genuine_artifacts: dict[ArtifactKind, BaseModel],
    kind: ArtifactKind,
) -> None:
    model = genuine_artifacts[kind]
    canonical = model.model_dump(mode="json")
    summary = _expected_summary(kind, canonical)
    manifest = _write_inputs(tmp_path, model, kind)
    input_before = _input_snapshot(tmp_path)
    catalog = DashboardCatalog.load(manifest)
    assert len(catalog.records) == 1
    assert catalog.records[0].data == canonical
    assert catalog.records[0].summary.model_dump(mode="json") == summary
    records_before = deepcopy(catalog.records)
    collection = ARTIFACT_ROUTES[kind][0]

    with TestClient(create_dashboard_app(catalog), base_url="http://127.0.0.1:8765") as client:
        for route in ("/api/v1/catalog", f"/api/v1/{collection}"):
            for offset in (0, 1, 3):
                response = client.get(route, params={"offset": offset, "limit": 2})
                assert response.status_code == 200
                assert response.json() == {
                    "items": [summary] if offset == 0 else [],
                    "total": 1,
                    "offset": offset,
                    "limit": 2,
                }
        detail = client.get(f"/api/v1/{collection}/artifact")
        assert detail.status_code == 200
        assert detail.json() == {
            "summary": summary,
            "data": _expected_detail_data(kind, canonical),
        }

    assert _input_snapshot(tmp_path) == input_before
    assert catalog.records == records_before
    assert model.model_dump(mode="json") == canonical


@pytest.mark.parametrize("collection", tuple(EVALUATION_COLLECTIONS))
def test_genuine_evaluation_nested_pages_preserve_canonical_data(
    tmp_path: Path,
    genuine_artifacts: dict[ArtifactKind, BaseModel],
    collection: str,
) -> None:
    kind = ArtifactKind.EVALUATION
    model = genuine_artifacts[kind]
    canonical = model.model_dump(mode="json")
    expected_items = canonical[EVALUATION_COLLECTIONS[collection]]
    assert isinstance(expected_items, list)
    assert expected_items, "the genuine fixture must exercise nonempty pagination"
    summary = _expected_summary(kind, canonical)
    manifest = _write_inputs(tmp_path, model, kind)
    input_before = _input_snapshot(tmp_path)
    catalog = DashboardCatalog.load(manifest)
    assert len(catalog.records) == 1
    assert catalog.records[0].data == canonical
    assert catalog.records[0].summary.model_dump(mode="json") == summary
    records_before = deepcopy(catalog.records)

    with TestClient(create_dashboard_app(catalog), base_url="http://127.0.0.1:8765") as client:
        detail = client.get("/api/v1/evaluations/artifact")
        assert detail.status_code == 200
        assert detail.json() == {
            "summary": summary,
            "data": _expected_detail_data(kind, canonical),
        }
        received: list[Any] = []
        total = len(expected_items)
        for offset in (*range(0, total, 2), total, total + 2):
            response = client.get(
                f"/api/v1/evaluations/artifact/{collection}",
                params={"offset": offset, "limit": 2},
            )
            assert response.status_code == 200
            page = response.json()
            assert page == {
                "items": expected_items[offset : offset + 2],
                "total": total,
                "offset": offset,
                "limit": 2,
            }
            received.extend(page["items"])
        assert received == expected_items

    assert _input_snapshot(tmp_path) == input_before
    assert catalog.records == records_before
    assert model.model_dump(mode="json") == canonical
