"""Public-loader invalid-input evidence; execute only in the lab sandbox."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import BaseModel

from agentsec.dashboard_catalog import DashboardCatalog, DashboardInputError
from agentsec.dashboard_models import ArtifactKind, Provenance

from .test_dashboard_artifact_redaction import genuine_artifacts as genuine_artifacts


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("malformed_json", "artifact is not valid UTF-8 JSON"),
        ("invalid_utf8", "artifact is not valid UTF-8 JSON"),
        ("unknown_schema_version", "selected report failed schema validation"),
        ("unknown_kind", "dashboard manifest failed validation"),
        ("wrong_scalar_type", "selected report failed schema validation"),
        ("nonfinite_number", "JSON contains a non-finite number"),
    ],
)
def test_public_loader_rejects_invalid_artifact_without_changing_inputs(
    tmp_path: Path,
    genuine_artifacts: dict[ArtifactKind, BaseModel],
    case: str,
    message: str,
) -> None:
    model = genuine_artifacts[ArtifactKind.RULE_TEST]
    canonical = model.model_dump(mode="json")
    artifact = tmp_path / "artifact.json"
    artifact.write_text(model.model_dump_json(), encoding="utf-8")
    entries = [{"id": "artifact", "kind": "rule_test", "path": artifact.name}]
    manifest_value = {
        "schema_version": "1.0",
        "entries": entries,
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(manifest_value), encoding="utf-8")
    original_files = {path: path.read_bytes() for path in (manifest, artifact)}
    inventory = set(tmp_path.rglob("*"))
    assert inventory == {manifest, artifact}

    # The selected files must genuinely load before any intentional corruption.
    catalog = DashboardCatalog.load(manifest)
    assert len(catalog.records) == 1
    record = catalog.get("artifact")
    assert record is not None
    assert record.summary.kind is ArtifactKind.RULE_TEST
    assert record.summary.provenance is Provenance.REPORT_ONLY
    assert record.data == canonical
    records_before = deepcopy(catalog.records)
    assert {path: path.read_bytes() for path in original_files} == original_files
    assert set(tmp_path.rglob("*")) == inventory

    target = artifact
    invalid_value = deepcopy(canonical)
    if case == "malformed_json":
        assert original_files[artifact].endswith(b"}")
        invalid_bytes = original_files[artifact][:-1]
    elif case == "invalid_utf8":
        invalid_value["status"] = "\ufffd"
        encoded = json.dumps(invalid_value, ensure_ascii=False).encode("utf-8")
        assert encoded.count(b"\xef\xbf\xbd") == 1
        invalid_bytes = encoded.replace(b"\xef\xbf\xbd", b"\xff")
    elif case == "unknown_schema_version":
        invalid_value["schema_version"] = "999.0"
        invalid_bytes = json.dumps(invalid_value).encode("utf-8")
    elif case == "unknown_kind":
        target = manifest
        entries[0]["kind"] = "unknown_artifact"
        invalid_bytes = json.dumps(manifest_value).encode("utf-8")
    elif case == "wrong_scalar_type":
        assert type(canonical["total_rules"]) is int
        invalid_value["total_rules"] = str(canonical["total_rules"])
        invalid_bytes = json.dumps(invalid_value).encode("utf-8")
    else:
        assert case == "nonfinite_number"
        invalid_value["total_rules"] = float("nan")
        invalid_bytes = json.dumps(invalid_value, allow_nan=True).encode("utf-8")
        assert b'"total_rules": NaN' in invalid_bytes

    assert invalid_bytes != original_files[target]
    target.write_bytes(invalid_bytes)
    expected_files = {**original_files, target: invalid_bytes}
    with pytest.raises(DashboardInputError, match=f"^{message}$"):
        DashboardCatalog.load(manifest)
    assert {path: path.read_bytes() for path in expected_files} == expected_files
    assert set(tmp_path.rglob("*")) == inventory
    assert catalog.records == records_before
    assert model.model_dump(mode="json") == canonical
