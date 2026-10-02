"""Schema-valid artifact redaction checks; execute only in the lab sandbox."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from agentsec.cli import main
from agentsec.constants import DIRECT_PROMPT_SCENARIO_ID
from agentsec.dashboard_api import create_dashboard_app
from agentsec.dashboard_catalog import CatalogRecord, DashboardCatalog, DashboardInputError
from agentsec.dashboard_models import ArtifactKind, CatalogSummary, Provenance
from agentsec.evaluation import EvaluationService
from agentsec.incidents import InvestigationService
from agentsec.models import PromptFixture
from agentsec.replay import ReplayService
from agentsec.resource_loader import load_canary, load_prompt
from agentsec.rule_engine import load_rules
from agentsec.rule_testing import load_rule_fixtures, run_rule_tests
from agentsec.runner import ScenarioRunner

from .helpers import sequential_ids

RESOURCES = Path(__file__).parents[1] / "src/agentsec/resources"
KINDS = tuple(kind for kind in ArtifactKind if kind is not ArtifactKind.EVENT_SOURCE)
COLLECTIONS = {
    ArtifactKind.RUN_REPORT: "runs",
    ArtifactKind.COMPARISON: "comparisons",
    ArtifactKind.INVESTIGATION: "investigations",
    ArtifactKind.EVALUATION: "evaluations",
    ArtifactKind.RULE: "rules",
    ArtifactKind.RULE_TEST: "rule-tests",
}


@pytest.fixture(scope="module")
def genuine_artifacts(tmp_path_factory: pytest.TempPathFactory) -> dict[ArtifactKind, BaseModel]:
    """Generate real public-service artifacts, not hand-crafted invalid negative fixtures."""
    root = tmp_path_factory.mktemp("redaction-artifacts")
    runner = ScenarioRunner(id_factory=sequential_ids())
    run = runner.run(DIRECT_PROMPT_SCENARIO_ID, root / "runs")
    source = run.run_directory / "events.sqlite3"
    original = source.read_bytes()
    rules = RESOURCES / "rules"
    investigation = InvestigationService(id_factory=sequential_ids()).investigate(
        source, run.run_id, rules, root / "investigations"
    )
    replay = ReplayService(id_factory=sequential_ids()).replay(
        source, run.run_id, rules, root / "replays"
    )
    comparison = runner.compare(DIRECT_PROMPT_SCENARIO_ID, root / "comparisons")
    evaluation = EvaluationService(id_factory=sequential_ids()).evaluate(
        "direct-injection-v1", 1, root / "evaluations"
    )
    loaded_rules = load_rules(rules)
    fixtures = load_rule_fixtures(RESOURCES / "rule_fixtures")
    rule_test = run_rule_tests(loaded_rules, fixtures)
    assert rule_test.status == evaluation.report.status == "passed"
    assert source.read_bytes() == original
    return {
        ArtifactKind.RUN_REPORT: run.report,
        ArtifactKind.COMPARISON: comparison.report,
        ArtifactKind.REPLAY: replay.report,
        ArtifactKind.INVESTIGATION: investigation.report,
        ArtifactKind.EVALUATION: evaluation.report,
        ArtifactKind.RULE: loaded_rules[0],
        ArtifactKind.RULE_TEST: rule_test,
    }


def contaminated_value(model: BaseModel, kind: ArtifactKind) -> dict[str, Any]:
    value: dict[str, Any] = model.model_dump(mode="json")
    canary = load_canary()
    if kind is ArtifactKind.RUN_REPORT:
        value["executive_summary"] = canary
    elif kind is ArtifactKind.COMPARISON:
        value["divergence"] = canary
    elif kind in {ArtifactKind.REPLAY, ArtifactKind.INVESTIGATION}:
        value["source_file"] = canary
    elif kind is ArtifactKind.EVALUATION:
        value["safety_and_limitations"][0] = canary
    elif kind is ArtifactKind.RULE:
        value["description"] = canary
    else:
        assert kind is ArtifactKind.RULE_TEST
        value["results"][0]["fixture"] = canary
    # Prove rejection cannot be satisfied by an unrelated schema/summary failure.
    type(model).model_validate_json(json.dumps(value))
    return value


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("encoding", ["literal", "unicode_escaped"])
def test_public_catalog_and_cli_reject_decoded_canary_in_every_json_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    genuine_artifacts: dict[ArtifactKind, BaseModel],
    kind: ArtifactKind,
    encoding: str,
) -> None:
    model = genuine_artifacts[kind]
    artifact = tmp_path / "artifact.json"
    artifact.write_text(model.model_dump_json(), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "entries": [{"id": "artifact", "kind": kind.value, "path": artifact.name}],
            }
        ),
        encoding="utf-8",
    )
    original_manifest = manifest.read_bytes()
    original_artifact = artifact.read_bytes()
    valid = DashboardCatalog.load(manifest).get("artifact")
    assert valid is not None and valid.summary.provenance is Provenance.REPORT_ONLY
    assert artifact.read_bytes() == original_artifact
    canary = load_canary()
    encoded = json.dumps(contaminated_value(model, kind), ensure_ascii=False)
    if encoding == "unicode_escaped":
        escaped = "".join(f"\\u{ord(character):04x}" for character in canary)
        encoded = encoded.replace(canary, escaped)
        assert canary not in encoded and escaped in encoded
    assert canary in json.dumps(json.loads(encoded), ensure_ascii=False)
    type(model).model_validate_json(encoded)
    artifact.write_text(encoded, encoding="utf-8")
    contaminated_bytes = artifact.read_bytes()
    with pytest.raises(DashboardInputError, match="raw lab canary") as rejected:
        DashboardCatalog.load(manifest)

    # If a regression reaches listener startup, fail safely without opening a socket.
    listeners: list[bool] = []
    monkeypatch.setattr("uvicorn.run", lambda *_args, **_kwargs: listeners.append(True))
    assert main(["dashboard", "--manifest", str(manifest)]) == 2
    assert listeners == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: invalid input (DashboardInputError)\n"
    output = captured.out + captured.err + caplog.text + str(rejected.value)
    for forbidden in (canary, load_prompt(PromptFixture.MALICIOUS)):
        assert forbidden not in output
    assert manifest.read_bytes() == original_manifest
    assert artifact.read_bytes() == contaminated_bytes
    assert set(tmp_path.iterdir()) == {manifest, artifact}


def artifact_catalog(kind: ArtifactKind, value: dict[str, Any]) -> DashboardCatalog:
    return DashboardCatalog(
        (
            CatalogRecord(
                CatalogSummary(
                    id="artifact",
                    kind=kind,
                    provenance=Provenance.REPORT_ONLY,
                    title="Synthetic artifact",
                    status="available",
                ),
                value,
            ),
        )
    )


@pytest.mark.parametrize("kind", tuple(COLLECTIONS))
def test_api_rejects_unsafe_in_memory_artifacts_with_fixed_response(
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    genuine_artifacts: dict[ArtifactKind, BaseModel],
    kind: ArtifactKind,
) -> None:
    model = genuine_artifacts[kind]
    with TestClient(
        create_dashboard_app(artifact_catalog(kind, model.model_dump(mode="json"))),
        base_url="http://127.0.0.1:8765",
    ) as client:
        positive = client.get(f"/api/v1/{COLLECTIONS[kind]}/artifact")
    assert positive.status_code == 200
    assert positive.json()["summary"]["kind"] == kind.value
    value = contaminated_value(genuine_artifacts[kind], kind)
    before = json.dumps(value, sort_keys=True)
    # TestClient is in-process; this does not start the optional HTTP listener.
    with TestClient(
        create_dashboard_app(artifact_catalog(kind, value)), base_url="http://127.0.0.1:8765"
    ) as client:
        response = client.get(f"/api/v1/{COLLECTIONS[kind]}/artifact")
    assert response.status_code == 503
    assert response.json() == {"error": {"code": "unsafe_projection_rejected"}}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    captured = capsys.readouterr()
    output = response.text + captured.out + captured.err + caplog.text
    for forbidden in (load_canary(), load_prompt(PromptFixture.MALICIOUS)):
        assert forbidden not in output
    assert json.dumps(value, sort_keys=True) == before


def test_replay_detail_route_is_unavailable_without_exposing_artifact(
    genuine_artifacts: dict[ArtifactKind, BaseModel],
) -> None:
    # Route-contract evidence only: 404 is not evidence of an API redaction scan.
    kind = ArtifactKind.REPLAY
    value = contaminated_value(genuine_artifacts[kind], kind)
    with TestClient(
        create_dashboard_app(artifact_catalog(kind, value)), base_url="http://127.0.0.1:8765"
    ) as client:
        response = client.get("/api/v1/replays/artifact")
    assert response.status_code == 404
    assert response.json() == {"error": {"code": "not_found"}}
    assert load_canary() not in response.text
