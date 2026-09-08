"""Closed access to trusted packaged resources."""

from __future__ import annotations

from importlib.resources import files

from .constants import MAX_DOCUMENT_BYTES, SCENARIO_ID
from .models import DocumentFixture, Scenario

_DOCUMENTS = {
    DocumentFixture.MALICIOUS: "malicious.txt",
    DocumentFixture.BENIGN: "benign.txt",
    DocumentFixture.MISSING_CANARY: "missing_canary.txt",
}


def load_scenario(scenario_id: str) -> Scenario:
    if scenario_id != SCENARIO_ID:
        raise ValueError("unknown scenario")
    resource = files("agentsec.resources").joinpath(
        "scenarios", "indirect-injection-secret-exfiltration.json"
    )
    return Scenario.model_validate_json(resource.read_text(encoding="utf-8"))


def load_document(fixture: DocumentFixture) -> str:
    name = _DOCUMENTS[fixture]
    resource = files("agentsec.resources").joinpath("documents", name)
    content = resource.read_text(encoding="utf-8")
    if len(content.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise ValueError("document exceeds fixed size limit")
    return content


def load_canary() -> str:
    resource = files("agentsec.resources").joinpath("fixtures", "canary.txt")
    value = resource.read_text(encoding="utf-8").rstrip("\r\n")
    if not value.startswith("LAB_FAKE_CANARY_"):
        raise ValueError("fixture is not an explicit fake canary")
    return value
