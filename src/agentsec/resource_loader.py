"""Closed access to trusted packaged resources."""

from __future__ import annotations

import json
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Any

from .constants import (
    DIRECT_PROMPT_CORRELATION_RULE_ID,
    DIRECT_PROMPT_CORRELATION_RULE_VERSION,
    DIRECT_PROMPT_SCENARIO_ID,
    MAX_DOCUMENT_BYTES,
    MAX_RULE_BYTES,
    MAX_SCENARIO_BYTES,
    SCENARIO_ID,
)
from .models import (
    DirectPromptScenario,
    DocumentFixture,
    PromptFixture,
    Scenario,
    ScenarioDefinition,
)
from .rule_models import DetectionRule, RuleKind

_DOCUMENTS = {
    DocumentFixture.MALICIOUS: "malicious.txt",
    DocumentFixture.BENIGN: "benign.txt",
    DocumentFixture.MISSING_CANARY: "missing_canary.txt",
}
_PROMPTS = {
    PromptFixture.MALICIOUS: "malicious.txt",
    PromptFixture.BENIGN: "benign.txt",
    PromptFixture.MISSING_CANARY: "missing_canary.txt",
}


def _read_bounded_utf8(resource: Traversable, limit: int, kind: str) -> bytes:
    with resource.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{kind} exceeds fixed size limit")
    try:
        data.decode("utf-8")
    except UnicodeError as error:
        raise ValueError(f"{kind} is not valid UTF-8") from error
    return data


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("scenario JSON contains duplicate object keys")
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> object:
    raise ValueError("scenario JSON contains a non-finite number")


def load_scenario(scenario_id: str) -> ScenarioDefinition:
    model: type[Scenario] | type[DirectPromptScenario]
    if scenario_id == SCENARIO_ID:
        resource = files("agentsec.resources").joinpath(
            "scenarios", "indirect-injection-secret-exfiltration.json"
        )
        model = Scenario
    elif scenario_id == DIRECT_PROMPT_SCENARIO_ID:
        resource = files("agentsec.resources").joinpath(
            "scenarios", "direct-prompt-injection-secret-exfiltration.json"
        )
        model = DirectPromptScenario
    else:
        raise ValueError("unknown scenario")
    data = _read_bounded_utf8(resource, MAX_SCENARIO_BYTES, "scenario")
    try:
        json.loads(
            data,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except json.JSONDecodeError as error:
        raise ValueError("scenario is not valid JSON") from error
    scenario = model.model_validate_json(data)
    if scenario.id != scenario_id:
        raise ValueError("packaged scenario identity does not match request")
    return scenario


def load_document(fixture: DocumentFixture) -> str:
    name = _DOCUMENTS[fixture]
    resource = files("agentsec.resources").joinpath("documents", name)
    return _read_bounded_utf8(resource, MAX_DOCUMENT_BYTES, "document").decode("utf-8")


def load_prompt(fixture: PromptFixture) -> str:
    resource = files("agentsec.resources").joinpath("prompts", _PROMPTS[fixture])
    return _read_bounded_utf8(resource, MAX_DOCUMENT_BYTES, "prompt").decode("utf-8")


def load_canary() -> str:
    resource = files("agentsec.resources").joinpath("fixtures", "canary.txt")
    value = resource.read_text(encoding="utf-8").rstrip("\r\n")
    if not value.startswith("LAB_FAKE_CANARY_"):
        raise ValueError("fixture is not an explicit fake canary")
    return value


def load_direct_detection_rule() -> DetectionRule:
    """Load only the fixed packaged direct rule; never accept a path or selector."""
    resource = files("agentsec.resources").joinpath("rules", "asl-corr-003-v1.json")
    data = _read_bounded_utf8(resource, MAX_RULE_BYTES, "direct detection rule")
    try:
        decoded = json.loads(
            data,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
        if load_canary() in json.dumps(decoded, ensure_ascii=False):
            raise ValueError("direct detection rule contains the lab canary")
        rule = DetectionRule.model_validate_json(data)
    except ValueError as error:
        raise ValueError("direct detection rule failed validation") from error
    if (
        rule.rule_id,
        rule.rule_version,
        rule.kind,
        rule.severity,
        rule.supported_event_versions,
        tuple(step.name for step in rule.steps),
    ) != (
        DIRECT_PROMPT_CORRELATION_RULE_ID,
        DIRECT_PROMPT_CORRELATION_RULE_VERSION,
        RuleKind.CORRELATION,
        "critical",
        ("0.2",),
        ("prompt", "read", "sink"),
    ):
        raise ValueError("packaged direct detection rule does not match its contract")
    return rule
