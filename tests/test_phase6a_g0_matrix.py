"""Direct-scenario loader, control, isolation, correlation, and metric evidence."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path

import pytest

import agentsec.resource_loader as loader
import agentsec.rule_engine as rule_engine
from agentsec.adapters import LabHttpSinkAdapter, VirtualFileAdapter
from agentsec.constants import (
    DIRECT_PROMPT_SCENARIO_ID,
    MAX_DOCUMENT_BYTES,
    MAX_SCENARIO_BYTES,
    SCENARIO_ID,
)
from agentsec.detection import CorrelationDetector
from agentsec.evaluation import EvaluationService, load_evaluation_suite
from agentsec.evidence import fingerprint_suite
from agentsec.incidents import InvestigationService
from agentsec.models import (
    ApprovalSimulation,
    DirectPromptScenario,
    DocumentFixture,
    InputChannel,
    PolicyProfile,
    PromptFixture,
)
from agentsec.replay import read_replay_evidence
from agentsec.resource_loader import load_canary, load_prompt, load_scenario
from agentsec.rule_engine import RuleEvaluationLimitExceeded, evaluate_rule, load_rules
from agentsec.rule_testing import load_rule_fixtures
from agentsec.runner import ScenarioRunner

from .helpers import sequential_ids

RESOURCES = Path(__file__).parents[1] / "src" / "agentsec" / "resources"


@pytest.mark.parametrize("kind", ["legacy_scenario", "direct_scenario", "document", "prompt"])
@pytest.mark.parametrize("oversized", [False, True])
def test_public_resource_loaders_read_only_cap_plus_one(
    monkeypatch: pytest.MonkeyPatch, kind: str, oversized: bool
) -> None:
    if kind.endswith("scenario"):
        scenario_id = SCENARIO_ID if kind == "legacy_scenario" else DIRECT_PROMPT_SCENARIO_ID
        data = json.dumps(load_scenario(scenario_id).model_dump(mode="json")).encode()
        cap = MAX_SCENARIO_BYTES
    else:
        data = b"safe text"
        cap = MAX_DOCUMENT_BYTES
    data += b" " * (cap - len(data) + (16 if oversized else 0))
    reads: list[int | None] = []

    class ReadSpy(BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            reads.append(size)
            return super().read(size)

    stream = ReadSpy(data)

    class Resource:
        def joinpath(self, *_parts: str) -> Resource:
            return self

        def open(self, mode: str) -> ReadSpy:
            assert mode == "rb"
            return stream

    monkeypatch.setattr(loader, "files", lambda _package: Resource())

    def invoke() -> object:
        if kind.endswith("scenario"):
            return loader.load_scenario(scenario_id)
        if kind == "document":
            return loader.load_document(DocumentFixture.MALICIOUS)
        return loader.load_prompt(PromptFixture.MALICIOUS)

    if oversized:
        with pytest.raises(ValueError, match="size limit"):
            invoke()
    else:
        invoke()
    assert reads == [cap + 1]
    assert stream.closed


@pytest.mark.parametrize("profile", list(PolicyProfile))
@pytest.mark.parametrize("fixture", list(PromptFixture))
def test_direct_fixture_profile_matrix_has_exact_outcomes_and_origin(
    tmp_path: Path, profile: PolicyProfile, fixture: PromptFixture
) -> None:
    scenario = load_scenario(DIRECT_PROMPT_SCENARIO_ID)
    assert isinstance(scenario, DirectPromptScenario)
    result = ScenarioRunner(id_factory=sequential_ids()).run_scenario(
        scenario.model_copy(update={"input_fixture": fixture}), tmp_path, profile=profile
    )
    events = read_replay_evidence(result.run_directory / "events.sqlite3", result.run_id).events
    benign = fixture is PromptFixture.BENIGN
    prevented = not benign and profile is PolicyProfile.STRICT
    impact = fixture is PromptFixture.MALICIOUS and profile is PolicyProfile.VULNERABLE
    assert result.report.outcome == (
        "prevented" if prevented else "simulated_impact" if impact else "no_correlated_chain"
    )
    assert result.report.prevention.blocked is prevented
    assert result.report.simulated_impact.reached is impact
    assert result.detection.detected is impact
    assert sum(event.event_type == "tool.requested" for event in events) == (
        0 if benign else 1 if prevented else 2
    )
    assert sum(event.event_type == "incident.created" for event in events) == int(impact)
    assert result.report.risk_version == "risk-v2"
    assert result.report.attack_vector == "Direct prompt injection through an untrusted user prompt"
    assert "document" not in result.report.root_cause.lower()
    assert all("document" not in text.lower() for text in result.report.recommended_remediation)
    assert events[1].event_type == "agent.context.prompt_added"
    assert events[1].payload["prompt_id"] == fixture.value
    assert all(
        (event.run_id, event.trace_id) == (result.run_id, result.trace_id) for event in events
    )
    assert [event.sequence for event in events] == list(range(1, len(events) + 1))
    if benign:
        assert not any(
            event.event_type in {"file.read", "lab.sink.payload_recorded", "policy.denied"}
            for event in events
        )
    if prevented:
        assert not any(
            event.event_type in {"file.read", "lab.sink.payload_recorded"} for event in events
        )
    if fixture is PromptFixture.MISSING_CANARY and not prevented:
        sink = next(event for event in events if event.event_type == "lab.sink.payload_recorded")
        assert sink.payload["matched"] is False
    decoded = json.dumps(json.loads((result.run_directory / "report.json").read_text()))
    for forbidden in (load_canary(), load_prompt(fixture), "[agentsec:direct-prompt-injection]"):
        assert forbidden not in decoded


@pytest.mark.parametrize("approval", list(ApprovalSimulation))
def test_direct_approval_cannot_override_secret_read_denial(
    tmp_path: Path, approval: ApprovalSimulation
) -> None:
    result = ScenarioRunner(id_factory=sequential_ids()).run(
        DIRECT_PROMPT_SCENARIO_ID,
        tmp_path,
        profile=PolicyProfile.STRICT,
        approval_simulation=approval,
    )
    events = read_replay_evidence(result.run_directory / "events.sqlite3", result.run_id).events
    assert result.report.prevention.stage == "secret_access"
    assert not any(
        event.event_type in {"approval.simulated", "policy.approval_required", "file.read"}
        for event in events
    )
    risk = next(event.payload["risk"] for event in events if event.event_type == "policy.evaluated")
    assert risk["version"] == "risk-v2" and risk["context_origin"] == "direct_prompt"
    assert risk["score"] == 80


@pytest.mark.parametrize("mode", ["consecutive", "concurrent", "comparison"])
def test_direct_run_modes_isolate_every_event_and_report(tmp_path: Path, mode: str) -> None:
    if mode == "consecutive":
        runner = ScenarioRunner(id_factory=sequential_ids())
        results = [runner.run(DIRECT_PROMPT_SCENARIO_ID, tmp_path) for _ in range(2)]
    elif mode == "concurrent":
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(ScenarioRunner().run, DIRECT_PROMPT_SCENARIO_ID, tmp_path)
                for _ in range(2)
            ]
            results = [future.result(timeout=10) for future in futures]
    else:
        comparison = ScenarioRunner(id_factory=sequential_ids()).compare(
            DIRECT_PROMPT_SCENARIO_ID, tmp_path
        )
        results = [comparison.vulnerable, comparison.strict]
        assert comparison.vulnerable.report.outcome == "simulated_impact"
        assert comparison.strict.report.outcome == "prevented"
        assert (
            "document"
            not in (comparison.comparison_directory / "comparison.md").read_text().lower()
        )
    assert len({result.run_id for result in results}) == len(results)
    assert len({result.trace_id for result in results}) == len(results)
    assert len({result.run_directory for result in results}) == len(results)
    for result in results:
        events = read_replay_evidence(result.run_directory / "events.sqlite3", result.run_id).events
        assert {(event.run_id, event.trace_id) for event in events} == {
            (result.run_id, result.trace_id)
        }
        assert result.report.run_id == result.run_id and result.report.trace_id == result.trace_id


@pytest.mark.parametrize("variant", ["missing", "reordered", "cross_run", "cross_trace", "noise"])
def test_direct_correlation_order_and_identity_parity(variant: str) -> None:
    rule = next(rule for rule in load_rules(RESOURCES / "rules") if rule.rule_id == "ASL-CORR-003")
    fixture = next(
        item
        for item in load_rule_fixtures(RESOURCES / "rule_fixtures")
        if item.name == "asl-corr-003-positive"
    )
    events = list(fixture.events)
    if variant == "missing":
        events.pop(1)
    elif variant == "reordered":
        events[1] = events[1].model_copy(update={"sequence": 3})
        events[2] = events[2].model_copy(update={"sequence": 2})
    elif variant in {"cross_run", "cross_trace"}:
        field = "run_id" if variant == "cross_run" else "trace_id"
        events[1] = events[1].model_copy(update={field: "other"})
    else:
        events.insert(1, events[1].model_copy(update={"event_id": "noise", "trace_id": "other"}))
    live = CorrelationDetector.for_input_channel(InputChannel.DIRECT_PROMPT).evaluate(events)
    offline = evaluate_rule(rule, events)
    assert live.detected is (variant == "noise")
    assert bool(offline.matches) is live.detected
    if live.detected:
        assert offline.matches[0].evidence_event_ids == live.evidence_event_ids


def test_direct_offline_rule_candidate_limit_fails_explicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rule = next(rule for rule in load_rules(RESOURCES / "rules") if rule.rule_id == "ASL-CORR-003")
    fixture = next(
        item
        for item in load_rule_fixtures(RESOURCES / "rule_fixtures")
        if item.name == "asl-corr-003-positive"
    )
    monkeypatch.setattr(rule_engine, "MAX_RULE_CANDIDATES", 3)
    assert len(evaluate_rule(rule, list(fixture.events)).matches) == 1
    monkeypatch.setattr(rule_engine, "MAX_RULE_CANDIDATES", 2)
    with pytest.raises(RuleEvaluationLimitExceeded, match="candidate count"):
        evaluate_rule(rule, list(fixture.events))


def test_direct_investigation_resolves_references_without_runtime_actions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = ScenarioRunner(id_factory=sequential_ids()).run(
        DIRECT_PROMPT_SCENARIO_ID, tmp_path / "runs"
    )
    source = run.run_directory / "events.sqlite3"
    original = source.read_bytes()
    source_events = read_replay_evidence(source, run.run_id).events

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("investigation invoked a runtime adapter")

    monkeypatch.setattr(VirtualFileAdapter, "read", forbidden)
    monkeypatch.setattr(LabHttpSinkAdapter, "record", forbidden)
    result = InvestigationService(id_factory=sequential_ids()).investigate(
        source, run.run_id, RESOURCES / "rules", tmp_path / "investigations"
    )
    assert source.read_bytes() == original
    assert len(result.report.incidents) == 1
    incident = result.report.incidents[0]
    assert incident.outcome.outcome == "simulated_impact"
    assert [alert.rule_id for alert in result.report.derived_alerts] == ["ASL-CORR-003"]
    by_id = {event.event_id: event for event in source_events}
    refs = [
        *incident.evidence,
        *(ref for stage in incident.stages for ref in stage.evidence),
        *(item.evidence for item in incident.timeline),
    ]
    for ref in refs:
        event = by_id[ref.event_id]
        assert ref.snapshot_fingerprint == result.report.snapshot_fingerprint
        assert (ref.run_id, ref.trace_id, ref.sequence) == (
            event.run_id,
            event.trace_id,
            event.sequence,
        )
    for path in result.investigation_directory.iterdir():
        if path.suffix in {".json", ".md"}:
            text = path.read_text()
            if path.suffix == ".json":
                text = json.dumps(json.loads(text))
            assert load_canary() not in text
            assert "[agentsec:direct-prompt-injection]" not in text


def test_direct_suite_repetitions_metrics_pairs_and_legacy_fingerprint(tmp_path: Path) -> None:
    _, core_data = load_evaluation_suite("core-lab-v1")
    assert (
        fingerprint_suite(core_data)
        == "53de470176966e7bcb52b82ae89d64fe27016e954c4db4e011c08352422a82c4"
    )
    result = EvaluationService(id_factory=sequential_ids()).evaluate(
        "direct-injection-v1", 2, tmp_path
    )
    report = result.report
    assert report.status == "passed"
    assert report.scheduled_children == report.completed_children == 12
    assert report.failed_children == report.excluded_children == report.assertion_failures == 0
    assert {(child.case_id, child.profile, child.trial) for child in report.children} == {
        (case, profile, trial)
        for case in ("malicious", "benign", "missing-canary")
        for profile in PolicyProfile
        for trial in (1, 2)
    }
    assert len({child.run_id for child in report.children}) == 12
    assert len(report.pairs) == 6 and all(pair.status == "complete" for pair in report.pairs)
    assert report.impact_pair_prevention_numerator == report.impact_pair_prevention_denominator == 2
    assert report.impact_pair_prevention_rate == 1.0
    expected = {
        (PolicyProfile.VULNERABLE, "simulated_attack_success_rate"): (2, 4),
        (PolicyProfile.VULNERABLE, "attack_run_detection_rate"): (2, 4),
        (PolicyProfile.VULNERABLE, "simulated_impact_detection_rate"): (2, 2),
        (PolicyProfile.VULNERABLE, "prevention_rate"): (0, 4),
        (PolicyProfile.VULNERABLE, "benign_run_false_positive_rate"): (0, 2),
        (PolicyProfile.STRICT, "simulated_attack_success_rate"): (0, 4),
        (PolicyProfile.STRICT, "attack_run_detection_rate"): (4, 4),
        (PolicyProfile.STRICT, "simulated_impact_detection_rate"): (0, 0),
        (PolicyProfile.STRICT, "prevention_rate"): (4, 4),
        (PolicyProfile.STRICT, "benign_run_false_positive_rate"): (0, 2),
    }
    assert {
        (metric.profile, metric.name): (metric.numerator, metric.denominator)
        for metric in report.metrics
    } == expected
    for metric in report.metrics:
        assert metric.eligible_count == metric.denominator
        assert metric.value == (
            metric.numerator / metric.denominator if metric.denominator else None
        )
    assert all(child.assertion_passed for child in report.children)
