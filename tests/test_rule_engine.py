from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.models import Event
from agentsec.rule_engine import (
    RuleEvaluationLimitExceeded,
    RuleInputError,
    RuleResourceLimitExceeded,
    evaluate_rule,
    load_rules,
    validate_rule_json,
)
from agentsec.rule_models import DetectionRule, ReplayReport, RuleTestReport
from agentsec.rule_testing import load_rule_fixtures, run_rule_tests

RESOURCE_ROOT = Path(__file__).parents[1] / "src" / "agentsec" / "resources"
RULES = RESOURCE_ROOT / "rules"
FIXTURES = RESOURCE_ROOT / "rule_fixtures"
CONTRACTS = Path(__file__).parents[1] / "examples" / "contracts"


def event(
    event_id: str,
    sequence: int,
    event_type: str,
    payload: dict[str, object],
    *,
    run_id: str = "run_1",
    trace_id: str = "trace_1",
    schema_version: str = "0.2",
) -> Event:
    return Event.model_validate(
        {
            "schema_version": schema_version,
            "event_id": event_id,
            "run_id": run_id,
            "trace_id": trace_id,
            "sequence": sequence,
            "timestamp": "2026-09-09T00:00:00Z",
            "event_type": event_type,
            "source_component": "fixture",
            "payload": payload,
        }
    )


def rule_json(
    *,
    rule_id: str = "TEST-EVENT-001",
    kind: str = "single_event",
    steps: list[dict[str, object]] | None = None,
    joins: list[dict[str, str]] | None = None,
) -> str:
    return json.dumps(
        {
            "schema_version": "1.0",
            "rule_id": rule_id,
            "rule_version": 1,
            "description": "Test rule",
            "severity": "medium",
            "supported_event_versions": ["0.1", "0.2"],
            "kind": kind,
            "steps": steps
            or [
                {
                    "name": "match",
                    "predicates": [
                        {
                            "field": "event_type",
                            "operator": "equals",
                            "value": "test.match",
                        }
                    ],
                }
            ],
            **({"joins": joins} if joins is not None else {}),
        }
    )


def test_packaged_rules_have_positive_and_negative_exact_fixtures() -> None:
    rules = load_rules(RULES)
    fixtures = load_rule_fixtures(FIXTURES)

    report = run_rule_tests(rules, fixtures)

    assert [rule.rule_id for rule in rules] == [
        "ASL-CORR-002",
        "ASL-EVENT-001",
        "ASL-SEQ-001",
    ]
    assert report.status == "passed"
    assert report.covered_rules == report.total_rules == 3
    assert report.assertions_passed == report.assertions_total == 6


@pytest.mark.parametrize(
    "mutation",
    [
        {"unknown": True},
        {"kind": "threshold"},
        {"supported_event_versions": ["9.9"]},
        {
            "steps": [
                {
                    "name": "match",
                    "predicates": [{"field": "payload", "operator": "ignored"}],
                }
            ]
        },
    ],
)
def test_rule_schema_rejects_unknown_fields_kinds_versions_and_predicates(
    mutation: dict[str, object],
) -> None:
    data = json.loads(rule_json())
    data.update(mutation)

    with pytest.raises(RuleInputError, match="schema"):
        validate_rule_json(json.dumps(data))


def test_rule_schema_rejects_invalid_correlation_joins() -> None:
    steps: list[dict[str, object]] = [
        {
            "name": "first",
            "predicates": [{"field": "event_type", "operator": "equals", "value": "first"}],
        },
        {
            "name": "second",
            "predicates": [{"field": "event_type", "operator": "equals", "value": "second"}],
        },
    ]
    backward_join: list[dict[str, str]] = [
        {
            "left_step": "second",
            "left_field": "payload.canary_id",
            "right_step": "first",
            "right_field": "payload.canary_id",
        }
    ]

    with pytest.raises(RuleInputError, match="schema"):
        validate_rule_json(rule_json(kind="correlation", steps=steps, joins=backward_join))


def test_predicates_use_strict_scalar_types_and_membership() -> None:
    steps: list[dict[str, object]] = [
        {
            "name": "match",
            "predicates": [
                {
                    "field": "payload.matched",
                    "operator": "in",
                    "values": [True],
                }
            ],
        }
    ]
    rule = validate_rule_json(rule_json(steps=steps))

    evaluation = evaluate_rule(
        rule,
        [
            event("evt_bool", 1, "test", {"matched": True}),
            event("evt_int", 2, "test", {"matched": 1}),
            event("evt_missing", 3, "test", {}),
        ],
    )

    assert [match.evidence_event_ids for match in evaluation.matches] == [("evt_bool",)]


def test_sequence_and_correlation_are_deterministic_and_trace_isolated() -> None:
    rule = next(rule for rule in load_rules(RULES) if rule.rule_id == "ASL-CORR-002")
    first_trace = [
        event("doc_1", 1, "agent.context.document_added", {"trust": "untrusted"}),
        event(
            "read_1",
            2,
            "file.read",
            {
                "classification": "secret",
                "canary_id": "canary_48f1",
                "value_sha256": "digest_1",
            },
        ),
        event(
            "sink_1",
            3,
            "lab.sink.payload_recorded",
            {
                "canary_id": "canary_48f1",
                "value_sha256": "digest_1",
                "matched": True,
                "redacted": True,
            },
        ),
    ]
    other_trace = [
        item.model_copy(
            update={
                "event_id": f"{item.event_id}_other",
                "trace_id": "trace_2",
            }
        )
        for item in first_trace
    ]

    forward = evaluate_rule(rule, [*first_trace, *other_trace])
    reversed_input = evaluate_rule(rule, list(reversed([*first_trace, *other_trace])))

    assert forward.matches == reversed_input.matches
    assert len(forward.matches) == 2
    assert {match.trace_id for match in forward.matches} == {"trace_1", "trace_2"}
    assert all(len(match.evidence_event_ids) == 3 for match in forward.matches)


def test_correlation_never_combines_evidence_across_runs() -> None:
    rule = next(rule for rule in load_rules(RULES) if rule.rule_id == "ASL-CORR-002")
    split_chain = [
        event("doc", 1, "agent.context.document_added", {"trust": "untrusted"}),
        event(
            "read",
            2,
            "file.read",
            {
                "classification": "secret",
                "canary_id": "canary_48f1",
                "value_sha256": "digest_1",
            },
            run_id="run_2",
        ),
        event(
            "sink",
            3,
            "lab.sink.payload_recorded",
            {
                "canary_id": "canary_48f1",
                "value_sha256": "digest_1",
                "matched": True,
                "redacted": True,
            },
            run_id="run_2",
        ),
    ]

    assert evaluate_rule(rule, split_chain).matches == ()


def test_repeated_events_enumerate_distinct_matches_and_deduplicate_identity() -> None:
    rule = next(rule for rule in load_rules(RULES) if rule.rule_id == "ASL-CORR-002")
    evidence = [
        event("doc", 1, "agent.context.document_added", {"trust": "untrusted"}),
        event(
            "read_1",
            2,
            "file.read",
            {
                "classification": "secret",
                "canary_id": "canary_48f1",
                "value_sha256": "digest_1",
            },
        ),
        event(
            "sink_1",
            3,
            "lab.sink.payload_recorded",
            {
                "canary_id": "canary_48f1",
                "value_sha256": "digest_1",
                "matched": True,
                "redacted": True,
            },
        ),
        event(
            "read_2",
            4,
            "file.read",
            {
                "classification": "secret",
                "canary_id": "canary_48f1",
                "value_sha256": "digest_2",
            },
        ),
        event(
            "sink_2",
            5,
            "lab.sink.payload_recorded",
            {
                "canary_id": "canary_48f1",
                "value_sha256": "digest_2",
                "matched": True,
                "redacted": True,
            },
        ),
    ]

    distinct = evaluate_rule(rule, evidence)
    duplicated_input = evaluate_rule(rule, [*evidence, evidence[-1]])

    assert [match.evidence_event_ids for match in distinct.matches] == [
        ("doc", "read_1", "sink_1"),
        ("doc", "read_2", "sink_2"),
    ]
    assert duplicated_input.matches == distinct.matches
    assert duplicated_input.duplicate_matches_removed == 1


def test_legacy_event_version_is_supported_by_declared_rule() -> None:
    rule = next(rule for rule in load_rules(RULES) if rule.rule_id == "ASL-SEQ-001")
    events = [
        event(
            "doc",
            1,
            "agent.context.document_added",
            {"trust": "untrusted"},
            schema_version="0.1",
        ),
        event(
            "request",
            2,
            "tool.requested",
            {"tool": "read_file"},
            schema_version="0.1",
        ),
    ]

    assert evaluate_rule(rule, events).matches[0].evidence_event_ids == (
        "doc",
        "request",
    )


def test_candidate_limit_fails_instead_of_returning_partial_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agentsec.rule_engine as engine

    rule = validate_rule_json(rule_json())
    monkeypatch.setattr(engine, "MAX_RULE_CANDIDATES", 1)

    with pytest.raises(RuleEvaluationLimitExceeded, match="candidate"):
        evaluate_rule(
            rule,
            [
                event("evt_1", 1, "test.match", {}),
                event("evt_2", 2, "test.match", {}),
            ],
        )


def test_rule_loader_rejects_duplicate_and_oversized_files(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate"
    duplicate.mkdir()
    (duplicate / "one.json").write_text(rule_json(), encoding="utf-8")
    (duplicate / "two.json").write_text(rule_json(), encoding="utf-8")
    with pytest.raises(RuleInputError, match="duplicate"):
        load_rules(duplicate)

    oversized = tmp_path / "oversized"
    oversized.mkdir()
    (oversized / "large.json").write_bytes(b"x" * (64 * 1024 + 1))
    with pytest.raises(RuleResourceLimitExceeded, match="limit"):
        load_rules(oversized)


def test_generalized_rule_has_distinct_identity_from_legacy_detector() -> None:
    correlation = next(rule for rule in load_rules(RULES) if rule.rule_id == "ASL-CORR-002")

    assert (correlation.rule_id, correlation.rule_version) != ("ASL-CORR-001", 1)
    assert isinstance(correlation, DetectionRule)


def test_phase_3_contract_examples_match_the_executable_schema() -> None:
    valid_rule = validate_rule_json((CONTRACTS / "rule-v1-valid.json").read_text(encoding="utf-8"))
    replay = ReplayReport.model_validate_json(
        (CONTRACTS / "replay-report-v1.json").read_text(encoding="utf-8")
    )

    assert valid_rule.rule_id == "ASL-EVENT-001"
    assert replay.source_run_id == "run_demo"
    with pytest.raises(RuleInputError, match="schema"):
        validate_rule_json(
            (CONTRACTS / "rule-v1-invalid-executable.json").read_text(encoding="utf-8")
        )


def test_report_models_reject_inconsistent_summary_fields() -> None:
    fixture_report = run_rule_tests(load_rules(RULES), load_rule_fixtures(FIXTURES))
    fixture_data = fixture_report.model_dump(mode="json")
    fixture_data["assertions_passed"] = 0
    with pytest.raises(ValidationError, match="assertion summary"):
        RuleTestReport.model_validate_json(json.dumps(fixture_data))

    replay_data = json.loads((CONTRACTS / "replay-report-v1.json").read_text(encoding="utf-8"))
    replay_data["total_matches"] = 0
    with pytest.raises(ValidationError, match="match total"):
        ReplayReport.model_validate_json(json.dumps(replay_data))
