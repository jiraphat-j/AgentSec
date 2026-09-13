"""Bounded declarative detection-rule loading and evaluation."""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
from pathlib import Path
from typing import Final, cast

from pydantic import ValidationError

from .constants import (
    MAX_RULE_BYTES,
    MAX_RULE_CANDIDATES,
    MAX_RULE_MATCHES,
    MAX_RULES,
)
from .models import Event
from .resource_loader import load_canary
from .rule_models import (
    DetectionMatch,
    DetectionRule,
    PredicateOperator,
    RuleEvaluation,
    RuleField,
    RulePredicate,
    RuleScalar,
)

_MISSING: Final = object()


class RuleInputError(ValueError):
    """Raised when rule data is missing, unsafe, or invalid."""


class RuleEvaluationLimitExceeded(RuntimeError):
    """Raised when bounded candidate or match state is exhausted."""


class RuleResourceLimitExceeded(RuntimeError):
    """Raised when bounded rule or fixture inputs exceed fixed resource limits."""


def load_rules(directory: Path) -> tuple[DetectionRule, ...]:
    if not directory.is_dir():
        raise RuleInputError("rule directory does not exist")
    paths = sorted(path for path in directory.iterdir() if path.suffix.lower() == ".json")
    if not paths:
        raise RuleInputError("rule directory contains no JSON rules")
    if len(paths) > MAX_RULES:
        raise RuleResourceLimitExceeded("rule count exceeds fixed limit")
    rules: list[DetectionRule] = []
    identities: set[tuple[str, int]] = set()
    raw_canary = load_canary()
    for path in paths:
        if not path.is_file() or path.stat().st_size > MAX_RULE_BYTES:
            raise RuleResourceLimitExceeded("rule file exceeds fixed limit")
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise RuleInputError("unable to read rule file") from error
        if raw_canary in text:
            raise RuleInputError("raw lab canary is forbidden in rule data")
        try:
            rule = DetectionRule.model_validate_json(text)
        except ValidationError as error:
            raise RuleInputError("rule file failed schema validation") from error
        identity = (rule.rule_id, rule.rule_version)
        if identity in identities:
            raise RuleInputError("duplicate rule identity")
        identities.add(identity)
        rules.append(rule)
    return tuple(sorted(rules, key=lambda item: (item.rule_id, item.rule_version)))


def _field_value(event: Event, field: RuleField) -> RuleScalar | object:
    if field == "schema_version":
        return event.schema_version
    if field == "event_type":
        return event.event_type
    if field == "source_component":
        return event.source_component
    if field == "tool_call_id":
        return event.tool_call_id if event.tool_call_id is not None else _MISSING
    payload_key = field.removeprefix("payload.")
    value: object = event.payload.get(payload_key, _MISSING)
    if value is _MISSING or type(value) not in {str, bool, int}:
        return _MISSING
    return cast(RuleScalar, value)


def _strict_equal(left: object, right: object) -> bool:
    return type(left) is type(right) and left == right


def _predicate_matches(event: Event, predicate: RulePredicate) -> bool:
    actual = _field_value(event, predicate.field)
    if actual is _MISSING:
        return False
    if predicate.operator is PredicateOperator.EQUALS:
        return _strict_equal(actual, predicate.value)
    return any(_strict_equal(actual, expected) for expected in predicate.values)


def _step_matches(event: Event, rule: DetectionRule, step_index: int) -> bool:
    return event.schema_version in rule.supported_event_versions and all(
        _predicate_matches(event, predicate) for predicate in rule.steps[step_index].predicates
    )


def _joins_match(rule: DetectionRule, selected: tuple[Event, ...]) -> bool:
    positions = {step.name: index for index, step in enumerate(rule.steps)}
    return all(
        (
            (left := _field_value(selected[positions[join.left_step]], join.left_field))
            is not _MISSING
            and (right := _field_value(selected[positions[join.right_step]], join.right_field))
            is not _MISSING
            and _strict_equal(left, right)
        )
        for join in rule.joins
    )


def _length_prefixed(parts: tuple[str, ...]) -> str:
    return "".join(f"{len(part)}:{part}" for part in parts)


def _match(rule: DetectionRule, selected: tuple[Event, ...]) -> DetectionMatch:
    first = selected[0]
    evidence = tuple(event.event_id for event in selected)
    dedup_key = _length_prefixed(
        (rule.rule_id, str(rule.rule_version), first.run_id, first.trace_id, *evidence)
    )
    return DetectionMatch(
        dedup_key=dedup_key,
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        run_id=first.run_id,
        trace_id=first.trace_id,
        evidence_event_ids=evidence,
        severity=rule.severity,
        description=rule.description,
    )


def evaluate_rule(rule: DetectionRule, events: list[Event]) -> RuleEvaluation:
    grouped: defaultdict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        grouped[(event.run_id, event.trace_id)].append(event)
    candidates = 0
    raw_matches: list[DetectionMatch] = []

    for identity in sorted(grouped):
        ordered = tuple(sorted(grouped[identity], key=lambda item: (item.sequence, item.event_id)))
        step_candidates = tuple(
            tuple(event for event in ordered if _step_matches(event, rule, step_index))
            for step_index in range(len(rule.steps))
        )
        step_sequences = tuple(
            tuple(event.sequence for event in candidates_at_step)
            for candidates_at_step in step_candidates
        )

        def walk(
            step_index: int,
            last_sequence: int,
            selected: tuple[Event, ...],
            candidates_by_step: tuple[tuple[Event, ...], ...] = step_candidates,
            sequences_by_step: tuple[tuple[int, ...], ...] = step_sequences,
        ) -> None:
            nonlocal candidates
            start = bisect_right(sequences_by_step[step_index], last_sequence)
            for event in candidates_by_step[step_index][start:]:
                candidates += 1
                if candidates > MAX_RULE_CANDIDATES:
                    raise RuleEvaluationLimitExceeded("rule candidate count exceeds fixed limit")
                next_selected = (*selected, event)
                if step_index + 1 < len(rule.steps):
                    walk(step_index + 1, event.sequence, next_selected)
                    continue
                if _joins_match(rule, next_selected):
                    raw_matches.append(_match(rule, next_selected))
                    if len(raw_matches) > MAX_RULE_MATCHES:
                        raise RuleEvaluationLimitExceeded("rule match count exceeds fixed limit")

        walk(0, 0, ())

    unique = {match.dedup_key: match for match in raw_matches}
    matches = tuple(unique[key] for key in sorted(unique))
    return RuleEvaluation(
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        candidate_count=candidates,
        duplicate_matches_removed=len(raw_matches) - len(matches),
        matches=matches,
    )


def evaluate_rules(
    rules: tuple[DetectionRule, ...], events: list[Event]
) -> tuple[RuleEvaluation, ...]:
    identities = [(rule.rule_id, rule.rule_version) for rule in rules]
    if len(identities) != len(set(identities)):
        raise RuleInputError("duplicate rule identity")
    return tuple(
        evaluate_rule(rule, events)
        for rule in sorted(rules, key=lambda item: (item.rule_id, item.rule_version))
    )


def validate_rule_json(raw: str) -> DetectionRule:
    """Validate one JSON rule without reading a path; used by contract tests."""
    try:
        return DetectionRule.model_validate_json(raw)
    except ValidationError as error:
        raise RuleInputError("rule failed schema validation") from error
