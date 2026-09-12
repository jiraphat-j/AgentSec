"""Deterministic positive and negative fixture harness for declarative rules."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from .constants import MAX_RULE_BYTES, MAX_RULES
from .resource_loader import load_canary
from .rule_engine import RuleInputError, RuleResourceLimitExceeded, evaluate_rule, load_rules
from .rule_models import (
    DetectionRule,
    RuleFixtureResult,
    RuleTestFixture,
    RuleTestReport,
)


@dataclass(frozen=True, slots=True)
class RuleTestResult:
    output_directory: Path
    report: RuleTestReport


def load_rule_fixtures(directory: Path) -> tuple[RuleTestFixture, ...]:
    if not directory.is_dir():
        raise RuleInputError("fixture directory does not exist")
    paths = sorted(path for path in directory.iterdir() if path.suffix.lower() == ".json")
    if not paths:
        raise RuleInputError("fixture directory contains no JSON fixtures")
    if len(paths) > MAX_RULES * 4:
        raise RuleResourceLimitExceeded("fixture count exceeds fixed limit")
    fixtures: list[RuleTestFixture] = []
    names: set[str] = set()
    raw_canary = load_canary()
    for path in paths:
        if not path.is_file() or path.stat().st_size > MAX_RULE_BYTES:
            raise RuleResourceLimitExceeded("fixture file exceeds fixed limit")
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise RuleInputError("unable to read fixture file") from error
        if raw_canary in text:
            raise RuleInputError("raw lab canary is forbidden in fixture data")
        try:
            fixture = RuleTestFixture.model_validate_json(text)
        except ValidationError as error:
            raise RuleInputError("fixture failed schema validation") from error
        if fixture.name in names:
            raise RuleInputError("duplicate fixture name")
        names.add(fixture.name)
        event_ids = [event.event_id for event in fixture.events]
        if len(event_ids) != len(set(event_ids)):
            raise RuleInputError("fixture event IDs must be unique")
        sequence_ids = [(event.run_id, event.sequence) for event in fixture.events]
        if len(sequence_ids) != len(set(sequence_ids)):
            raise RuleInputError("fixture run sequences must be unique")
        if any(
            event_id not in set(event_ids)
            for evidence in fixture.expected_evidence
            for event_id in evidence
        ):
            raise RuleInputError("fixture expectation references unknown evidence")
        fixtures.append(fixture)
    return tuple(fixtures)


def run_rule_tests(
    rules: tuple[DetectionRule, ...], fixtures: tuple[RuleTestFixture, ...]
) -> RuleTestReport:
    by_identity = {(rule.rule_id, rule.rule_version): rule for rule in rules}
    if len(by_identity) != len(rules):
        raise RuleInputError("duplicate rule identity")
    results: list[RuleFixtureResult] = []
    positive: set[tuple[str, int]] = set()
    negative: set[tuple[str, int]] = set()
    for fixture in sorted(fixtures, key=lambda item: item.name):
        identity = (fixture.rule_id, fixture.rule_version)
        rule = by_identity.get(identity)
        if rule is None:
            raise RuleInputError("fixture references an unknown rule")
        evaluation = evaluate_rule(rule, list(fixture.events))
        actual = tuple(match.evidence_event_ids for match in evaluation.matches)
        expected = fixture.expected_evidence
        if expected:
            positive.add(identity)
        else:
            negative.add(identity)
        results.append(
            RuleFixtureResult(
                fixture=fixture.name,
                rule_id=fixture.rule_id,
                rule_version=fixture.rule_version,
                passed=actual == expected,
                expected_evidence=expected,
                actual_evidence=actual,
            )
        )
    covered = len(set(by_identity) & positive & negative)
    passed = sum(result.passed for result in results)
    complete = passed == len(results) and covered == len(rules)
    return RuleTestReport(
        status="passed" if complete else "failed",
        total_rules=len(rules),
        covered_rules=covered,
        assertions_passed=passed,
        assertions_total=len(results),
        results=tuple(results),
    )


def execute_rule_tests(
    rules_directory: Path, fixtures_directory: Path, output_directory: Path
) -> RuleTestResult:
    from .detection_reporting import write_rule_test_report

    rules = load_rules(rules_directory)
    fixtures = load_rule_fixtures(fixtures_directory)
    report = run_rule_tests(rules, fixtures)
    output_directory.mkdir(parents=True, exist_ok=False)
    write_rule_test_report(report, output_directory)
    return RuleTestResult(output_directory, report)
