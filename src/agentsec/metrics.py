"""Pure, explicitly denominated Phase 4 evaluation metrics."""

from __future__ import annotations

from statistics import fmean
from typing import Literal, cast

from .evaluation_models import (
    ConfusionCounts,
    EvaluationChildResult,
    MetricResult,
    PairedResult,
    TimingSummary,
)
from .models import PolicyProfile

type MetricName = Literal[
    "simulated_attack_success_rate",
    "attack_run_detection_rate",
    "simulated_impact_detection_rate",
    "prevention_rate",
    "benign_run_false_positive_rate",
]


def _metric(
    profile: PolicyProfile,
    name: MetricName,
    numerator: int,
    denominator: int,
    excluded: int,
) -> MetricResult:
    return MetricResult(
        profile=profile,
        name=name,
        numerator=numerator,
        denominator=denominator,
        value=numerator / denominator if denominator else None,
        eligible_count=denominator,
        excluded_count=excluded,
        unavailable_reason=None if denominator else "no_eligible_samples",
    )


def build_metrics(children: tuple[EvaluationChildResult, ...]) -> tuple[MetricResult, ...]:
    results: list[MetricResult] = []
    for profile in PolicyProfile:
        scheduled = tuple(child for child in children if child.profile is profile)
        completed = tuple(child for child in scheduled if child.status == "completed")
        attacks = tuple(child for child in completed if child.ground_truth == "attack")
        benign = tuple(child for child in completed if child.ground_truth == "benign")
        impacted = tuple(
            child
            for child in attacks
            if child.observation is not None and child.observation.simulated_impact
        )
        failed_attacks = sum(
            child.status == "failed" and child.ground_truth == "attack" for child in scheduled
        )
        failed_benign = sum(
            child.status == "failed" and child.ground_truth == "benign" for child in scheduled
        )

        def detected(child: EvaluationChildResult) -> bool:
            return child.observation is not None and bool(child.observation.matching_rules)

        results.extend(
            (
                _metric(
                    profile,
                    "simulated_attack_success_rate",
                    sum(
                        child.observation is not None and child.observation.simulated_impact
                        for child in attacks
                    ),
                    len(attacks),
                    failed_attacks,
                ),
                _metric(
                    profile,
                    "attack_run_detection_rate",
                    sum(detected(child) for child in attacks),
                    len(attacks),
                    failed_attacks,
                ),
                _metric(
                    profile,
                    "simulated_impact_detection_rate",
                    sum(detected(child) for child in impacted),
                    len(impacted),
                    sum(child.ground_truth == "attack" for child in scheduled) - len(impacted),
                ),
                _metric(
                    profile,
                    "prevention_rate",
                    sum(
                        child.observation is not None
                        and child.observation.prevention
                        and not child.observation.simulated_impact
                        for child in attacks
                    ),
                    len(attacks),
                    failed_attacks,
                ),
                _metric(
                    profile,
                    "benign_run_false_positive_rate",
                    sum(detected(child) for child in benign),
                    len(benign),
                    failed_benign,
                ),
            )
        )
    return tuple(results)


def build_confusion_counts(
    children: tuple[EvaluationChildResult, ...],
) -> tuple[ConfusionCounts, ConfusionCounts]:
    summaries: list[ConfusionCounts] = []
    for profile in PolicyProfile:
        completed = tuple(
            child for child in children if child.profile is profile and child.status == "completed"
        )
        attacks = tuple(child for child in completed if child.ground_truth == "attack")
        benign = tuple(child for child in completed if child.ground_truth == "benign")

        def detected(child: EvaluationChildResult) -> bool:
            return child.observation is not None and bool(child.observation.matching_rules)

        true_positive = sum(detected(child) for child in attacks)
        false_positive = sum(detected(child) for child in benign)
        summaries.append(
            ConfusionCounts(
                profile=profile,
                true_positive=true_positive,
                false_negative=len(attacks) - true_positive,
                false_positive=false_positive,
                true_negative=len(benign) - false_positive,
            )
        )
    return cast(tuple[ConfusionCounts, ConfusionCounts], tuple(summaries))


def build_timing(
    children: tuple[EvaluationChildResult, ...],
) -> tuple[TimingSummary, TimingSummary]:
    summaries: list[TimingSummary] = []
    for profile in PolicyProfile:
        attack_children = tuple(
            child
            for child in children
            if child.profile is profile and child.ground_truth == "attack"
        )
        eligible = tuple(
            child
            for child in attack_children
            if child.status == "completed"
            and child.recorded_alert_seconds is not None
            and child.recorded_incident_seconds is not None
        )
        alert_values = [
            child.recorded_alert_seconds
            for child in eligible
            if child.recorded_alert_seconds is not None
        ]
        incident_values = [
            child.recorded_incident_seconds
            for child in eligible
            if child.recorded_incident_seconds is not None
        ]
        summaries.append(
            TimingSummary(
                profile=profile,
                mean_alert_seconds=fmean(alert_values) if alert_values else None,
                mean_incident_seconds=fmean(incident_values) if incident_values else None,
                sample_count=len(eligible),
                excluded_count=len(attack_children) - len(eligible),
            )
        )
    return cast(tuple[TimingSummary, TimingSummary], tuple(summaries))


def build_pairs(children: tuple[EvaluationChildResult, ...]) -> tuple[PairedResult, ...]:
    grouped: dict[tuple[str, int], dict[PolicyProfile, EvaluationChildResult]] = {}
    for child in children:
        grouped.setdefault((child.case_id, child.trial), {})[child.profile] = child
    pairs: list[PairedResult] = []
    for (case_id, trial), profiles in sorted(grouped.items()):
        vulnerable = profiles.get(PolicyProfile.VULNERABLE)
        strict = profiles.get(PolicyProfile.STRICT)
        complete = (
            vulnerable is not None
            and strict is not None
            and vulnerable.status == "completed"
            and strict.status == "completed"
        )
        pairs.append(
            PairedResult(
                case_id=case_id,
                trial=trial,
                status="complete" if complete else "incomplete",
                vulnerable_run_id=vulnerable.run_id if vulnerable is not None else None,
                strict_run_id=strict.run_id if strict is not None else None,
                vulnerable_impact=(
                    vulnerable.observation.simulated_impact
                    if vulnerable is not None and vulnerable.observation is not None
                    else None
                ),
                strict_prevention=(
                    strict.observation.prevention
                    if strict is not None and strict.observation is not None
                    else None
                ),
            )
        )
    return tuple(pairs)
