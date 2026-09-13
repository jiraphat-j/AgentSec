"""Bounded JSON and Markdown output for Phase 4 evaluations."""

from __future__ import annotations

import json
from pathlib import Path

from .evaluation_models import EvaluationReport
from .phase4_artifacts import publish_report_pair
from .reporting import safe_markdown


def render_evaluation_markdown(report: EvaluationReport) -> str:
    child_rows = "\n".join(
        "| "
        + " | ".join(
            (
                safe_markdown(child.case_id),
                str(child.trial),
                safe_markdown(child.profile),
                safe_markdown(child.status),
                safe_markdown(
                    str(child.observation.model_dump(mode="json")) if child.observation else "none"
                ),
                safe_markdown(child.exclusion_reason or "none"),
            )
        )
        + " |"
        for child in report.children
    )
    metric_rows = "\n".join(
        "| "
        + " | ".join(
            (
                safe_markdown(metric.profile),
                safe_markdown(metric.name),
                str(metric.numerator),
                str(metric.denominator),
                "unavailable" if metric.value is None else f"{metric.value:.6f}",
                str(metric.excluded_count),
            )
        )
        + " |"
        for metric in report.metrics
    )
    confusion_rows = "\n".join(
        f"| {safe_markdown(item.profile)} | {item.true_positive} | {item.false_negative} | "
        f"{item.false_positive} | {item.true_negative} |"
        for item in report.confusion_counts
    )
    timing_rows = "\n".join(
        f"| {safe_markdown(item.profile)} | {item.mean_alert_seconds} | "
        f"{item.mean_incident_seconds} | {item.sample_count} | {item.excluded_count} |"
        for item in report.timing
    )
    rule_rows = "\n".join(
        f"| `{safe_markdown(item.rule_id)}` | {item.run_count} |" for item in report.rule_run_counts
    )
    category_rows = "\n".join(
        f"| `{safe_markdown(item.category)}` | {item.incident_count} |"
        for item in report.incident_category_counts
    )
    limitations = "\n".join(f"- {safe_markdown(item)}" for item in report.safety_and_limitations)
    pair_rows = "\n".join(
        f"| {safe_markdown(pair.case_id)} | {pair.trial} | {safe_markdown(pair.status)} | "
        f"{pair.vulnerable_impact} | {pair.strict_prevention} |"
        for pair in report.pairs
    )
    return (
        "# AgentSec Lab evaluation\n\n"
        f"- Evaluation: `{safe_markdown(report.evaluation_id)}`\n"
        f"- Suite: `{safe_markdown(report.suite_id)}`\n"
        f"- Suite fingerprint: `{report.suite_fingerprint}`\n"
        f"- Status: `{safe_markdown(report.status)}`\n"
        f"- Repetitions: {report.repetitions}\n"
        f"- Children: {report.completed_children}/{report.scheduled_children} completed\n"
        f"- Assertion failures: {report.assertion_failures}\n\n"
        "## Child runs\n\n"
        "| Case | Trial | Profile | Status | Observed facts | Exclusion |\n"
        "|---|---:|---|---|---:|---|\n"
        f"{child_rows}\n\n"
        "## Metrics\n\n"
        "| Profile | Metric | Numerator | Denominator | Value | Excluded |\n"
        "|---|---|---:|---:|---:|---:|\n"
        f"{metric_rows}\n\n"
        "## Run-level confusion counts\n\n"
        "| Profile | TP | FN | FP | TN |\n"
        "|---|---:|---:|---:|---:|\n"
        f"{confusion_rows}\n\n"
        "## Recorded legacy timing\n\n"
        "| Profile | Mean alert seconds | Mean incident seconds | Samples | Excluded |\n"
        "|---|---:|---:|---:|---:|\n"
        f"{timing_rows}\n\n"
        "## Detection and incident breakdown\n\n"
        "| Rule | Runs with a match |\n"
        "|---|---:|\n"
        f"{rule_rows or '| None | 0 |'}\n\n"
        "| Incident category | Incidents |\n"
        "|---|---:|\n"
        f"{category_rows or '| None | 0 |'}\n\n"
        "## Paired outcomes\n\n"
        "| Case | Trial | Status | Vulnerable impact | Strict prevention |\n"
        "|---|---:|---|---|---|\n"
        f"{pair_rows}\n\n"
        "## Paired prevention on vulnerable-impact cases\n\n"
        f"- Numerator: {report.impact_pair_prevention_numerator}\n"
        f"- Denominator: {report.impact_pair_prevention_denominator}\n"
        f"- Fraction: {report.impact_pair_prevention_rate}\n\n"
        "## Safety and limitations\n\n"
        f"{limitations}\n"
    )


def write_evaluation_report(report: EvaluationReport, directory: Path) -> tuple[Path, Path]:
    json_data = json.dumps(
        report.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    markdown_data = render_evaluation_markdown(report).encode("utf-8")
    return publish_report_pair(directory, "evaluation", json_data, markdown_data)
