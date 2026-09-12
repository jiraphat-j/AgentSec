"""Bounded JSON and Markdown reports for rule tests and offline replay."""

from __future__ import annotations

import json
from pathlib import Path

from .constants import MAX_REPORT_BYTES
from .reporting import ReportWriteError, safe_markdown
from .resource_loader import load_canary
from .rule_models import ReplayReport, RuleTestReport


def render_rule_test_markdown(report: RuleTestReport) -> str:
    rows = "\n".join(
        "| "
        + " | ".join(
            (
                safe_markdown(result.fixture),
                safe_markdown(result.rule_id),
                str(result.rule_version),
                str(result.passed).lower(),
                str(len(result.expected_evidence)),
                str(len(result.actual_evidence)),
            )
        )
        + " |"
        for result in report.results
    )
    return (
        "# AgentSec Lab rule-test report\n\n"
        f"- Status: `{report.status}`\n"
        f"- Rule coverage: {report.covered_rules}/{report.total_rules}\n"
        f"- Fixture assertions: {report.assertions_passed}/{report.assertions_total}\n\n"
        "| Fixture | Rule | Version | Passed | Expected matches | Actual matches |\n"
        "|---|---|---:|---:|---:|---:|\n"
        f"{rows}\n"
    )


def render_replay_markdown(report: ReplayReport) -> str:
    rows = "\n".join(
        "| "
        + " | ".join(
            (
                safe_markdown(evaluation.rule_id),
                str(evaluation.rule_version),
                str(len(evaluation.matches)),
                str(evaluation.candidate_count),
            )
        )
        + " |"
        for evaluation in report.evaluations
    )
    evidence = "\n".join(
        f"- `{safe_markdown(match.dedup_key)}`: "
        + ", ".join(f"`{safe_markdown(item)}`" for item in match.evidence_event_ids)
        for evaluation in report.evaluations
        for match in evaluation.matches
    )
    evidence = evidence or "- None"
    limitations = "\n".join(f"- {safe_markdown(item)}" for item in report.safety_and_limitations)
    return (
        "# AgentSec Lab replay report\n\n"
        f"- Replay ID: `{safe_markdown(report.replay_id)}`\n"
        f"- Source file: `{safe_markdown(report.source_file)}`\n"
        f"- Source run: `{safe_markdown(report.source_run_id)}`\n"
        f"- Source status: `{report.source_status}`\n"
        f"- Evidence cutoff: {report.evidence_cutoff_sequence}\n"
        f"- Evaluated events: {report.evaluated_event_count}/{report.input_event_count}\n"
        f"- Total matches: {report.total_matches}\n"
        f"- Local processing seconds: {report.local_processing_seconds:.6f}\n\n"
        "| Rule | Version | Matches | Candidate states |\n"
        "|---|---:|---:|---:|\n"
        f"{rows}\n\n"
        "## Evidence\n\n"
        f"{evidence}\n\n"
        "## Safety and limitations\n\n"
        f"{limitations}\n"
    )


def _write_report_pair(
    report: RuleTestReport | ReplayReport,
    directory: Path,
    stem: str,
    markdown: str,
) -> tuple[Path, Path]:
    json_path = directory / f"{stem}.json"
    markdown_path = directory / f"{stem}.md"
    if json_path.exists() or markdown_path.exists():
        raise ReportWriteError("refusing to overwrite an existing detection report")
    json_data = json.dumps(
        report.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    markdown_data = markdown.encode("utf-8")
    raw_canary = load_canary().encode("utf-8")
    if raw_canary in json_data or raw_canary in markdown_data:
        raise ReportWriteError("raw lab canary rejected from detection report")
    if len(json_data) > MAX_REPORT_BYTES or len(markdown_data) > MAX_REPORT_BYTES:
        raise ReportWriteError("detection report exceeds fixed size limit")
    json_temp = directory / f".{stem}.json.tmp"
    markdown_temp = directory / f".{stem}.md.tmp"
    try:
        json_temp.write_bytes(json_data)
        markdown_temp.write_bytes(markdown_data)
        json_temp.replace(json_path)
        markdown_temp.replace(markdown_path)
    except OSError as error:
        for path in (json_temp, markdown_temp, json_path, markdown_path):
            if path.exists():
                path.unlink()
        raise ReportWriteError("unable to write required detection artifacts") from error
    return json_path, markdown_path


def write_rule_test_report(report: RuleTestReport, directory: Path) -> tuple[Path, Path]:
    return _write_report_pair(report, directory, "rule-tests", render_rule_test_markdown(report))


def write_replay_report(report: ReplayReport, directory: Path) -> tuple[Path, Path]:
    return _write_report_pair(report, directory, "replay", render_replay_markdown(report))
