"""Evidence-backed JSON and Markdown report generation."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .constants import MAX_REPORT_BYTES
from .models import DetectionResult, Event, Outcome, PolicyProfile, Report, Scenario
from .outcomes import derive_impact, derive_prevention


class ReportWriteError(RuntimeError):
    pass


def build_report(
    scenario: Scenario,
    run_id: str,
    trace_id: str,
    events: list[Event],
    detection: DetectionResult,
    profile: PolicyProfile = PolicyProfile.VULNERABLE,
) -> Report:
    impact = derive_impact(events)
    prevention = derive_prevention(events)
    outcome: Outcome
    if impact.reached and prevention.blocked:
        outcome = "incomplete"
    elif impact.reached:
        outcome = "simulated_impact"
    elif prevention.blocked:
        outcome = "prevented"
    else:
        outcome = "no_correlated_chain"
    actions = tuple(
        f"{event.event_type}: {event.payload.get('tool', event.source_component)}"
        for event in events
        if event.event_type
        in {
            "tool.requested",
            "policy.allowed",
            "policy.denied",
            "policy.approval_required",
            "approval.simulated",
            "file.read",
            "lab.sink.payload_recorded",
        }
    )
    if outcome == "simulated_impact":
        executive_summary = (
            "The deterministic lab observed a fake canary at the in-process sink. "
            "The complete correlated chain created a critical incident."
            if detection.detected
            else (
                "The deterministic lab observed simulated impact, but the available "
                "evidence did not produce the complete correlation result."
            )
        )
        root_cause = (
            "The vulnerable profile followed an instruction from untrusted document content "
            "and allowed both controlled tool actions."
        )
    elif outcome == "prevented":
        executive_summary = (
            f"The strict runtime policy blocked the attack at {prevention.stage} before "
            "simulated impact."
        )
        root_cause = (
            "Untrusted document content proposed a sensitive tool action; the strict policy "
            "recognized the risk and denied dispatch."
        )
    elif outcome == "incomplete":
        executive_summary = (
            "The evidence contains both simulated impact and a prevention decision and requires "
            "manual investigation."
        )
        root_cause = "The available evidence is internally inconsistent for a single outcome."
    else:
        executive_summary = (
            "The deterministic lab completed without simulated impact or evidence-backed "
            "prevention of the defined attack."
        )
        root_cause = "The evidence does not establish the complete simulated attack chain."
    return Report(
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        run_id=run_id,
        trace_id=trace_id,
        status="completed",
        executive_summary=executive_summary,
        attack_vector="Indirect prompt injection through an untrusted text document",
        agent_and_tool_actions=actions,
        timeline=tuple(events),
        evidence_cutoff_sequence=events[-1].sequence if events else 0,
        policy_profile=profile,
        detection=detection,
        prevention=prevention,
        simulated_impact=impact,
        outcome=outcome,
        attempted_impact=(
            "A fake canary reached the in-process lab sink; this was attempted simulated "
            "exfiltration with no network connection."
            if impact.reached
            else "No matching fake-canary flow reached the in-process lab sink."
        ),
        root_cause=root_cause,
        recommended_remediation=(
            "Treat document content as untrusted data rather than tool instructions.",
            "Require policy authorization for sensitive data access and outbound actions.",
            "Correlate document provenance, secret access, and outbound data-flow telemetry.",
        ),
        safety_and_limitations=(
            "This is an educational simulation using a fake canary with no real privileges.",
            "Risk scores are deterministic heuristics, not calibrated attack probabilities.",
            "Simulated approval is not actual human authorization.",
            "The lab sink opens no operating-system network socket and performs no DNS lookup.",
            "The deterministic mock does not measure the susceptibility of a real language model.",
        ),
    )


def safe_markdown(value: object) -> str:
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(value))
    for token in ("\\", "`", "*", "_", "{", "}", "[", "]", "<", ">", "#", "|", "~"):
        text = text.replace(token, f"\\{token}")
    return text.replace("\r", " ").replace("\n", " ")


def render_markdown(report: Report) -> str:
    detection = "Critical alert created" if report.detection.detected else "No correlated match"
    prevention = (
        f"Blocked at {report.prevention.stage} ({report.prevention.reason})"
        if report.prevention.blocked
        else "No evidence-backed prevention"
    )
    detection_evidence = (
        "\n".join(
            f"- `{safe_markdown(event_id)}`" for event_id in report.detection.evidence_event_ids
        )
        or "- None"
    )
    prevention_evidence = (
        "\n".join(
            f"- `{safe_markdown(event_id)}`" for event_id in report.prevention.evidence_event_ids
        )
        or "- None"
    )
    timeline = "\n".join(
        f"- {event.sequence}. `{safe_markdown(event.event_type)}` from "
        f"`{safe_markdown(event.source_component)}`"
        for event in report.timeline
    )
    remediation = "\n".join(f"- {safe_markdown(item)}" for item in report.recommended_remediation)
    actions = "\n".join(f"- {safe_markdown(item)}" for item in report.agent_and_tool_actions)
    actions = actions or "- No tool action recorded"
    limitations = "\n".join(f"- {safe_markdown(item)}" for item in report.safety_and_limitations)
    return (
        "# AgentSec Lab run report\n\n"
        f"- Scenario: {safe_markdown(report.scenario_name)}\n"
        f"- Scenario ID: `{safe_markdown(report.scenario_id)}`\n"
        f"- Run ID: `{safe_markdown(report.run_id)}`\n"
        f"- Trace ID: `{safe_markdown(report.trace_id)}`\n"
        f"- Policy profile: `{safe_markdown(report.policy_profile)}`\n"
        f"- Policy version: `{safe_markdown(report.policy_version)}`\n"
        f"- Risk version: `{safe_markdown(report.risk_version)}`\n"
        f"- Outcome: `{safe_markdown(report.outcome)}`\n"
        f"- Detection: {safe_markdown(detection)}\n"
        f"- Prevention: {safe_markdown(prevention)}\n\n"
        "## Executive summary\n\n"
        f"{safe_markdown(report.executive_summary)}\n\n"
        "## Attack vector\n\n"
        f"{safe_markdown(report.attack_vector)}\n\n"
        "## Agent and tool actions\n\n"
        f"{actions}\n\n"
        "## Timeline\n\n"
        f"{timeline}\n\n"
        "## Detection\n\n"
        f"- Rule: `{safe_markdown(report.detection.rule_id)}`\n"
        f"- Version: {report.detection.rule_version}\n"
        f"- Matched: {str(report.detection.detected).lower()}\n\n"
        "## Prevention\n\n"
        f"- Result: {safe_markdown(prevention)}\n\n"
        "## Evidence references\n\n"
        "### Detection\n\n"
        f"{detection_evidence}\n\n"
        "### Prevention\n\n"
        f"{prevention_evidence}\n\n"
        "## Attempted impact\n\n"
        f"{safe_markdown(report.attempted_impact)}\n\n"
        "## Root cause\n\n"
        f"{safe_markdown(report.root_cause)}\n\n"
        "## Recommended remediation\n\n"
        f"{remediation}\n\n"
        "## Safety and limitations\n\n"
        f"{limitations}\n"
    )


def write_reports(report: Report, run_directory: Path) -> tuple[Path, Path]:
    json_path = run_directory / "report.json"
    markdown_path = run_directory / "report.md"
    if json_path.exists() or markdown_path.exists():
        raise ReportWriteError("refusing to overwrite an existing report")
    json_data = json.dumps(
        report.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    markdown_data = render_markdown(report).encode("utf-8")
    if len(json_data) > MAX_REPORT_BYTES or len(markdown_data) > MAX_REPORT_BYTES:
        raise ReportWriteError("report exceeds fixed size limit")
    json_temp = run_directory / ".report.json.tmp"
    markdown_temp = run_directory / ".report.md.tmp"
    try:
        json_temp.write_bytes(json_data)
        markdown_temp.write_bytes(markdown_data)
        json_temp.replace(json_path)
        markdown_temp.replace(markdown_path)
    except OSError as error:
        for path in (json_temp, markdown_temp, json_path, markdown_path):
            if path.exists():
                path.unlink()
        raise ReportWriteError("unable to write required report artifacts") from error
    return json_path, markdown_path
