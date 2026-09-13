"""Bounded investigation JSON and Markdown artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from .incident_models import InvestigationReport
from .phase4_artifacts import publish_report_pair
from .reporting import safe_markdown


def render_investigation_markdown(report: InvestigationReport) -> str:
    incident_sections: list[str] = []
    for incident in report.incidents:
        alerts = "\n".join(
            f"- `{safe_markdown(alert.rule_id)}` v{alert.rule_version}: "
            f"{safe_markdown(alert.severity)} ({safe_markdown(alert.category)})"
            for alert in incident.alerts
        )
        stages = "\n".join(
            f"- `{safe_markdown(stage.stage)}`: "
            + ", ".join(f"`{safe_markdown(reference.event_id)}`" for reference in stage.evidence)
            for stage in incident.stages
        )
        timeline = "\n".join(
            f"- {entry.evidence.sequence}. `{safe_markdown(entry.timestamp)}` "
            f"`{safe_markdown(entry.event_type)}` from "
            f"`{safe_markdown(entry.source_component)}`"
            + (" — direct match evidence" if entry.direct_match_evidence else "")
            + (" — historical detection/report" if entry.historical_derived_event else "")
            for entry in incident.timeline
        )
        evidence = "\n".join(
            f"- `{safe_markdown(reference.event_id)}` (sequence {reference.sequence})"
            for reference in incident.evidence
        )
        remediation = "\n".join(
            f"- {safe_markdown(item)}" for item in incident.recommended_remediation
        )
        incident_sections.append(
            f"## Incident `{safe_markdown(incident.stable_key)}`\n\n"
            f"- Trace: `{safe_markdown(incident.trace_id)}`\n"
            f"- Status: `{safe_markdown(incident.status)}`\n"
            f"- Category: `{safe_markdown(incident.category)}`\n"
            f"- Severity: `{safe_markdown(incident.severity)}`\n"
            f"- Outcome: `{safe_markdown(incident.outcome.outcome)}`\n"
            f"- Simulated impact: `{safe_markdown(incident.outcome.simulated_impact)}`\n"
            f"- Evidence-backed prevention: `{safe_markdown(incident.outcome.prevention)}`\n\n"
            "### Alerts\n\n"
            f"{alerts}\n\n"
            "### Attack stages\n\n"
            f"{stages or '- None'}\n\n"
            "### Timeline\n\n"
            f"{timeline or '- None'}\n\n"
            "### Direct evidence\n\n"
            f"{evidence}\n\n"
            "### Root-cause hypothesis\n\n"
            f"{safe_markdown(incident.root_cause_hypothesis)}\n\n"
            "### Recommended remediation\n\n"
            f"{remediation}\n"
        )
    incidents = "\n\n".join(incident_sections) or "## Incidents\n\nNo derived incident."
    limitations = "\n".join(f"- {safe_markdown(item)}" for item in report.safety_and_limitations)
    timing = (
        f"alert={report.historical_timing.alert_seconds}s, "
        f"incident={report.historical_timing.incident_seconds}s"
        if report.historical_timing.exclusion_reason is None
        else f"unavailable ({safe_markdown(report.historical_timing.exclusion_reason)})"
    )
    return (
        "# AgentSec Lab investigation\n\n"
        f"- Investigation: `{safe_markdown(report.investigation_id)}`\n"
        f"- Source file: `{safe_markdown(report.source_file)}`\n"
        f"- Source run: `{safe_markdown(report.source_run_id)}`\n"
        f"- Source status: `{safe_markdown(report.source_status)}`\n"
        f"- Evidence cutoff: {report.evidence_cutoff_sequence}\n"
        f"- Snapshot fingerprint: `{report.snapshot_fingerprint}`\n"
        f"- Rule-set fingerprint: `{report.rule_set_fingerprint}`\n"
        f"- Evaluated events: {report.evaluated_event_count}/{report.input_event_count}\n"
        f"- Derived alerts: {len(report.derived_alerts)}\n"
        f"- Derived incidents: {len(report.incidents)}\n"
        f"- Historical legacy timing: {timing}\n"
        f"- Offline processing seconds: {report.local_processing_seconds:.6f}\n\n"
        f"{incidents}\n\n"
        "## Safety and limitations\n\n"
        f"{limitations}\n"
    )


def write_investigation_report(report: InvestigationReport, directory: Path) -> tuple[Path, Path]:
    json_data = json.dumps(
        report.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    markdown_data = render_investigation_markdown(report).encode("utf-8")
    return publish_report_pair(directory, "investigation", json_data, markdown_data)
