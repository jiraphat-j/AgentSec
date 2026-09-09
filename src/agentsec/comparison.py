"""Evidence-backed vulnerable-versus-strict comparison reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .constants import MAX_REPORT_BYTES
from .detection import CorrelationDetector
from .models import (
    ApprovalEvidence,
    ComparisonChild,
    ComparisonReport,
    EnforcementLayer,
    Event,
    Outcome,
    PolicyDecisionEvidence,
    PolicyProfile,
    RiskAssessment,
    Scenario,
)
from .outcomes import derive_impact, derive_prevention
from .reporting import ReportWriteError, safe_markdown


@dataclass(frozen=True, slots=True)
class ComparisonEvidence:
    profile: PolicyProfile
    run_id: str
    trace_id: str
    relative_directory: str
    events: list[Event]


def _child(source: ComparisonEvidence) -> ComparisonChild:
    detection = CorrelationDetector().evaluate(source.events)
    impact = derive_impact(source.events)
    prevention = derive_prevention(source.events)
    outcome: Outcome
    if impact.reached and prevention.blocked:
        outcome = "incomplete"
    elif impact.reached:
        outcome = "simulated_impact"
    elif prevention.blocked:
        outcome = "prevented"
    else:
        outcome = "no_correlated_chain"
    decisions = tuple(
        PolicyDecisionEvidence(
            event_id=event.event_id,
            tool_call_id=event.tool_call_id,
            tool=str(event.payload.get("tool", "unknown")),
            decision=str(event.payload.get("decision", "unknown")),
            reason=str(event.payload.get("reason", "unknown")),
            rule_id=str(event.payload.get("rule_id", "unknown")),
            enforcement_layer=EnforcementLayer(
                str(event.payload.get("enforcement_layer", "safety"))
            ),
            risk=(
                RiskAssessment.model_validate_json(json.dumps(event.payload["risk"]))
                if event.payload.get("risk") is not None
                else None
            ),
        )
        for event in source.events
        if event.event_type in {"policy.allowed", "policy.denied"}
    )
    approvals = tuple(
        ApprovalEvidence(
            event_id=event.event_id,
            tool_call_id=event.tool_call_id,
            approved=event.payload.get("approved") is True,
            reason=str(event.payload.get("reason", "unknown")),
        )
        for event in source.events
        if event.event_type == "approval.simulated"
    )
    unqualified_references = (
        detection.evidence_event_ids
        + impact.evidence_event_ids
        + prevention.evidence_event_ids
        + tuple(decision.event_id for decision in decisions)
        + tuple(approval.event_id for approval in approvals)
    )
    references = tuple(
        f"{source.run_id}:{event_id}"
        for event_id in dict.fromkeys(unqualified_references)
    )
    relative = Path(source.relative_directory)
    return ComparisonChild(
        profile=source.profile,
        run_id=source.run_id,
        trace_id=source.trace_id,
        relative_directory=relative.as_posix(),
        report_json=(relative / "report.json").as_posix(),
        report_markdown=(relative / "report.md").as_posix(),
        outcome=outcome,
        detected=detection.detected,
        simulated_impact=impact,
        prevention=prevention,
        policy_decisions=decisions,
        approval_results=approvals,
        evidence_references=references,
    )


def build_comparison(
    scenario: Scenario,
    comparison_id: str,
    vulnerable: ComparisonEvidence,
    strict: ComparisonEvidence,
) -> ComparisonReport:
    if vulnerable.profile is not PolicyProfile.VULNERABLE:
        raise ValueError("vulnerable comparison child has the wrong profile")
    if strict.profile is not PolicyProfile.STRICT:
        raise ValueError("strict comparison child has the wrong profile")
    _verify_recorded_run(vulnerable, scenario)
    _verify_recorded_run(strict, scenario)
    vulnerable_child = _child(vulnerable)
    strict_child = _child(strict)
    divergence = _first_policy_divergence(vulnerable_child, strict_child)
    conclusion = comparison_conclusion(vulnerable_child, strict_child)
    return ComparisonReport(
        comparison_id=comparison_id,
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        children=(vulnerable_child, strict_child),
        divergence=divergence,
        conclusion=conclusion,
        safety_and_limitations=(
            "Both children use the same packaged deterministic scenario in isolated runs.",
            "The lab opens no operating-system socket and performs no DNS lookup.",
            "Risk scores are educational heuristics and approvals are simulated.",
            "This comparison does not measure real-model robustness or real-network prevention.",
        ),
    )


def comparison_conclusion(
    vulnerable: ComparisonChild, strict: ComparisonChild
) -> str:
    if vulnerable.outcome == "incomplete":
        vulnerable_result = (
            "The vulnerable profile recorded both simulated impact and evidence-backed "
            "prevention, so its outcome is incomplete."
        )
    elif vulnerable.simulated_impact.reached and vulnerable.detected:
        vulnerable_result = (
            "The vulnerable profile reached socket-free simulated impact and created the "
            "expected critical incident."
        )
    elif vulnerable.simulated_impact.reached:
        vulnerable_result = (
            "The vulnerable profile reached socket-free simulated impact, but the evidence "
            "did not create the expected critical incident."
        )
    elif vulnerable.detected:
        vulnerable_result = (
            "The vulnerable profile recorded a critical detection without matching "
            "simulated-impact evidence."
        )
    else:
        vulnerable_result = (
            "The vulnerable profile established neither simulated impact nor a critical "
            "detection."
        )

    if strict.outcome == "incomplete":
        if strict.simulated_impact.reached and strict.prevention.blocked:
            stage = (
                "secret-access"
                if strict.prevention.stage == "secret_access"
                else "outbound-transfer"
            )
            strict_result = (
                f"The strict profile recorded both simulated impact and a {stage} block, so "
                "its outcome is incomplete."
            )
        else:
            strict_result = (
                "The strict profile contains internally inconsistent evidence, so its outcome "
                "is incomplete."
            )
    elif strict.prevention.blocked and strict.prevention.stage == "secret_access":
        strict_result = (
            "The strict profile prevented the chain before fake-secret access."
        )
    elif strict.prevention.blocked and strict.prevention.stage == "outbound_transfer":
        strict_result = "The strict profile blocked the outbound transfer."
    else:
        strict_result = "The strict profile did not establish evidence-backed prevention."
    return f"{vulnerable_result} {strict_result}"


def _first_policy_divergence(
    vulnerable: ComparisonChild, strict: ComparisonChild
) -> str:
    for vulnerable_decision, strict_decision in zip(
        vulnerable.policy_decisions, strict.policy_decisions, strict=False
    ):
        if (
            vulnerable_decision.tool == strict_decision.tool
            and vulnerable_decision.decision != strict_decision.decision
        ):
            return (
                f"The vulnerable profile chose {vulnerable_decision.decision} for "
                f"{vulnerable_decision.tool}; the strict profile chose "
                f"{strict_decision.decision} with {strict_decision.reason} before adapter "
                "dispatch."
            )
    return "Canonical policy evidence contains no corresponding decision divergence."


def _verify_recorded_run(source: ComparisonEvidence, scenario: Scenario) -> None:
    started = next(
        (event for event in source.events if event.event_type == "run.started"), None
    )
    if started is None:
        raise ValueError("comparison child has no run.started evidence")
    if started.run_id != source.run_id or started.trace_id != source.trace_id:
        raise ValueError("comparison child identity does not match canonical evidence")
    if started.payload.get("scenario_id") != scenario.id:
        raise ValueError("comparison children must use the same scenario")
    if started.payload.get("fixture") != scenario.document_fixture.value:
        raise ValueError("comparison children must use the same document fixture")
    if started.payload.get("profile") != source.profile.value:
        raise ValueError("comparison profile does not match canonical evidence")


def render_comparison_markdown(report: ComparisonReport) -> str:
    rows = "\n".join(
        "| "
        + " | ".join(
            (
                safe_markdown(child.profile),
                f"`{safe_markdown(child.run_id)}`",
                safe_markdown(child.outcome),
                str(child.detected).lower(),
                str(child.simulated_impact.reached).lower(),
                str(child.prevention.blocked).lower(),
                f"[{safe_markdown(child.report_markdown)}]({safe_markdown(child.report_markdown)})",
            )
        )
        + " |"
        for child in report.children
    )
    limitations = "\n".join(f"- {safe_markdown(item)}" for item in report.safety_and_limitations)
    return (
        "# AgentSec Lab defense comparison\n\n"
        f"- Comparison ID: `{safe_markdown(report.comparison_id)}`\n"
        f"- Scenario: {safe_markdown(report.scenario_name)}\n"
        f"- Policy version: `{safe_markdown(report.policy_version)}`\n"
        f"- Risk version: `{safe_markdown(report.risk_version)}`\n\n"
        "## Results\n\n"
        "| Profile | Run | Outcome | Detected | Impact | Prevented | Report |\n"
        "|---|---|---|---:|---:|---:|---|\n"
        f"{rows}\n\n"
        "## First policy divergence\n\n"
        f"{safe_markdown(report.divergence)}\n\n"
        "## Conclusion\n\n"
        f"{safe_markdown(report.conclusion)}\n\n"
        "## Safety and limitations\n\n"
        f"{limitations}\n"
    )


def write_comparison_reports(
    report: ComparisonReport, comparison_directory: Path
) -> tuple[Path, Path]:
    json_path = comparison_directory / "comparison.json"
    markdown_path = comparison_directory / "comparison.md"
    if json_path.exists() or markdown_path.exists():
        raise ReportWriteError("refusing to overwrite an existing comparison report")
    json_data = json.dumps(
        report.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    markdown_data = render_comparison_markdown(report).encode("utf-8")
    if len(json_data) > MAX_REPORT_BYTES or len(markdown_data) > MAX_REPORT_BYTES:
        raise ReportWriteError("comparison report exceeds fixed size limit")
    json_temp = comparison_directory / ".comparison.json.tmp"
    markdown_temp = comparison_directory / ".comparison.md.tmp"
    try:
        json_temp.write_bytes(json_data)
        markdown_temp.write_bytes(markdown_data)
        json_temp.replace(json_path)
        markdown_temp.replace(markdown_path)
    except OSError as error:
        for path in (json_temp, markdown_temp, json_path, markdown_path):
            if path.exists():
                path.unlink()
        raise ReportWriteError("unable to write required comparison artifacts") from error
    return json_path, markdown_path
