from __future__ import annotations

import pytest

from agentsec.approvals import ApprovalBindingError, ApprovalSimulator
from agentsec.models import (
    ApprovalSimulation,
    PolicyAction,
    PolicyProfile,
    RiskBand,
)
from agentsec.policy import PolicyEvaluator
from agentsec.risk import assess_risk


def test_risk_score_is_deterministic_bounded_and_profile_independent() -> None:
    first = assess_risk(
        "http_post", untrusted_document=True, matching_canary=True
    )
    second = assess_risk(
        "http_post", untrusted_document=True, matching_canary=True
    )

    assert first == second
    assert first.score == 100
    assert first.band is RiskBand.HIGH
    assert [factor.code for factor in first.factors] == [
        "untrusted_document",
        "lab_post",
        "matching_canary_transfer",
    ]
    assert PolicyEvaluator(PolicyProfile.VULNERABLE).evaluate(
        "http_post", first
    ).risk == PolicyEvaluator(PolicyProfile.STRICT).evaluate("http_post", first).risk


@pytest.mark.parametrize(
    ("score_source", "band", "action"),
    [
        ("low", RiskBand.LOW, PolicyAction.ALLOW),
        ("elevated", RiskBand.ELEVATED, PolicyAction.REQUIRE_APPROVAL),
        ("high", RiskBand.HIGH, PolicyAction.DENY),
    ],
)
def test_strict_risk_bands_choose_expected_action(
    score_source: str, band: RiskBand, action: PolicyAction
) -> None:
    if score_source == "low":
        risk = assess_risk("read_file", untrusted_document=False)
    elif score_source == "elevated":
        risk = assess_risk("http_post", untrusted_document=False)
    else:
        risk = assess_risk(
            "read_file", untrusted_document=True, secret_resource=True
        )

    decision = PolicyEvaluator(PolicyProfile.STRICT).evaluate("other", risk)

    assert risk.band is band
    assert decision.action is action


def test_approval_response_is_bound_and_single_use() -> None:
    simulator = ApprovalSimulator(
        ApprovalSimulation.APPROVE, id_factory=lambda: "approval_1"
    )
    response = simulator.respond("run_1", "trace_1", "call_1")

    assert simulator.resolve(
        response, run_id="run_1", trace_id="trace_1", tool_call_id="call_1"
    )
    with pytest.raises(ApprovalBindingError, match="consumed"):
        simulator.resolve(
            response, run_id="run_1", trace_id="trace_1", tool_call_id="call_1"
        )


def test_forged_or_stale_approval_response_is_rejected() -> None:
    simulator = ApprovalSimulator(
        ApprovalSimulation.APPROVE, id_factory=lambda: "approval_1"
    )
    response = simulator.respond("run_old", "trace_1", "call_1")

    with pytest.raises(ApprovalBindingError, match="match"):
        simulator.resolve(
            response, run_id="run_new", trace_id="trace_1", tool_call_id="call_1"
        )


def test_internally_inconsistent_approval_response_is_rejected() -> None:
    simulator = ApprovalSimulator(
        ApprovalSimulation.APPROVE, id_factory=lambda: "approval_1"
    )
    response = simulator.respond("run_1", "trace_1", "call_1").model_copy(
        update={"reason": "simulated_approval_denied"}
    )

    with pytest.raises(ApprovalBindingError, match="match"):
        simulator.resolve(
            response, run_id="run_1", trace_id="trace_1", tool_call_id="call_1"
        )


def test_internally_inconsistent_approval_response_is_rejected() -> None:
    simulator = ApprovalSimulator(
        ApprovalSimulation.APPROVE, id_factory=lambda: "approval_1"
    )
    response = simulator.respond("run_1", "trace_1", "call_1").model_copy(
        update={"reason": "simulated_approval_denied"}
    )

    with pytest.raises(ApprovalBindingError, match="match"):
        simulator.resolve(
            response, run_id="run_1", trace_id="trace_1", tool_call_id="call_1"
        )
