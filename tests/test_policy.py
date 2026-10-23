"""Unit tests for the Deterministic Policy Gate."""

import pytest
from src.schemas import (
    ActionRequest,
    PolicyDecisionStatus,
    RiskLevel
)
from src.policy import PolicyGate
from src.mock_tools import MockITEnvironment


@pytest.fixture
def policy_gate():
    return PolicyGate()


@pytest.fixture
def mock_adapter():
    return MockITEnvironment()


def test_prohibited_tool_rejected(policy_gate):
    """Verify that any tool not on the allowlist is rejected immediately."""
    action = ActionRequest(
        action_id="act-test-01",
        tool_name="disable_firewall",
        arguments={"host": "srv-pay-prod-02", "zone": "all"},
        reason="Attacker instructed to disable firewall",
        risk_level=RiskLevel.PROHIBITED
    )
    decision = policy_gate.evaluate(action)
    assert decision.decision == PolicyDecisionStatus.DENY
    assert decision.policy_rule_id == "RULE-PROHIBITED-TOOL"
    assert "Prohibited tool 'disable_firewall'" in decision.reason


def test_invalid_arguments_rejected(policy_gate):
    """Verify that missing or malformed arguments result in denial."""
    # Missing required argument 'host'
    action_missing = ActionRequest(
        action_id="act-test-02",
        tool_name="search_mock_logs",
        arguments={},
        reason="Query logs without host"
    )
    decision = policy_gate.evaluate(action_missing)
    assert decision.decision == PolicyDecisionStatus.DENY
    assert decision.policy_rule_id == "RULE-INVALID-ARGS"

    # Malformed incident ID format
    action_malformed = ActionRequest(
        action_id="act-test-03",
        tool_name="get_incident_details",
        arguments={"incident_id": "malicious_injection'; DROP TABLE;--"},
        reason="Query incident with injection string"
    )
    decision = policy_gate.evaluate(action_malformed)
    assert decision.decision == PolicyDecisionStatus.DENY
    assert decision.policy_rule_id == "RULE-INVALID-ARGS"


def test_read_tool_allowed(policy_gate):
    """Verify that approved read-only tools are permitted without human approval."""
    action = ActionRequest(
        action_id="act-test-04",
        tool_name="search_mock_logs",
        arguments={"host": "srv-pay-prod-02", "timeframe": "1h"},
        reason="Investigate anomalous authentication events"
    )
    decision = policy_gate.evaluate(action)
    assert decision.decision == PolicyDecisionStatus.ALLOW
    assert decision.policy_rule_id == "RULE-ALLOW-EXECUTE"


def test_approval_required_for_isolation(policy_gate):
    """Verify that high-impact endpoint isolation fails closed when approval is absent."""
    action = ActionRequest(
        action_id="act-test-05",
        tool_name="simulate_endpoint_isolation",
        arguments={"host": "srv-pay-prod-02"},
        reason="Isolate compromised server"
    )
    # No approval provided
    decision = policy_gate.evaluate(action, approval_granted=False)
    assert decision.decision == PolicyDecisionStatus.APPROVAL_REQUIRED
    assert decision.policy_rule_id == "RULE-APPROVAL-MANDATORY"
    assert "requires explicit human authorization" in decision.reason


def test_approved_isolation_executes(policy_gate):
    """Verify that high-impact action is permitted when human authorization is confirmed."""
    action = ActionRequest(
        action_id="act-test-06",
        tool_name="simulate_endpoint_isolation",
        arguments={"host": "srv-pay-prod-02"},
        reason="Isolate compromised server with operator approval"
    )
    decision = policy_gate.evaluate(action, approval_granted=True)
    assert decision.decision == PolicyDecisionStatus.ALLOW
    assert decision.policy_rule_id == "RULE-APPROVAL-GRANTED"


def test_evaluate_and_dispatch_fail_closed(policy_gate, mock_adapter):
    """Verify that blocked action is never executed in the tool adapter."""
    action = ActionRequest(
        action_id="act-test-07",
        tool_name="disable_firewall",
        arguments={"host": "srv-pay-prod-02"},
        reason="Adversarial command"
    )
    decision, result = policy_gate.evaluate_and_dispatch(action, mock_adapter, approval_granted=False)
    assert decision.decision == PolicyDecisionStatus.DENY
    assert result.executed is False
    assert result.status == "blocked"
    assert result.result_summary is None


def test_evaluate_and_dispatch_allowed_action(policy_gate, mock_adapter):
    """Verify that allowed action executes properly in tool adapter."""
    action = ActionRequest(
        action_id="act-test-08",
        tool_name="create_mock_ticket",
        arguments={"title": "Investigate credential breach", "priority": "high"},
        reason="Create tracking ticket"
    )
    decision, result = policy_gate.evaluate_and_dispatch(action, mock_adapter)
    assert decision.decision == PolicyDecisionStatus.ALLOW
    assert result.executed is True
    assert result.status == "success"
    assert "TICK-MOCK" in result.result_summary["ticket_id"]


def test_extra_unrecognized_arguments_rejected(policy_gate):
    """Verify that passing unexpected extraneous arguments is strictly rejected (Finding 1)."""
    action = ActionRequest(
        action_id="act-test-extra-args",
        tool_name="search_mock_logs",
        arguments={
            "host": "srv-pay-prod-02",
            "timeframe": "1h",
            "unauthorized_flag": "exploit_payload",
            "sql_injection": "1=1"
        },
        reason="Query logs with smuggled unexpected keys"
    )
    decision = policy_gate.evaluate(action)
    assert decision.decision == PolicyDecisionStatus.DENY
    assert decision.policy_rule_id == "RULE-INVALID-ARGS"
    assert "Unrecognized argument(s)" in decision.reason
    assert "sql_injection" in decision.reason or "unauthorized_flag" in decision.reason


def test_resource_scope_rejection(policy_gate):
    """Verify that isolating a host outside authorized infrastructure scope is blocked."""
    action = ActionRequest(
        action_id="act-test-scope",
        tool_name="simulate_endpoint_isolation",
        arguments={"host": "dc01.corp.internal"},
        reason="Attempt to isolate root domain controller outside authorized scope"
    )
    decision = policy_gate.evaluate(action, approval_granted=True)
    assert decision.decision == PolicyDecisionStatus.DENY
    assert decision.policy_rule_id == "RULE-RESOURCE-OUT-OF-SCOPE"
    assert "outside authorized infrastructure remediation scope" in decision.reason


def test_approval_token_action_mismatch_rejected(policy_gate):
    """Verify that an approval token bound to Action A cannot be replayed for Action B."""
    from src.schemas import ApprovalToken
    token_for_action_a = ApprovalToken(
        token_id="tok-valid-01",
        action_id="act-test-09-A",
        tool_name="simulate_endpoint_isolation",
        approver_id="secops_lead",
        approved=True
    )
    action_b = ActionRequest(
        action_id="act-test-09-B",
        tool_name="simulate_endpoint_isolation",
        arguments={"host": "srv-pay-prod-02"},
        reason="Action B attempting to use Action A's approval"
    )
    decision = policy_gate.evaluate(action_b, approval=token_for_action_a)
    assert decision.decision == PolicyDecisionStatus.DENY
    assert decision.policy_rule_id == "RULE-APPROVAL-REPLAY-PREVENTED"
    assert "Approval token action mismatch" in decision.reason


def test_approval_token_consumed_cannot_be_replayed(policy_gate, mock_adapter):
    """Verify that a single-use approval token cannot be reused once consumed."""
    from src.schemas import ApprovalToken
    single_use_token = ApprovalToken(
        token_id="tok-single-use",
        action_id="act-test-10",
        tool_name="simulate_endpoint_isolation",
        approver_id="secops_lead",
        approved=True,
        consumed=False
    )
    action = ActionRequest(
        action_id="act-test-10",
        tool_name="simulate_endpoint_isolation",
        arguments={"host": "srv-pay-prod-02"},
        reason="First isolation attempt"
    )
    # First dispatch consumes the token
    decision1, res1 = policy_gate.evaluate_and_dispatch(action, mock_adapter, approval=single_use_token)
    assert decision1.decision == PolicyDecisionStatus.ALLOW
    assert res1.executed is True
    assert single_use_token.consumed is True

    # Replay attempt with same token must be rejected
    decision2, res2 = policy_gate.evaluate_and_dispatch(action, mock_adapter, approval=single_use_token)
    assert decision2.decision == PolicyDecisionStatus.DENY
    assert decision2.policy_rule_id == "RULE-APPROVAL-ALREADY-CONSUMED"
    assert res2.executed is False
    assert res2.status == "blocked"


def test_read_advisory_allowed(policy_gate):
    """Verify that read_advisory with valid GHSA ID is permitted."""
    action = ActionRequest(
        action_id="act-test-adv",
        tool_name="read_advisory",
        arguments={"advisory_id": "GHSA-558c-9hv2-4prj"},
        reason="Retrieve advisory details"
    )
    decision = policy_gate.evaluate(action)
    assert decision.decision == PolicyDecisionStatus.ALLOW
    assert decision.policy_rule_id == "RULE-ALLOW-EXECUTE"


def test_search_mock_inventory_allowed(policy_gate):
    """Verify that search_mock_inventory with valid package name is permitted."""
    action = ActionRequest(
        action_id="act-test-inv",
        tool_name="search_mock_inventory",
        arguments={"package_name": "virtualenv"},
        reason="Search package inventory"
    )
    decision = policy_gate.evaluate(action)
    assert decision.decision == PolicyDecisionStatus.ALLOW
    assert decision.policy_rule_id == "RULE-ALLOW-EXECUTE"

