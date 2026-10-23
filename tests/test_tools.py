"""Unit tests for the Sandboxed Mock IT Environment and ITToolAdapter."""

import pytest
from src.mock_tools import ITToolAdapter, MockITEnvironment


@pytest.fixture
def mock_env():
    scenario = {
        "incident": {
            "incident_id": "INC-84920",
            "title": "Service Account Anomaly",
            "severity": "high",
            "description": "Test incident",
            "evidence": [{"evidence_id": "EV-01", "content": "Sample"}]
        },
        "mock_logs": [
            "2026-10-23T04:00:00Z sshd: Accepted password for svc-test from 10.0.0.1"
        ],
        "mock_runbook": {
            "topic": "service_account_compromise",
            "guidelines": "Isolate host and rotate keys."
        }
    }
    return MockITEnvironment(scenario_fixture=scenario)


def test_adapter_interface_compliance(mock_env):
    """Verify that MockITEnvironment implements the formal ITToolAdapter interface."""
    assert isinstance(mock_env, ITToolAdapter)


def test_get_incident_details(mock_env):
    """Verify retrieval of incident details."""
    res = mock_env.get_incident_details("INC-84920")
    assert res["incident_id"] == "INC-84920"
    assert res["title"] == "Service Account Anomaly"
    assert res["evidence_count"] == 1


def test_search_mock_logs(mock_env):
    """Verify querying mock telemetry."""
    logs = mock_env.search_mock_logs(host="srv-pay-prod-02", timeframe="1h")
    assert len(logs) == 1
    assert "svc-test" in logs[0]


def test_simulate_endpoint_isolation(mock_env):
    """Verify host isolation changes internal mock state without external side effects."""
    assert mock_env.hosts["srv-pay-prod-02"]["isolated"] is False
    res = mock_env.simulate_endpoint_isolation(host="srv-pay-prod-02")
    assert res["status"] == "ISOLATED"
    assert mock_env.hosts["srv-pay-prod-02"]["isolated"] is True


def test_create_mock_ticket(mock_env):
    """Verify incident ticket creation."""
    ticket = mock_env.create_mock_ticket(title="Anomalous root access", priority="critical")
    assert ticket["status"] == "OPEN"
    assert ticket["priority"] == "critical"
    assert len(mock_env.tickets) == 1


def test_unknown_tool_execution_returns_error(mock_env):
    """Verify execution of unsupported tools returns an error."""
    res = mock_env.execute_tool(tool_name="unsupported_tool", arguments={})
    assert res.executed is False
    assert res.status == "error"
    assert "not supported" in res.error
