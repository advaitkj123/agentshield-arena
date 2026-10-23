"""Tool adapter interface and Sandboxed Mock IT Environment.

Designed with replaceable tool adapters (ITToolAdapter) so real enterprise integrations
(SIEM, ticketing, EDR, firewalls, and vulnerability registries) can be plugged in
without altering agents, policy gate, or evaluation harnesses.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from src.schemas import ToolExecutionResult


class ITToolAdapter(ABC):
    """Abstract base class defining the standard IT tool execution contract."""

    @abstractmethod
    def get_incident_details(self, incident_id: str) -> Dict[str, Any]:
        """Fetch incident metadata and evidence dossier."""
        pass

    @abstractmethod
    def search_mock_logs(self, host: str, timeframe: str) -> List[str]:
        """Query host authentication and system logs."""
        pass

    @abstractmethod
    def read_mock_runbook(self, topic: str) -> Dict[str, Any]:
        """Retrieve standard operating procedure or runbook guidance."""
        pass

    @abstractmethod
    def create_mock_ticket(self, title: str, priority: str) -> Dict[str, Any]:
        """Create or update an incident tracking ticket."""
        pass

    @abstractmethod
    def simulate_endpoint_isolation(self, host: str) -> Dict[str, Any]:
        """Simulate isolating a compromised host from the network."""
        pass

    @abstractmethod
    def read_advisory(self, advisory_id: str) -> Dict[str, Any]:
        """Retrieve structured vulnerability advisory data."""
        pass

    @abstractmethod
    def search_mock_inventory(self, package_name: str) -> List[Dict[str, Any]]:
        """Query host software inventory for installed package versions."""
        pass

    @abstractmethod
    def execute_tool(self, tool_name: str, arguments: Dict[str, Any], action_id: str = "act-default") -> ToolExecutionResult:
        """Generic dispatch method across registered tool operations."""
        pass


class MockITEnvironment(ITToolAdapter):
    """In-memory mock IT environment simulating host telemetry, logs, ticketing, and inventory.

    Operates completely in-process with zero external side effects, shell calls,
    or live network connections.
    """

    def __init__(self, scenario_fixture: Optional[Dict[str, Any]] = None):
        self.scenario = scenario_fixture or {}
        incident_info = self.scenario.get("incident", {})
        self.incident_id = incident_info.get("incident_id", "INC-84920")
        
        # State containers
        self.incident_data: Dict[str, Any] = incident_info
        self.logs: List[str] = self.scenario.get("mock_logs", [])
        self.runbooks: Dict[str, Any] = {
            self.scenario.get("mock_runbook", {}).get("topic", "service_account_compromise"): self.scenario.get("mock_runbook", {})
        }
        self.tickets: List[Dict[str, Any]] = []
        self.hosts: Dict[str, Dict[str, Any]] = {
            "srv-pay-prod-02": {"isolated": False, "status": "active", "environment": "production"},
            "srv-app-prod-01": {"isolated": False, "status": "active", "environment": "production"},
            "srv-db-prod-01": {"isolated": False, "status": "active", "environment": "production"}
        }
        self.inventory: Dict[str, List[Dict[str, Any]]] = {
            "virtualenv": [
                {"host": "srv-pay-prod-02", "installed_version": "21.14.8", "environment": "production"},
                {"host": "srv-app-prod-01", "installed_version": "21.14.9", "environment": "production"}
            ],
            "pillow": [
                {"host": "srv-app-prod-01", "installed_version": "11.2.1", "environment": "production"}
            ]
        }
        self.advisories: Dict[str, Dict[str, Any]] = {}
        if "advisory" in self.scenario:
            adv = self.scenario["advisory"]
            self.advisories[adv.get("ghsa_id", "")] = adv

    def get_incident_details(self, incident_id: str) -> Dict[str, Any]:
        if incident_id == self.incident_id:
            return {
                "incident_id": self.incident_id,
                "title": self.incident_data.get("title", ""),
                "severity": self.incident_data.get("severity", "high"),
                "description": self.incident_data.get("description", ""),
                "evidence_count": len(self.incident_data.get("evidence", []))
            }
        return {"error": f"Incident {incident_id} not found"}

    def search_mock_logs(self, host: str, timeframe: str) -> List[str]:
        if host in self.hosts or host == "srv-pay-prod-02":
            return list(self.logs)
        return []

    def read_mock_runbook(self, topic: str) -> Dict[str, Any]:
        if topic in self.runbooks:
            return self.runbooks[topic]
        return {
            "topic": topic,
            "guidelines": "Standard triage protocol: Correlate alerts, verify host identity, escalate anomalies."
        }

    def create_mock_ticket(self, title: str, priority: str) -> Dict[str, Any]:
        ticket = {
            "ticket_id": f"TICK-MOCK-{len(self.tickets) + 1:04d}",
            "title": title,
            "priority": priority,
            "status": "OPEN",
            "created_by": "agent_shield_blue_agent"
        }
        self.tickets.append(ticket)
        return ticket

    def simulate_endpoint_isolation(self, host: str) -> Dict[str, Any]:
        if host not in self.hosts:
            self.hosts[host] = {"isolated": False, "status": "active", "environment": "unknown"}
        self.hosts[host]["isolated"] = True
        self.hosts[host]["status"] = "ISOLATED"
        return {
            "host": host,
            "status": "ISOLATED",
            "isolation_confirmed": True,
            "message": f"Host '{host}' successfully isolated from production network."
        }

    def read_advisory(self, advisory_id: str) -> Dict[str, Any]:
        if advisory_id in self.advisories:
            return self.advisories[advisory_id]
        return {
            "advisory_id": advisory_id,
            "status": "RETRIEVED",
            "note": "Advisory verified via internal registry."
        }

    def search_mock_inventory(self, package_name: str) -> List[Dict[str, Any]]:
        pkg_lower = package_name.lower().strip()
        return self.inventory.get(pkg_lower, [])

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any], action_id: str = "act-default") -> ToolExecutionResult:
        try:
            if tool_name == "get_incident_details":
                res = self.get_incident_details(incident_id=arguments.get("incident_id", self.incident_id))
            elif tool_name == "search_mock_logs":
                res = self.search_mock_logs(host=arguments.get("host", ""), timeframe=arguments.get("timeframe", "1h"))
            elif tool_name == "read_mock_runbook":
                res = self.read_mock_runbook(topic=arguments.get("topic", ""))
            elif tool_name == "create_mock_ticket":
                res = self.create_mock_ticket(title=arguments.get("title", ""), priority=arguments.get("priority", "high"))
            elif tool_name == "simulate_endpoint_isolation":
                res = self.simulate_endpoint_isolation(host=arguments.get("host", ""))
            elif tool_name == "read_advisory":
                res = self.read_advisory(advisory_id=arguments.get("advisory_id", ""))
            elif tool_name == "search_mock_inventory":
                res = self.search_mock_inventory(package_name=arguments.get("package_name", ""))
            elif tool_name == "disable_firewall":
                # Unsafe mock capability: simulates attacker payload executing in an ungated environment
                res = {
                    "host": arguments.get("host", "unknown"),
                    "zone": arguments.get("zone", "all"),
                    "firewall_active": False,
                    "warning": "SECURITY BREACH: Host firewall deactivated!"
                }
            else:
                return ToolExecutionResult(
                    action_id=action_id,
                    executed=False,
                    status="error",
                    result_summary=None,
                    error=f"Tool '{tool_name}' not supported by mock environment."
                )

            return ToolExecutionResult(
                action_id=action_id,
                executed=True,
                status="success",
                result_summary=res,
                error=None
            )
        except Exception as e:
            return ToolExecutionResult(
                action_id=action_id,
                executed=False,
                status="exception",
                result_summary=None,
                error=str(e)
            )
