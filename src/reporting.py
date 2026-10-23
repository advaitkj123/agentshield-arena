"""Reporting module for AgentShield Arena.

Generates structured append-only JSONL execution traces and human-readable Markdown post-mortems
for both IT security incidents and vulnerability triage workflows.
"""

import json
import os
from typing import Any, Dict, List
from src.schemas import EvaluationResult


class ReportGenerator:
    """Produces audit trails and analyst-facing incident post-mortems."""

    @staticmethod
    def export_audit_trail_jsonl(audit_events: List[Dict[str, Any]], filepath: str, append: bool = True) -> None:
        """Serialize audit events to a JSONL file.

        Defaults to append mode ('a') to preserve forensic audit history across consecutive runs.
        """
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        mode = "a" if append else "w"
        with open(filepath, mode, encoding="utf-8") as f:
            for event in audit_events:
                f.write(json.dumps(event) + "\n")

    @staticmethod
    def load_audit_trail_jsonl(filepath: str, run_id: str = None) -> List[Dict[str, Any]]:
        """Load audit events from a JSONL file, optionally filtering by run_id."""
        if not os.path.exists(filepath):
            return []
        events = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                    if run_id is None or evt.get("run_id") == run_id:
                        events.append(evt)
                except json.JSONDecodeError:
                    continue
        return events

    @staticmethod
    def generate_markdown_report(
        incident_summary: Dict[str, Any],
        eval_result: EvaluationResult,
        filepath: str
    ) -> str:
        """Format a comprehensive incident or vulnerability triage report and write to disk."""
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        report_id = incident_summary.get("incident_id") or incident_summary.get("advisory_id") or "UNKNOWN"
        workflow_type = incident_summary.get("workflow_type", "INCIDENT INVESTIGATION")
        
        md_lines = [
            f"# {workflow_type} REPORT: {report_id}",
            "",
            "## 1. Executive Summary",
            f"* **Title:** {incident_summary.get('title', 'N/A')}",
            f"* **Assessed Severity:** {str(incident_summary.get('severity', 'HIGH')).upper()}",
            f"* **Impacted Asset / Package:** `{incident_summary.get('affected_host') or incident_summary.get('affected_package', 'N/A')}`",
            f"* **Triage / Containment Status:** `{incident_summary.get('containment_status') or incident_summary.get('triage_status', 'CONTAINED')}`",
        ]

        if "data_source" in incident_summary:
            md_lines.append(f"* **Advisory Data Source:** `{incident_summary.get('data_source')}`")

        md_lines.extend([
            "",
            "## 2. Root Cause Analysis & Technical Findings",
            incident_summary.get("root_cause_analysis", "Investigation concluded."),
            "",
            "## 3. Correlated Evidence & Citations",
        ])

        for cite in incident_summary.get("evidence_citations", []):
            md_lines.append(f"* {cite}")

        md_lines.extend([
            "",
            "## 4. Policy Gate Enforcement & Intercepted Attacks",
        ])

        blocked = incident_summary.get("blocked_adversarial_attempts", [])
        if blocked:
            for b in blocked:
                md_lines.append(f"* **BLOCKED:** {b}")
        else:
            md_lines.append("* No unauthorized actions were attempted.")

        md_lines.extend([
            "",
            "## 5. Security & Utility Evaluation Metrics",
            f"* **Task Completion Rate (TCR):** {eval_result.metrics.get('task_completion_rate', '100%')}",
            f"* **Unauthorized Action Execution Rate (UAER):** {eval_result.metrics.get('unauthorized_action_execution_rate', '0.0%')} *(Target: 0.0%)*",
            f"* **Attack Success Rate (ASR):** {eval_result.metrics.get('attack_success_rate', '0.0%')} *(Target: 0.0%)*",
            f"* **False-Block Rate (FBR):** {eval_result.metrics.get('false_block_rate', '0.0%')}",
            f"* **Audit Completeness (ACR):** {eval_result.metrics.get('audit_completeness_rate', '100%')}",
            "",
            "## 6. Recommended Next Steps",
        ])

        for step in incident_summary.get("recommended_next_steps", []):
            md_lines.append(f"1. {step}")

        content = "\n".join(md_lines) + "\n"

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        return content
