"""Multi-scenario benchmarking runner for AgentShield Arena.

Executes all incident scenarios in data/incident_scenarios/ through the full
policy-gated pipeline and aggregates metrics into a comparative benchmark report.
Supports both defended and unsafe baseline modes for empirical comparison.
"""

import json
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.main import run_incident_orchestration


SCENARIOS_DIR = "data/incident_scenarios"


def discover_scenarios(scenarios_dir: str = SCENARIOS_DIR) -> List[str]:
    """Discover all JSON scenario files in the scenarios directory."""
    if not os.path.isdir(scenarios_dir):
        return []
    return sorted([
        os.path.join(scenarios_dir, f)
        for f in os.listdir(scenarios_dir)
        if f.endswith(".json")
    ])


def run_benchmark(
    scenarios_dir: str = SCENARIOS_DIR,
    include_unsafe_baseline: bool = True,
    audit_log_path: str = "outputs/benchmark_audit_trail.jsonl",
    report_dir: str = "outputs/benchmark_reports",
    progress_callback: Optional[Callable[[int, int, Optional[str]], None]] = None,
) -> Dict[str, Any]:
    """Execute all discovered scenarios through the full pipeline.

    progress_callback(completed, total, current_scenario_id) is invoked as each
    scenario starts and once more on completion — used by the dashboard's
    background benchmark job to report real progress.

    Returns aggregated benchmark results dictionary.
    """
    scenarios = discover_scenarios(scenarios_dir)
    if not scenarios:
        print(f"[-] No scenario files found in '{scenarios_dir}'.")
        return {}

    os.makedirs(report_dir, exist_ok=True)
    # Clear the benchmark audit log for a fresh run
    if os.path.exists(audit_log_path):
        os.remove(audit_log_path)

    print(f"\n{'='*70}")
    print(f" AgentShield Arena: Multi-Scenario Security Benchmark")
    print(f" Scenarios discovered: {len(scenarios)}")
    print(f"{'='*70}\n")

    results = []

    for scenario_path in scenarios:
        scenario_name = os.path.basename(scenario_path).replace(".json", "")

        # Load scenario metadata for display
        try:
            with open(scenario_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            s_meta = meta.get("scenario_metadata", {})
            scenario_id = s_meta.get("scenario_id", scenario_name)
            display_name = s_meta.get("name", scenario_name)
        except Exception:
            scenario_id = scenario_name
            display_name = scenario_name

        if progress_callback:
            progress_callback(len(results), len(scenarios), scenario_id)

        print(f"\n{'-'*70}")
        print(f" SCENARIO: {scenario_id}")
        print(f" Name    : {display_name}")
        print(f"{'-'*70}")

        scenario_result = {
            "scenario_id": scenario_id,
            "scenario_name": display_name,
            "scenario_path": scenario_path,
            "defended": None,
            "unsafe_baseline": None
        }

        # -- Run 1: Defended Mode ----------------------------------------------
        print(f"\n [Defended Mode]")
        report_path = os.path.join(report_dir, f"{scenario_name}_defended.md")
        t0 = time.perf_counter()
        try:
            defended_exit = run_incident_orchestration(
                scenario_path=scenario_path,
                auto_approve=True,
                interactive_approval=False,
                disable_policy_gate=False,
                audit_log_path=audit_log_path,
                report_path=report_path
            )
        except Exception as e:
            print(f"  [ERROR] Defended run failed: {e}")
            defended_exit = -1
        elapsed_defended = time.perf_counter() - t0

        scenario_result["defended"] = {
            "exit_code": defended_exit,
            "passed": (defended_exit == 0),
            "triage_latency_s": round(elapsed_defended, 3)
        }

        # -- Run 2: Unsafe Baseline Mode --------------------------------------
        if include_unsafe_baseline:
            print(f"\n [Unsafe Baseline Mode]")
            baseline_report = os.path.join(report_dir, f"{scenario_name}_unsafe.md")
            t0 = time.perf_counter()
            try:
                unsafe_exit = run_incident_orchestration(
                    scenario_path=scenario_path,
                    auto_approve=True,
                    interactive_approval=False,
                    disable_policy_gate=True,
                    audit_log_path=audit_log_path,
                    report_path=baseline_report
                )
            except Exception as e:
                print(f"  [ERROR] Unsafe baseline run failed: {e}")
                unsafe_exit = -1
            elapsed_unsafe = time.perf_counter() - t0

            scenario_result["unsafe_baseline"] = {
                "exit_code": unsafe_exit,
                "breached": (unsafe_exit != 0),
                "triage_latency_s": round(elapsed_unsafe, 3)
            }

        results.append(scenario_result)

    if progress_callback:
        progress_callback(len(results), len(scenarios), None)

    # -- Aggregate Summary ------------------------------------------------------
    total = len(results)
    defended_passes = sum(1 for r in results if r["defended"] and r["defended"]["passed"])
    unsafe_breaches = sum(1 for r in results if r["unsafe_baseline"] and r["unsafe_baseline"]["breached"])
    avg_latency = (
        sum(r["defended"]["triage_latency_s"] for r in results if r["defended"])
        / max(total, 1)
    )

    aggregate = {
        "total_scenarios": total,
        "defended_pass_rate": f"{(defended_passes / max(total, 1)) * 100:.1f}%",
        "defended_passes": defended_passes,
        "defended_failures": total - defended_passes,
        "unsafe_breach_rate": f"{(unsafe_breaches / max(total, 1)) * 100:.1f}%" if include_unsafe_baseline else "N/A",
        "avg_triage_latency_s": round(avg_latency, 3),
        "scenarios": results
    }

    print(f"\n{'='*70}")
    print(f" BENCHMARK AGGREGATE RESULTS")
    print(f"{'='*70}")
    print(f" Total Scenarios Evaluated  : {total}")
    print(f" Defended Pass Rate         : {aggregate['defended_pass_rate']} ({defended_passes}/{total})")
    print(f" Unsafe Baseline Breach Rate: {aggregate['unsafe_breach_rate']}")
    print(f" Average Triage Latency     : {aggregate['avg_triage_latency_s']}s")
    print(f"{'='*70}\n")

    # Write aggregate JSON report
    agg_path = os.path.join(report_dir, "benchmark_summary.json")
    with open(agg_path, "w", encoding="utf-8") as f:
        json.dump(aggregate, f, indent=2)
    print(f"[+] Benchmark summary written to: {agg_path}")
    print(f"[+] Individual reports written to: {report_dir}/")

    return aggregate


if __name__ == "__main__":
    run_benchmark()
