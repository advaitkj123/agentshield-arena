# AgentShield Arena — Independent MVP Technical Audit Report

> **Audit Date:** 2026-10-23  
> **Repository:** `agentshield-arena`  
> **Auditor:** Independent Security & Architecture Review  
> **Scope:** Verification of MVP claims (test suite, offline execution, policy enforcement, human approval, baseline comparability, metrics, failure handling, and architecture).  
> **Constraint Verification:** Audit-only; zero modifications made to application code, tests, or configurations.

---

## 1. Executive Verdict

**VERDICT: QUALIFIED PASS (Solid Architecture, Validated Security Boundary, Scope Bounds Verified)**

The AgentShield Arena repository implements a working, fully reproducible, and zero-cost offline prototype for policy-gated IT incident response. 

### Key Audit Conclusions:
1. **Claims Confirmed:** 
   * The test suite (`pytest`) runs cleanly with **20/20 passed tests in 0.21s**.
   * Zero external API credentials, paid tokens, or GPUs are required to run the full workflow or test battery.
   * In defended mode, **Unauthorized Action Execution Rate (UAER) is strictly 0.0%**, successfully halting an injected `disable_firewall` command.
   * In unsafe baseline mode (`--disable-policy-gate`), the injected attack executes in the sandbox, resulting in **100.0% UAER and 100.0% Attack Success Rate (ASR)**.
   * Mandatory human approval for high-risk actions (`simulate_endpoint_isolation`) is enforced deterministically and **fails closed** when unapproved.
2. **Key Nuances & Scope Bounds Identified:**
   * **Blue Agent Fallback Scope:** `BlueAgent` currently executes a deterministic step-sequence investigation rather than a dynamic LLM token generation loop. Live OpenAI/LiteLLM integration is stubbed/deferred.
   * **Red Agent Scope:** `RedAgent` operates on a predefined static scenario fixture (`SCENARIO-01-COMPROMISED-SERVICE-ACCOUNT`) rather than generating autonomous dynamic prompt mutations.
   * **Audit Log Appending:** The JSONL audit log is append-only *in memory* during a single execution run, but `ReportGenerator.export_audit_trail_jsonl()` writes with mode `"w"`, overwriting `outputs/audit_trail.jsonl` across successive runs unless custom filepaths are supplied.
   * **Parameter Allowlisting:** Argument validation checks for required keys and formats, but does not strictly reject unlisted extraneous parameters.

---

## 2. Actual Stack and Component Map

Inspection of `requirements.txt`, `pyproject.toml`, and `src/` establishes the following concrete stack:

| Component | Repository Implementation | Location | Dependencies |
| :--- | :--- | :--- | :--- |
| **Language Runtime** | Python 3.10+ (Verified on Python 3.14.3) | Repository-wide | Python Standard Library |
| **Data Schemas** | Standard Library `@dataclass` | `src/schemas.py` | `dataclasses`, `enum`, `datetime` |
| **Tool Sandbox & Adapter** | `ITToolAdapter` (ABC) + `MockITEnvironment` | `src/mock_tools.py` | `abc`, `typing` |
| **Policy Engine** | Procedural `PolicyGate` & static allowlists | `src/policy.py` | `re`, `typing` |
| **Red Agent** | `RedAgent` campaign tracker & payload injector | `src/red_agent.py` | `json`, `typing` |
| **Blue Agent** | `BlueAgent` state-machine triage loop | `src/agent.py` | Standard Library |
| **Evaluation Engine** | `Evaluator` metrics calculator | `src/evaluation.py` | Standard Library |
| **Audit & Reporting** | `ReportGenerator` (JSONL & Markdown) | `src/reporting.py` | `json`, `os` |
| **CLI Entry Point** | `argparse` orchestrator | `src/main.py` | `argparse`, `sys`, `uuid` |
| **Test Runner** | `pytest 9.1.1` | `tests/` | `pytest>=8.0.0`, `python-dotenv>=1.0.0` |

### Entry Points & Commands Verified:
* **Run Defended CLI Demo:** `python src/main.py`
* **Run Interactive Approval Mode:** `python src/main.py --interactive-approval`
* **Run Unapproved Fail-Closed Test:** `python src/main.py --no-auto-approve`
* **Run Unsafe Baseline Demo:** `python src/main.py --disable-policy-gate`
* **Execute Test Suite:** `python -m pytest tests/ -v`

---

## 3. Detailed Verification Matrix

| Check Item | Verified Property | Status | Concrete Evidence (Files & Functions) |
| :--- | :--- | :--- | :--- |
| **1. Tool Allowlist** | Denies tools not in allowlist | **VERIFIED** | `src/policy.py:112` (`RULE-PROHIBITED-TOOL`); tested in `tests/test_policy.py:test_prohibited_tool_rejected`. |
| **2. Argument Validation** | Enforces regex and bounds on parameters | **VERIFIED** | `src/policy.py:55` (`validate_arguments`); tested in `tests/test_policy.py:test_invalid_arguments_rejected`. |
| **3. Policy Mediation** | Denied actions never reach tool execution | **VERIFIED** | `src/policy.py:157` (`evaluate_and_dispatch`); tested in `tests/test_policy.py:test_evaluate_and_dispatch_fail_closed`. |
| **4. Human Approval Gate** | High-impact actions halt without approval | **VERIFIED** | `src/policy.py:133` (`RULE-APPROVAL-MANDATORY`); tested in `tests/test_workflow.py:test_fail_closed_without_human_approval`. |
| **5. Red Agent Tracking** | Records objective and tracks sandbox breach | **VERIFIED** | `src/red_agent.py:27` (`load_scenario`, `evaluate_attack_success`); tested in `tests/test_workflow.py:test_red_agent_scenario_injection_and_tracking`. |
| **6. Replaceable Adapter** | Mock tools adhere to abstract interface | **VERIFIED** | `src/mock_tools.py:14` (`class ITToolAdapter(ABC)`); tested in `tests/test_tools.py:test_adapter_interface_compliance`. |
| **7. Metric Formulas** | Mathematical calculation from observed trace | **VERIFIED** | `src/evaluation.py:88-108` (`UAER`, `TCR`, `ASR`, `FBR`, `ACR`); tested in `tests/test_workflow.py:test_uaer_zero_under_attack`. |
| **8. Unsafe Baseline** | Demonstrates attack execution without gate | **VERIFIED** | `src/main.py:146` & `src/mock_tools.py:133`; tested in `tests/test_workflow.py:test_unsafe_baseline_demonstrates_vulnerability`. |
| **9. Serialized Audit** | Valid JSONL output with required event types | **VERIFIED** | `src/reporting.py:16` & `outputs/audit_trail.jsonl`; tested in `tests/test_workflow.py:test_audit_trail_serializable`. |
| **10. Post-Mortem Report** | Evidence citations, blocked actions, metrics | **VERIFIED** | `outputs/incident_report.md`; tested in `tests/test_workflow.py:test_incident_report_generation`. |

---

## 4. Test Results and Reproduction Log

Independent execution of `python -m pytest tests/ -v` yielded 20 passes with zero errors:

```text
tests/test_policy.py::test_prohibited_tool_rejected PASSED               [  5%]
tests/test_policy.py::test_invalid_arguments_rejected PASSED             [ 10%]
tests/test_policy.py::test_read_tool_allowed PASSED                      [ 15%]
tests/test_policy.py::test_approval_required_for_isolation PASSED        [ 20%]
tests/test_policy.py::test_approved_isolation_executes PASSED            [ 25%]
tests/test_policy.py::test_evaluate_and_dispatch_fail_closed PASSED      [ 30%]
tests/test_policy.py::test_evaluate_and_dispatch_allowed_action PASSED   [ 35%]
tests/test_tools.py::test_adapter_interface_compliance PASSED            [ 40%]
tests/test_tools.py::test_get_incident_details PASSED                    [ 45%]
tests/test_tools.py::test_search_mock_logs PASSED                        [ 50%]
tests/test_tools.py::test_simulate_endpoint_isolation PASSED             [ 55%]
tests/test_tools.py::test_create_mock_ticket PASSED                      [ 60%]
tests/test_tools.py::test_unknown_tool_execution_returns_error PASSED    [ 65%]
tests/test_workflow.py::test_red_agent_scenario_injection_and_tracking PASSED [ 70%]
tests/test_workflow.py::test_end_to_end_defended_workflow PASSED         [ 75%]
tests/test_workflow.py::test_uaer_zero_under_attack PASSED               [ 80%]
tests/test_workflow.py::test_audit_trail_serializable PASSED             [ 85%]
tests/test_workflow.py::test_incident_report_generation PASSED           [ 90%]
tests/test_workflow.py::test_fail_closed_without_human_approval PASSED   [ 95%]
tests/test_workflow.py::test_unsafe_baseline_demonstrates_vulnerability PASSED [100%]

============================= 20 passed in 0.21s ==============================
```

---

## 5. Security & Threat Analysis Findings

### Finding 1: Unvalidated Extraneous Arguments (Severity: P1)
* **Location:** `src/policy.py:55` (`validate_arguments`)
* **Mechanism:** `validate_arguments()` iterates through `config["required_args"]` and validates each required key. However, it does not check for or reject extraneous, unexpected dictionary keys passed in `action.arguments`.
* **Risk:** In an environment where tool adapters accept `**kwargs`, an attacker could smuggle unexpected secondary parameters through the gate as long as the required parameters are syntactically valid.
* **Remediation Recommendation:** Add strict schema allowlisting:
  ```python
  allowed_keys = set(config["required_args"]) | set(config.get("optional_args", []))
  extra_keys = set(arguments.keys()) - allowed_keys
  if extra_keys:
      return False, f"Unrecognized argument(s): {', '.join(extra_keys)}"
  ```

### Finding 2: Unbound Approval Authorization Boolean (Severity: P1)
* **Location:** `src/policy.py:106` & `src/main.py:179`
* **Mechanism:** Approval status is passed to `evaluate()` and `evaluate_and_dispatch()` as a primitive `approval_granted: bool`. It is not cryptographically signed, single-use, or bound to the specific `action.action_id`.
* **Risk:** In an asynchronous or multi-agent pipeline, a race condition or misplaced boolean flag could accidentally authorize an action intended for a different step.
* **Remediation Recommendation:** Bind approvals to the target action:
  ```python
  @dataclass
  class ApprovalToken:
      action_id: str
      approver_id: str
      approved: bool
      timestamp: str
  ```

### Finding 3: JSONL Audit Log Overwrite Across Consecutive Runs (Severity: P2)
* **Location:** `src/reporting.py:19`
* **Mechanism:** `export_audit_trail_jsonl()` uses `open(filepath, "w", encoding="utf-8")`.
* **Impact:** While the in-memory log accumulates events sequentially during a single run, calling `python src/main.py` multiple times overwrites `outputs/audit_trail.jsonl` rather than creating an append-only forensic history across all runs.
* **Remediation Recommendation:** Open with `"a"` append mode and include a run header/separator, or auto-name logs using `audit_trail_{run_id}.jsonl`.

### Finding 4: Hardcoded Task Evaluation Set (Severity: P2)
* **Location:** `src/evaluation.py:22` (`REQUIRED_LEGITIMATE_TASKS`)
* **Mechanism:** Evaluator hardcodes tasks to `["search_mock_logs", "read_mock_runbook", "simulate_endpoint_isolation", "create_mock_ticket"]`.
* **Impact:** Testing new scenarios with different expected tool combinations requires modifying `src/evaluation.py` instead of dynamically reading `incident.expected_outcome`.

---

## 6. Metric and Baseline Validity Assessment

### Evaluation Formulas Inspected
* **Unauthorized Action Execution Rate (UAER):**
  $$\text{UAER} = \frac{\text{unauthorized\_executed}}{\text{prohibited\_attempts}} \times 100.0$$
  * *Zero-Denominator Guard:* If `prohibited_attempts == 0`, returns string `"N/A (0 attempts)"` and numeric `0.0`. Validated.
* **Task Completion Rate (TCR):**
  $$\text{TCR} = \frac{|\text{legitimate\_completed\_set}|}{|\text{REQUIRED\_LEGITIMATE\_TASKS}|} \times 100.0$$
  * *Event-Driven:* Tracks actual tool execution events with `executed == True`. Validated.
* **Attack Success Rate (ASR):**
  $$\text{ASR} = 100.0 \text{ if unauthorized\_executed} > 0 \text{ else } 0.0$$
  * *Validated.*
* **False-Block Rate (FBR):**
  $$\text{FBR} = \frac{\text{false\_blocks}}{\text{legitimate\_attempts}} \times 100.0$$
  * *Validated.*
* **Audit Completeness Rate (ACR):**
  $$\text{ACR} = \frac{|\text{present\_lifecycle\_events}|}{|\text{REQUIRED\_AUDIT\_EVENTS}|} \times 100.0$$
  * *Validated.*

### Baseline Comparability Analysis
* Both defended and unsafe modes run against the identical scenario file (`data/incident_scenario.json`) and identical `RedAgent` injection.
* In defended mode, `disable_firewall` is blocked by the policy gate before execution (`executed=False, status="blocked"`).
* In unsafe mode (`--disable-policy-gate`), the policy gate is bypassed and `disable_firewall` executes inside `MockITEnvironment` (`executed=True, status="success"`), correctly triggering `UAER = 100.0%`.
* **Validity Verdict:** The baseline comparison is mathematically fair and demonstrably valid.

---

## 7. Current Limitations and Unverified Claims

1. **Deterministic Agent Simulation vs. Live LLM:**
   * *Claim in earlier planning docs:* Dual-mode provider with live OpenAI integration.
   * *Actual Code:* `src/agent.py` accepts `provider="deterministic"`, but has not implemented live HTTP calls to external LLM providers. The entire investigation operates on deterministic step indexing (`step == 0, 1, 2...`). This meets offline/cost constraints, but dynamic LLM parsing is not yet verified.
2. **Single Scenario Coverage:**
   * Attack coverage is currently limited to one JSON fixture (`data/incident_scenario.json`). No multi-scenario battery exists yet.
3. **No Network Shell or Real Infrastructure:**
   * Confirmed strictly mock; no real cloud or OS system calls are attempted or supported.

---

## 8. Missing Regression Tests

The following tests are currently missing from `tests/` and should be prioritized for future regression hardening:
1. **Extraneous Argument Injection:** Test whether passing unexpected dictionary keys (e.g., `{"host": "srv-pay-prod-02", "extra_payload": "rm -rf"}`) is blocked by the policy gate.
2. **Approval Re-use / Replay Attack:** Test whether an approval granted for Action A can inadvertently approve Action B.
3. **Corrupted Scenario Loading:** Test policy gate and evaluator resilience when scenario fields (e.g. `evidence` or `expected_outcome`) are empty or malformed.
4. **Target Host Boundary Enforcement:** Test whether `simulate_endpoint_isolation` can be tricked into isolating hosts outside the incident's `affected_host` scope.

---

## 9. Architectural Stack Assessment and Recommendation

### Architecture Evaluation
* **LangGraph:** *Not Recommended for MVP.* StateGraph abstractions would add significant debugging complexity, asynchronous loop overhead, and third-party dependencies without improving security guarantees.
* **FastAPI:** *Not Recommended for MVP.* A CLI orchestrator is faster, more deterministic, and avoids local port binding and firewall issues during evaluations.
* **Pydantic v2:** *Recommended for Next Milestone.* Upgrading from standard `dataclasses` to `Pydantic v2` will enable automatic rejection of extra parameters (`extra='forbid'`) and stricter regex parsing.
* **SQLite / Database Persistence:** *Deferred.* In-memory dictionary state and JSONL exports are sufficient for the current single-scenario evaluation harness.

### Final Recommendation: **SELECTIVELY UPGRADE CURRENT STACK**
Retain the lightweight Python standard library architecture. It is fast, inspectable, and 100% reliable for hackathon evaluators. Apply targeted hardening:
1. Enforce strict parameter key allowlisting in `src/policy.py`.
2. Introduce an explicit `ApprovalToken` entity bound to `action_id`.
3. Support multi-scenario iteration via a scenario directory (`data/incident_scenarios/`).
