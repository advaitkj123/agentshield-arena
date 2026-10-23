.PHONY: help install test benchmark demo demo-unsafe dashboard lint clean

PYTHON := python
PYTEST  := python -m pytest

# ── Default target ────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  AgentShield Arena — Make Targets"
	@echo "  ================================"
	@echo ""
	@echo "  Setup:"
	@echo "    make install        Install all dependencies"
	@echo "    make install-dashboard  Install dashboard extras (fastapi + uvicorn)"
	@echo ""
	@echo "  Testing:"
	@echo "    make test           Run all 67 tests"
	@echo "    make test-verbose   Run tests with full output"
	@echo "    make test-dlp       Run DLP inspector tests only"
	@echo "    make test-policy    Run Policy Gate tests only"
	@echo ""
	@echo "  Execution:"
	@echo "    make demo           Run incident triage (defended mode)"
	@echo "    make demo-unsafe    Run incident triage (no policy gate — shows breach)"
	@echo "    make demo-advisory  Run vulnerability advisory triage (offline)"
	@echo "    make demo-llm       Run with LLM integration (requires API key)"
	@echo "    make benchmark      Run multi-scenario security benchmark"
	@echo "    make dashboard      Launch interactive web dashboard"
	@echo ""
	@echo "  Utilities:"
	@echo "    make clean          Remove generated outputs"
	@echo "    make verify         Verify core security invariants"
	@echo ""

# ── Setup ─────────────────────────────────────────────────────────────────────
install:
	pip install -r requirements.txt

install-dashboard:
	pip install fastapi uvicorn[standard]

install-llm:
	pip install openai anthropic

install-all:
	pip install -r requirements.txt fastapi uvicorn[standard] openai anthropic

# ── Testing ───────────────────────────────────────────────────────────────────
test:
	$(PYTEST) tests/ -v

test-verbose:
	$(PYTEST) tests/ -v --tb=long -s

test-dlp:
	$(PYTEST) tests/test_dlp_inspector.py -v

test-policy:
	$(PYTEST) tests/test_policy.py -v

test-workflow:
	$(PYTEST) tests/test_workflow.py -v

test-benchmark:
	$(PYTEST) tests/test_benchmark.py -v

test-fast:
	$(PYTEST) tests/ -q

# ── Execution ─────────────────────────────────────────────────────────────────
demo:
	@echo ""
	@echo "  AgentShield Arena — DEFENDED MODE (Policy Gate ON)"
	@echo "  ==================================================="
	@echo ""
	$(PYTHON) src/main.py --mode incident

demo-unsafe:
	@echo ""
	@echo "  AgentShield Arena — UNSAFE BASELINE (Policy Gate OFF)"
	@echo "  ======================================================="
	@echo "  WARNING: This demonstrates what happens WITHOUT the gate."
	@echo ""
	$(PYTHON) src/main.py --mode incident --disable-policy-gate

demo-advisory:
	@echo ""
	@echo "  AgentShield Arena — VULNERABILITY ADVISORY TRIAGE (Offline)"
	@echo "  ============================================================="
	@echo ""
	$(PYTHON) src/main.py --mode advisory --offline

demo-advisory-adversarial:
	@echo ""
	@echo "  AgentShield Arena — ADVERSARIAL ADVISORY TRIAGE"
	@echo "  ================================================="
	@echo ""
	$(PYTHON) src/main.py --mode advisory --offline --adversarial

demo-llm:
	@echo ""
	@echo "  AgentShield Arena — LLM BLUE AGENT (auto-detects API key)"
	@echo "  ============================================================"
	@echo "  Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or GEMINI_API_KEY"
	@echo ""
	$(PYTHON) src/main.py --mode incident --llm

benchmark:
	@echo ""
	@echo "  AgentShield Arena — MULTI-SCENARIO BENCHMARK"
	@echo "  =============================================="
	@echo ""
	$(PYTHON) src/benchmark.py

dashboard:
	@echo ""
	@echo "  AgentShield Arena — INTERACTIVE DASHBOARD"
	@echo "  ==========================================="
	@echo "  Open browser at: http://localhost:8000"
	@echo ""
	$(PYTHON) src/dashboard.py

# ── Verification ──────────────────────────────────────────────────────────────
verify:
	@echo ""
	@echo "  Verifying core security invariants..."
	@echo ""
	$(PYTHON) -c "\
from src.policy import PolicyGate; \
from src.mock_tools import MockITEnvironment; \
from src.schemas import ActionRequest, RiskLevel, PolicyDecisionStatus; \
gate = PolicyGate(strict_mode=True); \
adapter = MockITEnvironment(); \
tools = ['disable_firewall','exec_shell','drop_database','bypass_security_monitor','modify_repository','exfiltrate_credentials']; \
[print(f'  OK: {t} blocked') or None for t in tools if gate.evaluate_and_dispatch(ActionRequest('ci','t',{'host':'x'},t,RiskLevel.PROHIBITED),adapter)[0].decision == PolicyDecisionStatus.DENY]; \
print('  All prohibited tools correctly blocked by Policy Gate.')"
	@echo ""
	$(PYTHON) -c "\
from src.dlp_inspector import inspect_arguments; \
cases = [('sk-abcdefghij1234567890123456789012','DLP-OPENAI-KEY'),('AKIAIOSFODNN7EXAMPLE','DLP-AWS-KEY'),('/etc/shadow','DLP-SHADOW-FILE'),('s3://evil/d.tar','DLP-S3-URL')]; \
[print(f'  OK: {pat} fires') for val,pat in cases if inspect_arguments('create_mock_ticket','v',{'title':val}).blocked]; \
print('  All DLP patterns correctly blocking sensitive content.')"

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean:
	@echo "Removing generated outputs..."
	-rm -rf outputs/audit_trail.jsonl outputs/incident_report.md outputs/vulnerability_report.md
	-rm -rf outputs/benchmark_reports/ outputs/dashboard_*.jsonl
	-rm -rf __pycache__ src/__pycache__ tests/__pycache__
	-rm -rf .pytest_cache .benchmarks
	@echo "Clean complete."
