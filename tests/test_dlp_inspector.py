"""Tests for the Semantic DLP Inspector module.

Verifies that the DLP inspection layer correctly detects and blocks
sensitive data patterns (API keys, credentials, exfiltration URLs) embedded
in permitted tool argument values.
"""

import pytest
from src.dlp_inspector import inspect_arguments, DLPInspectionResult, DLPViolation


# ─── Fixture ───────────────────────────────────────────────────────────────

def make_result(tool: str, args: dict) -> DLPInspectionResult:
    return inspect_arguments(tool_name=tool, action_id="act-dlp-test", arguments=args)


# ─── Tests: Clean Arguments ────────────────────────────────────────────────

def test_clean_args_pass_inspection():
    """Verify that normal, benign arguments pass DLP inspection without violations."""
    result = make_result("create_mock_ticket", {
        "title": "Investigate credential breach on srv-pay-prod-02",
        "priority": "high"
    })
    assert result.blocked is False
    assert len(result.violations) == 0
    assert "passed" in result.inspection_summary.lower()


def test_clean_log_query_passes():
    """Verify standard log query arguments produce no DLP violations."""
    result = make_result("search_mock_logs", {
        "host": "srv-app-prod-01",
        "timeframe": "2h"
    })
    assert result.blocked is False
    assert len(result.violations) == 0


# ─── Tests: OpenAI API Key Detection (BLOCK) ──────────────────────────────

def test_openai_api_key_detected_and_blocked():
    """Verify that an OpenAI API key embedded in a ticket title is detected and blocked."""
    result = make_result("create_mock_ticket", {
        "title": "Debug report: sk-abcdefghij1234567890123456789012 attached",
        "priority": "low"
    })
    assert result.blocked is True
    violation_ids = [v.pattern_id for v in result.violations]
    assert "DLP-OPENAI-KEY" in violation_ids


def test_openai_key_in_runbook_topic_blocked():
    """Verify OpenAI key in runbook topic argument is detected."""
    result = make_result("read_mock_runbook", {
        "topic": "sk-testkey1234567890123456789012345678"
    })
    assert result.blocked is True


# ─── Tests: AWS Credential Detection (BLOCK) ──────────────────────────────

def test_aws_access_key_detected():
    """Verify that AWS Access Key ID pattern is detected."""
    result = make_result("create_mock_ticket", {
        "title": "Review AWS key AKIAIOSFODNN7EXAMPLE found in deployment log",
        "priority": "critical"
    })
    assert result.blocked is True
    violation_ids = [v.pattern_id for v in result.violations]
    assert "DLP-AWS-KEY" in violation_ids


# ─── Tests: GitHub Token Detection (BLOCK) ────────────────────────────────

def test_github_personal_access_token_detected():
    """Verify that GitHub PAT is detected in argument values."""
    result = make_result("create_mock_ticket", {
        "title": "Token ghs_16C7e42F292c6912E7710c838347Ae178B4a in logs",
        "priority": "high"
    })
    assert result.blocked is True
    violation_ids = [v.pattern_id for v in result.violations]
    assert "DLP-GITHUB-TOKEN" in violation_ids


# ─── Tests: Private Key Detection (BLOCK) ─────────────────────────────────

def test_private_key_header_detected():
    """Verify that a private key PEM header is detected and blocked."""
    result = make_result("create_mock_ticket", {
        "title": "Key: -----BEGIN RSA PRIVATE KEY----- found in deployment artifact",
        "priority": "critical"
    })
    assert result.blocked is True
    violation_ids = [v.pattern_id for v in result.violations]
    assert "DLP-PRIVATE-KEY" in violation_ids


# ─── Tests: Password Field Detection (BLOCK) ──────────────────────────────

def test_password_assignment_detected():
    """Verify that password= assignment patterns are detected."""
    result = make_result("create_mock_ticket", {
        "title": "Credential dump: password=SuperS3cret! db_user=admin",
        "priority": "high"
    })
    assert result.blocked is True
    violation_ids = [v.pattern_id for v in result.violations]
    assert "DLP-PASSWORD-FIELD" in violation_ids


# ─── Tests: Shadow File Path Detection (BLOCK) ────────────────────────────

def test_shadow_file_path_blocked():
    """Verify that /etc/shadow path references are blocked."""
    result = make_result("read_mock_runbook", {
        "topic": "Extract contents from /etc/shadow for audit"
    })
    assert result.blocked is True
    violation_ids = [v.pattern_id for v in result.violations]
    assert "DLP-SHADOW-FILE" in violation_ids


def test_etc_passwd_path_blocked():
    """Verify /etc/passwd path is also blocked."""
    result = make_result("create_mock_ticket", {
        "title": "Contents of /etc/passwd attached for review",
        "priority": "medium"
    })
    assert result.blocked is True


# ─── Tests: S3 Exfiltration URL Detection (BLOCK) ─────────────────────────

def test_s3_exfiltration_url_blocked():
    """Verify that S3 bucket URLs embedded in ticket text are blocked."""
    result = make_result("create_mock_ticket", {
        "title": "Upload result to s3://external-debug-drop/output.tar.gz",
        "priority": "low"
    })
    assert result.blocked is True
    violation_ids = [v.pattern_id for v in result.violations]
    assert "DLP-S3-URL" in violation_ids


# ─── Tests: Warning-Only Patterns (WARN, not BLOCK) ───────────────────────

def test_external_url_triggers_warn_not_block():
    """Verify external HTTP URL triggers WARN but does not block if no BLOCK patterns also present."""
    result = make_result("create_mock_ticket", {
        "title": "Advisory reference: https://example-external-vendor.com/advisories/2026-1234",
        "priority": "low"
    })
    # External URL should warn, not block on its own
    warn_violations = [v for v in result.violations if v.severity == "WARN"]
    block_violations = [v for v in result.violations if v.severity == "BLOCK"]
    # The external URL warning should be present
    assert any("DLP-HTTP-EXTERNAL" in v.pattern_id for v in warn_violations)
    # If no BLOCK violations, should not be blocked
    if not block_violations:
        assert result.blocked is False


# ─── Tests: Multiple Violations in One Call ────────────────────────────────

def test_multiple_violations_all_reported():
    """Verify that multiple sensitive patterns in one argument are all captured."""
    result = make_result("create_mock_ticket", {
        "title": (
            "Exfil via s3://evil-bucket/data.tar.gz using key "
            "sk-abcdefghij1234567890123456789012 from /etc/shadow"
        ),
        "priority": "low"
    })
    assert result.blocked is True
    violation_ids = [v.pattern_id for v in result.violations]
    # Multiple violation types should be detected
    assert len(result.violations) >= 2


# ─── Tests: DLP Integration with PolicyGate ───────────────────────────────

def test_policy_gate_dlp_blocks_credential_in_ticket():
    """Verify PolicyGate with DLP enabled blocks a ticket containing an API key."""
    from src.policy import PolicyGate
    from src.mock_tools import MockITEnvironment
    from src.schemas import ActionRequest, RiskLevel, PolicyDecisionStatus

    gate = PolicyGate(strict_mode=True, enable_dlp=True)
    adapter = MockITEnvironment()

    action = ActionRequest(
        action_id="act-dlp-gate-01",
        tool_name="create_mock_ticket",
        arguments={
            "title": "Exfil attempt: sk-abcdefghij1234567890123456789012",
            "priority": "low"
        },
        reason="Adversarial ticket exfiltration attempt",
        risk_level=RiskLevel.LOW
    )
    decision, result, dlp = gate.evaluate_and_dispatch(action, adapter)
    assert decision.decision == PolicyDecisionStatus.DENY
    assert decision.policy_rule_id == "RULE-DLP-BLOCKED"
    assert result.executed is False
    assert result.status == "dlp_blocked"
    assert dlp is not None
    assert dlp.blocked is True


def test_policy_gate_dlp_allows_clean_ticket():
    """Verify PolicyGate with DLP allows a clean ticket with no sensitive patterns."""
    from src.policy import PolicyGate
    from src.mock_tools import MockITEnvironment
    from src.schemas import ActionRequest, RiskLevel, PolicyDecisionStatus

    gate = PolicyGate(strict_mode=True, enable_dlp=True)
    adapter = MockITEnvironment()

    action = ActionRequest(
        action_id="act-dlp-gate-02",
        tool_name="create_mock_ticket",
        arguments={
            "title": "Track remediation progress for INC-84920 credential breach",
            "priority": "high"
        },
        reason="Create tracking ticket for credential breach",
        risk_level=RiskLevel.LOW
    )
    decision, result, dlp = gate.evaluate_and_dispatch(action, adapter)
    assert decision.decision == PolicyDecisionStatus.ALLOW
    assert result.executed is True
    assert result.status == "success"


def test_policy_gate_dlp_disabled_allows_credential_through():
    """Verify that when DLP is disabled, credential-containing tickets pass through."""
    from src.policy import PolicyGate
    from src.mock_tools import MockITEnvironment
    from src.schemas import ActionRequest, RiskLevel, PolicyDecisionStatus

    gate = PolicyGate(strict_mode=True, enable_dlp=False)  # DLP disabled
    adapter = MockITEnvironment()

    action = ActionRequest(
        action_id="act-dlp-gate-03",
        tool_name="create_mock_ticket",
        arguments={
            "title": "Key sk-abcdefghij1234567890123456789012 in log",
            "priority": "low"
        },
        reason="Test with DLP disabled",
        risk_level=RiskLevel.LOW
    )
    decision, result, _dlp = gate.evaluate_and_dispatch(action, adapter)
    # Without DLP, only Layer 1-3 run: ticket should be allowed
    assert decision.decision == PolicyDecisionStatus.ALLOW
    assert result.executed is True


# ─── Tests: DLP Result Structure ──────────────────────────────────────────

def test_dlp_violation_to_dict_serializable():
    """Verify DLPViolation serializes correctly to dict."""
    result = make_result("create_mock_ticket", {
        "title": "Key sk-abcdefghij1234567890123456789012 found",
        "priority": "low"
    })
    assert result.blocked is True
    for violation in result.violations:
        d = violation.to_dict()
        assert "pattern_id" in d
        assert "severity" in d
        assert "argument_key" in d
        assert "matched_snippet" in d
        # Ensure the full key is redacted
        assert "sk-abcdefghij1234567890123456789012" not in d["matched_snippet"]


def test_dlp_inspection_result_to_dict():
    """Verify DLPInspectionResult serializes correctly to dict."""
    result = make_result("read_mock_runbook", {
        "topic": "safe runbook topic"
    })
    d = result.to_dict()
    assert "tool_name" in d
    assert "action_id" in d
    assert "blocked" in d
    assert "violations" in d
    assert isinstance(d["violations"], list)
