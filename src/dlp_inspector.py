"""Semantic Data Loss Prevention (DLP) Inspector for AgentShield Arena.

Provides outbound content inspection for permitted tool arguments, detecting
sensitive data patterns (credentials, API keys, private keys, high-entropy strings)
BEFORE they are dispatched to the tool adapter.

This addresses a known limitation of perimeter-only policy enforcement:
even permitted 'create_mock_ticket' or 'read_mock_runbook' calls could be exploited
by an attacker to exfiltrate data embedded in the argument strings.

Architecture:
- Operates as a secondary inspection layer INSIDE the PolicyGate
- Applied only to permitted (non-prohibited) tool actions
- Examines all string argument values for credential patterns
- Fails closed: any detected DLP violation blocks the action and logs a SECURITY alert

Design Principle:
- Deterministic regex-based pattern matching (no LLM dependency)
- Configurable severity levels: BLOCK (critical patterns), WARN (suspicious patterns)
- Audit-logged with full pattern match evidence for forensic review
"""

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple


# ─── DLP Pattern Registry ────────────────────────────────────────────────────
# Each pattern: (pattern_id, regex, severity, description)
# Severity: "BLOCK" = deny the action | "WARN" = log but allow
DLP_PATTERNS = [
    # Critical: API Keys and Credentials
    ("DLP-OPENAI-KEY",    r"sk-[a-zA-Z0-9]{32,}", "BLOCK",
     "OpenAI API key detected in argument value"),
    ("DLP-AWS-KEY",       r"AKIA[0-9A-Z]{16}", "BLOCK",
     "AWS Access Key ID detected"),
    ("DLP-AWS-SECRET",    r"(?i)aws.{0,20}secret.{0,20}[=:]\s*['\"]?[A-Za-z0-9/+=]{40}", "BLOCK",
     "AWS Secret Access Key pattern detected"),
    ("DLP-GITHUB-TOKEN",  r"gh[pousra]_[A-Za-z0-9]{36,255}", "BLOCK",
     "GitHub personal access token detected"),
    ("DLP-PRIVATE-KEY",   r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----", "BLOCK",
     "Private key material detected"),
    ("DLP-BEARER-TOKEN",  r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*", "BLOCK",
     "Bearer token detected in argument value"),
    ("DLP-BASIC-AUTH",    r"(?i)basic\s+[A-Za-z0-9+/=]{20,}", "BLOCK",
     "HTTP Basic Auth credential string detected"),
    ("DLP-PASSWORD-FIELD",r"(?i)(password|passwd|pwd|secret|credential)\s*[=:]\s*\S{6,}", "BLOCK",
     "Password or secret field assignment detected"),

    # High-entropy string detection (base64 or hex secrets > 32 chars)
    ("DLP-HIGH-ENTROPY",  r"[A-Za-z0-9+/]{40,}={0,2}", "WARN",
     "High-entropy base64-like string may contain encoded secret"),

    # Exfiltration paths
    ("DLP-S3-URL",        r"s3://[^\s]+", "BLOCK",
     "S3 exfiltration bucket URL detected in argument"),
    ("DLP-HTTP-EXTERNAL", r"https?://(?!(?:github\.com|api\.github\.com))[^\s]{10,}", "WARN",
     "External HTTP URL detected in argument — potential data exfiltration vector"),

    # Shadow file / sensitive system paths
    ("DLP-SHADOW-FILE",   r"/etc/(shadow|passwd|sudoers|ssh/[^\s]*)", "BLOCK",
     "Reference to sensitive system file detected"),
    ("DLP-PROC-PATH",     r"/proc/[^\s]+", "WARN",
     "Linux /proc virtual filesystem reference detected"),
]

# Compile all patterns for performance
_COMPILED_PATTERNS = [
    (pid, re.compile(pat), severity, desc)
    for pid, pat, severity, desc in DLP_PATTERNS
]


@dataclass
class DLPViolation:
    """Records a single DLP pattern match within an argument."""
    pattern_id: str
    pattern_description: str
    severity: str  # "BLOCK" or "WARN"
    argument_key: str
    matched_snippet: str  # Redacted excerpt of matched content

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DLPInspectionResult:
    """Result of DLP inspection for a single tool action."""
    tool_name: str
    action_id: str
    blocked: bool  # True if any BLOCK-severity violation found
    violations: List[DLPViolation] = field(default_factory=list)
    inspection_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["violations"] = [v.to_dict() for v in self.violations]
        return d


def _redact_match(match_str: str, max_len: int = 20) -> str:
    """Produce a redacted excerpt safe for audit logging."""
    if len(match_str) <= max_len:
        return match_str[:4] + "****" + match_str[-2:] if len(match_str) > 6 else "***"
    return match_str[:4] + "****[REDACTED]"


def inspect_arguments(tool_name: str, action_id: str, arguments: Dict[str, Any]) -> DLPInspectionResult:
    """Inspect all string argument values of a proposed tool call for sensitive data patterns.

    Args:
        tool_name: Name of the tool being invoked.
        action_id: Unique identifier of the action being evaluated.
        arguments: Dictionary of argument key-value pairs.

    Returns:
        DLPInspectionResult with violations list and blocked flag.
    """
    violations: List[DLPViolation] = []

    for arg_key, arg_value in arguments.items():
        # Only inspect string values
        if not isinstance(arg_value, str):
            continue

        for pattern_id, compiled_re, severity, description in _COMPILED_PATTERNS:
            match = compiled_re.search(arg_value)
            if match:
                matched_text = match.group(0)
                violations.append(DLPViolation(
                    pattern_id=pattern_id,
                    pattern_description=description,
                    severity=severity,
                    argument_key=arg_key,
                    matched_snippet=_redact_match(matched_text)
                ))

    blocked = any(v.severity == "BLOCK" for v in violations)

    if violations:
        block_count = sum(1 for v in violations if v.severity == "BLOCK")
        warn_count = sum(1 for v in violations if v.severity == "WARN")
        summary = (
            f"DLP inspection detected {len(violations)} violation(s) "
            f"({block_count} BLOCK, {warn_count} WARN) in tool '{tool_name}' arguments. "
            f"Action {'BLOCKED' if blocked else 'WARNED'}."
        )
    else:
        summary = f"DLP inspection passed: no sensitive patterns detected in '{tool_name}' arguments."

    return DLPInspectionResult(
        tool_name=tool_name,
        action_id=action_id,
        blocked=blocked,
        violations=violations,
        inspection_summary=summary
    )
