"""AgentShield Arena — Gemini AI Security Advisor.

Provides an interactive AI chatbot backed by Google Gemini that answers
questions about:
  - Incident analysis and triage
  - Policy Gate decisions
  - DLP pattern explanations
  - CVE and security advisory context
  - Agent evaluation metrics
  - General cybersecurity best practices

The advisor is integrated into the dashboard as a floating chat widget.
It operates entirely through the Gemini REST API — no additional SDKs required.
"""

import json
import os
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"

# System prompt that gives Gemini context about AgentShield Arena
SYSTEM_PROMPT = """You are the AgentShield Arena AI Security Advisor — an expert AI assistant embedded in an \
adversarial AI-agent evaluation and incident-response platform.

Your role is to:
1. Help users understand Policy Gate decisions (ALLOW / BLOCK / REQUIRE_APPROVAL)
2. Explain DLP (Data Loss Prevention) pattern violations and their risk implications
3. Analyze incident scenarios and suggest triage steps
4. Explain evaluation metrics: Safety Score, Helpfulness Score, DLP Compliance Score, \
Policy Compliance Rate, False Positive Rate, HITL Rate, Adversarial Robustness Index
5. Help interpret CVE/security advisory data and patch recommendations
6. Answer general cybersecurity questions related to AI agent governance
7. Suggest improvements to incident response playbooks
8. Explain the four-layer Policy Gate architecture (input validation → risk classification → \
argument validation → DLP inspection)
9. Guide users through the Human-in-the-Loop (HITL) approval workflow

AgentShield Arena framework features:
- Deterministic Blue Agent (rule-based incident response)
- LLM-backed Blue Agent (AI-powered investigation)
- Red Agent (adversarial attack injections — 6 scenarios)
- Four-layer deterministic Policy Gate
- 13-pattern Semantic DLP Inspector
- HITL approval workflow for high-risk actions
- GitHub Security Advisories integration
- Multi-scenario benchmarking with 7 evaluation metrics
- Append-only JSONL audit logging
- FastAPI/SSE real-time dashboard

Always be concise, technically precise, and actionable. When discussing security events, \
prioritize risk context and mitigation steps. If you reference specific incident IDs or metrics, \
acknowledge they are from the current session context.

Format responses with clear structure using markdown when appropriate, but keep answers focused.
"""


# ── Gemini API Client ────────────────────────────────────────────────────────

class GeminiAdvisor:
    """Stateful Gemini-backed AI security advisor with conversation history."""

    def __init__(self, max_history: int = 20):
        self.api_key = GEMINI_API_KEY
        self.model = GEMINI_MODEL
        self.max_history = max_history
        self._history: List[Dict[str, Any]] = []
        self._available: Optional[bool] = None  # cached availability check

    @property
    def is_available(self) -> bool:
        """Return True if the Gemini API key is configured."""
        return bool(self.api_key)

    def _build_request_body(self, user_message: str) -> Dict[str, Any]:
        """Build the Gemini generateContent request body with conversation history."""
        contents = []

        # Prepend history
        for turn in self._history[-self.max_history:]:
            contents.append(turn)

        # Add the new user message
        contents.append({
            "role": "user",
            "parts": [{"text": user_message}]
        })

        return {
            "system_instruction": {
                "parts": [{"text": SYSTEM_PROMPT}]
            },
            "contents": contents,
            "generationConfig": {
                "temperature": 0.4,
                "topP": 0.9,
                "maxOutputTokens": 1024,
            },
            "safetySettings": [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_ONLY_HIGH"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_ONLY_HIGH"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_ONLY_HIGH"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_ONLY_HIGH"},
            ]
        }

    def chat(self, user_message: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a message and return the AI response.

        Args:
            user_message: The user's question or statement.
            context: Optional dict with incident/run context to inject.

        Returns:
            Dict with keys: 'response', 'success', 'error', 'model', 'timestamp'
        """
        if not self.is_available:
            return {
                "response": (
                    "⚠️ The AI Security Advisor is not configured. "
                    "Please set `GEMINI_API_KEY` in your `.env` file to enable this feature. "
                    "You can obtain a free API key at https://aistudio.google.com/apikey"
                ),
                "success": False,
                "error": "GEMINI_API_KEY not set",
                "model": self.model,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # Inject context if provided
        enhanced_message = user_message
        if context:
            ctx_lines = []
            if "incident_id" in context:
                ctx_lines.append(f"Incident ID: {context['incident_id']}")
            if "run_id" in context:
                ctx_lines.append(f"Run ID: {context['run_id']}")
            if "recent_violations" in context:
                ctx_lines.append(f"Recent DLP Violations: {context['recent_violations']}")
            if "policy_decisions" in context:
                ctx_lines.append(f"Recent Policy Decisions: {context['policy_decisions']}")
            if ctx_lines:
                ctx_str = "\n".join(ctx_lines)
                enhanced_message = f"[Session Context]\n{ctx_str}\n\n[Question]\n{user_message}"

        url = f"{GEMINI_BASE_URL}/{self.model}:generateContent?key={self.api_key}"
        body = self._build_request_body(enhanced_message)
        data = json.dumps(body).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            # Extract response text
            candidates = result.get("candidates", [])
            if not candidates:
                raise ValueError("No candidates in Gemini response")

            parts = candidates[0].get("content", {}).get("parts", [])
            response_text = " ".join(p.get("text", "") for p in parts).strip()

            if not response_text:
                finish_reason = candidates[0].get("finishReason", "UNKNOWN")
                response_text = f"[Response blocked — finish reason: {finish_reason}]"

            # Update history for multi-turn conversation
            self._history.append({"role": "user", "parts": [{"text": enhanced_message}]})
            self._history.append({"role": "model", "parts": [{"text": response_text}]})

            # Prune history to avoid token bloat
            if len(self._history) > self.max_history * 2:
                self._history = self._history[-(self.max_history * 2):]

            return {
                "response": response_text,
                "success": True,
                "error": None,
                "model": self.model,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "usage": result.get("usageMetadata", {}),
            }

        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8") if exc.fp else str(exc)
            logger.error("[GeminiAdvisor] HTTP error %s: %s", exc.code, err_body)
            error_msg = f"HTTP {exc.code}"
            if exc.code == 400:
                error_msg = "Invalid request — check your message format."
            elif exc.code == 403:
                error_msg = "API key invalid or quota exceeded."
            elif exc.code == 429:
                error_msg = "Rate limit exceeded — please try again in a moment."
            return {
                "response": f"⚠️ AI Advisor temporarily unavailable: {error_msg}",
                "success": False,
                "error": error_msg,
                "model": self.model,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:  # noqa: BLE001
            logger.error("[GeminiAdvisor] Unexpected error: %s", exc)
            return {
                "response": "⚠️ AI Advisor encountered an unexpected error. Please try again.",
                "success": False,
                "error": str(exc),
                "model": self.model,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def reset_history(self) -> None:
        """Clear conversation history to start a fresh session."""
        self._history.clear()
        logger.info("[GeminiAdvisor] Conversation history reset.")

    def analyze_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Specialized method to analyze an incident and get AI recommendations."""
        inc_id = incident.get("incident_id", "UNKNOWN")
        title = incident.get("title", "Unknown incident")
        severity = incident.get("severity", "unknown")
        description = incident.get("description", "")
        evidence = incident.get("evidence", [])
        evidence_summary = "; ".join(
            f"{e.get('source_type', '?')}: {str(e.get('content', ''))[:80]}"
            for e in evidence[:3]
        )

        prompt = (
            f"Analyze this IT security incident and provide a concise triage report:\n\n"
            f"ID: {inc_id}\n"
            f"Title: {title}\n"
            f"Severity: {severity}\n"
            f"Description: {description}\n"
            f"Evidence: {evidence_summary}\n\n"
            f"Provide: 1) Root cause assessment, 2) Immediate containment steps, "
            f"3) Long-term remediation, 4) Risk to organization (1 sentence each)."
        )
        return self.chat(prompt)

    def explain_policy_decision(
        self,
        tool_name: str,
        decision: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Get AI explanation for a Policy Gate decision."""
        prompt = (
            f"Explain this AgentShield Policy Gate decision:\n\n"
            f"Tool: {tool_name}\n"
            f"Decision: {decision}\n"
            f"Reason: {reason}\n\n"
            f"Explain: 1) Why this decision was made, 2) Security implications, "
            f"3) What the agent should do instead."
        )
        return self.chat(prompt)


# ── Module-level singleton (shared across API routes) ────────────────────────
_advisor_instance: Optional[GeminiAdvisor] = None


def get_advisor() -> GeminiAdvisor:
    """Get or create the module-level GeminiAdvisor singleton."""
    global _advisor_instance
    if _advisor_instance is None:
        _advisor_instance = GeminiAdvisor()
        logger.info("[GeminiAdvisor] Initialized (model: %s, available: %s)",
                    _advisor_instance.model, _advisor_instance.is_available)
    return _advisor_instance
