"""AgentShield Arena — Notification & Alerting Module.

Provides unified notification delivery via:
  - Brevo (Sendinblue) transactional email API
  - Telegram Bot API (real-time security alerts)

Notifications are triggered for:
  - Welcome / onboarding emails when the dashboard first starts
  - Critical security policy violations (BLOCK decisions)
  - DLP data-leakage detections
  - Human-in-the-Loop (HITL) approval requests
  - Benchmark completion summaries
  - Incident resolution reports

All functions degrade gracefully — if an API key is missing or the
network is unavailable, errors are logged but execution continues.
"""

import json
import os
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────
BREVO_API_KEY: str = os.getenv("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL: str = os.getenv("BREVO_SENDER_EMAIL", "agentshield@agentops.ai")
BREVO_SENDER_NAME: str = os.getenv("BREVO_SENDER_NAME", "AgentShield Arena")
_admin_emails_raw: str = os.getenv("ADMIN_EMAILS", "")
ADMIN_EMAILS: List[str] = [e.strip() for e in _admin_emails_raw.split(",") if e.strip()]

TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
_tg_chats_raw: str = os.getenv("TELEGRAM_CHAT_IDS", "")
TELEGRAM_CHAT_IDS: List[str] = [c.strip() for c in _tg_chats_raw.split(",") if c.strip()]

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"
TELEGRAM_API_BASE = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

# Circuit breakers: once a provider rejects our credentials, stop calling it for
# the rest of the process instead of re-failing (and re-logging) on every event.
_disabled_channels: Dict[str, str] = {}


def _trip_on_auth_failure(channel: str, exc: Exception) -> None:
    code = getattr(exc, "code", None)
    if code in (401, 403, 404):
        _disabled_channels[channel] = f"HTTP {code} — credentials rejected; alerts disabled until restart"
        logger.error("[Notifications] %s disabled: %s", channel, _disabled_channels[channel])


def channel_status() -> Dict[str, Optional[str]]:
    """Reason each channel is disabled, or None if healthy — surfaced by /api/integrations/status."""
    return {"brevo": _disabled_channels.get("brevo"), "telegram": _disabled_channels.get("telegram")}


# ── Brevo Email ──────────────────────────────────────────────────────────────

def _send_brevo_email(
    to_emails: List[str],
    subject: str,
    html_content: str,
    text_content: str = "",
) -> bool:
    """Send a transactional email via Brevo API v3.

    Returns True on success, False on failure.
    """
    if not BREVO_API_KEY or not to_emails:
        logger.warning("[Notifications] Brevo API key or recipients not configured — skipping email.")
        return False
    if "brevo" in _disabled_channels:
        return False

    try:
        import urllib.request
        import urllib.error

        payload = {
            "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
            "to": [{"email": e} for e in to_emails],
            "subject": subject,
            "htmlContent": html_content,
            "textContent": text_content or "",
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            BREVO_API_URL,
            data=data,
            headers={
                "accept": "application/json",
                "api-key": BREVO_API_KEY,
                "content-type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            logger.info("[Notifications] Brevo email sent — HTTP %s — to: %s", status, to_emails)
            return status in (200, 201)

    except Exception as exc:  # noqa: BLE001
        logger.error("[Notifications] Brevo email failed: %s", exc)
        _trip_on_auth_failure("brevo", exc)
        return False


def _build_email_html(title: str, body_lines: List[str], severity: str = "info") -> str:
    """Build a clean, branded HTML email body."""
    severity_colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#10b981",
        "info": "#3b82f6",
    }
    accent = severity_colors.get(severity.lower(), "#3b82f6")
    body_html = "".join(f"<p style='margin:8px 0;color:#d1d5db;font-size:14px;'>{line}</p>" for line in body_lines)
    return f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset='UTF-8'></head>
    <body style='background:#0a0e1a;font-family:Inter,Arial,sans-serif;padding:32px;'>
      <div style='max-width:600px;margin:0 auto;background:#111827;border-radius:12px;
                  border:1px solid {accent};overflow:hidden;'>
        <div style='background:{accent};padding:20px 28px;'>
          <h1 style='color:#fff;margin:0;font-size:20px;font-weight:700;'>
            🛡️ AgentShield Arena
          </h1>
          <p style='color:rgba(255,255,255,0.8);margin:4px 0 0;font-size:13px;'>
            {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
          </p>
        </div>
        <div style='padding:28px;'>
          <h2 style='color:#f9fafb;font-size:16px;margin:0 0 16px;font-weight:600;'>{title}</h2>
          {body_html}
        </div>
        <div style='padding:16px 28px;background:#0d1117;border-top:1px solid #243050;'>
          <p style='color:#6b7280;font-size:12px;margin:0;'>
            AgentShield Arena — Adversarially Resilient AI Security Platform<br/>
            This is an automated security notification. Do not reply to this email.
          </p>
        </div>
      </div>
    </body>
    </html>
    """


# ── Public Email Senders ─────────────────────────────────────────────────────

def send_welcome_email(to_emails: Optional[List[str]] = None) -> bool:
    """Send welcome/onboarding email when the dashboard starts."""
    recipients = to_emails or ADMIN_EMAILS
    if not recipients:
        return False

    subject = "🛡️ AgentShield Arena Dashboard is Live"
    body_lines = [
        "Your <strong>AgentShield Arena</strong> security dashboard has started successfully.",
        "",
        "You can now:",
        "• Run adversarial incident simulations",
        "• Monitor real-time Policy Gate decisions",
        "• Inspect DLP violations and audit logs",
        "• Interact with the AI Security Advisor chatbot",
        "• Receive Telegram alerts for critical security events",
        "",
        "Open the dashboard at: <a href='http://localhost:8000' style='color:#3b82f6;'>http://localhost:8000</a>",
        "",
        "For Human-in-the-Loop approvals, the dashboard will notify you here and via Telegram.",
    ]
    html = _build_email_html("Welcome to AgentShield Arena!", body_lines, "info")
    return _send_brevo_email(recipients, subject, html)


def send_security_alert_email(
    alert_type: str,
    incident_id: str,
    details: str,
    severity: str = "high",
    to_emails: Optional[List[str]] = None,
) -> bool:
    """Send a security alert email for policy violations or DLP detections."""
    recipients = to_emails or ADMIN_EMAILS
    if not recipients:
        return False

    severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity.lower(), "🔵")
    subject = f"{severity_emoji} AgentShield Alert [{severity.upper()}]: {alert_type}"
    body_lines = [
        f"<strong>Alert Type:</strong> {alert_type}",
        f"<strong>Incident ID:</strong> {incident_id}",
        f"<strong>Severity:</strong> {severity.upper()}",
        f"<strong>Timestamp:</strong> {datetime.now(timezone.utc).isoformat()}",
        "",
        "<strong>Details:</strong>",
        details,
        "",
        "Please review the audit trail for full context.",
    ]
    html = _build_email_html(f"Security Alert: {alert_type}", body_lines, severity)
    return _send_brevo_email(recipients, subject, html)


def send_hitl_approval_email(
    action_id: str,
    tool_name: str,
    arguments: Dict[str, Any],
    run_id: str,
    dashboard_url: str = "http://localhost:8000",
    to_emails: Optional[List[str]] = None,
) -> bool:
    """Send a Human-in-the-Loop approval request email."""
    recipients = to_emails or ADMIN_EMAILS
    if not recipients:
        return False

    approve_url = f"{dashboard_url}/#hitl"
    subject = f"⚠️ AgentShield HITL Approval Required — {tool_name}"
    args_text = json.dumps(arguments, indent=2)
    body_lines = [
        "A high-risk action requires your <strong>manual approval</strong> before execution.",
        "",
        f"<strong>Action ID:</strong> {action_id}",
        f"<strong>Tool:</strong> {tool_name}",
        f"<strong>Run ID:</strong> {run_id}",
        "",
        "<strong>Arguments:</strong>",
        f"<pre style='background:#0d1117;padding:12px;border-radius:6px;color:#a3e635;"
        f"font-size:12px;overflow:auto;'>{args_text}</pre>",
        "",
        f"<a href='{approve_url}' style='display:inline-block;background:#3b82f6;color:#fff;"
        f"padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;'>Review & Approve →</a>",
    ]
    html = _build_email_html("Human-in-the-Loop Approval Required", body_lines, "high")
    return _send_brevo_email(recipients, subject, html)


def send_benchmark_report_email(
    summary: Dict[str, Any],
    to_emails: Optional[List[str]] = None,
) -> bool:
    """Send a benchmark completion summary email."""
    recipients = to_emails or ADMIN_EMAILS
    if not recipients:
        return False

    subject = "📊 AgentShield Arena — Benchmark Run Complete"
    scenarios = summary.get("scenarios_run", "N/A")
    passed = summary.get("scenarios_passed", "N/A")
    avg_score = summary.get("average_score", "N/A")
    body_lines = [
        "Your multi-scenario benchmark run has completed.",
        "",
        f"<strong>Scenarios Run:</strong> {scenarios}",
        f"<strong>Scenarios Passed:</strong> {passed}",
        f"<strong>Average Score:</strong> {avg_score}",
        "",
        "View the full benchmark report in the dashboard.",
    ]
    html = _build_email_html("Benchmark Run Complete", body_lines, "info")
    return _send_brevo_email(recipients, subject, html)


# ── Telegram Bot ─────────────────────────────────────────────────────────────

def _send_telegram_message(chat_id: str, text: str, parse_mode: str = "HTML") -> bool:
    """Send a Telegram message to a single chat ID.

    Returns True on success, False on failure.
    """
    if not TELEGRAM_BOT_TOKEN:
        logger.warning("[Notifications] Telegram bot token not configured — skipping.")
        return False
    if "telegram" in _disabled_channels:
        return False

    try:
        import urllib.request
        import urllib.parse

        url = f"{TELEGRAM_API_BASE}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            ok = result.get("ok", False)
            if ok:
                logger.info("[Notifications] Telegram message sent to chat %s", chat_id)
            else:
                logger.error("[Notifications] Telegram error: %s", result)
            return ok

    except Exception as exc:  # noqa: BLE001
        logger.error("[Notifications] Telegram send failed to %s: %s", chat_id, exc)
        _trip_on_auth_failure("telegram", exc)
        return False


def _broadcast_telegram(text: str, parse_mode: str = "HTML") -> List[bool]:
    """Broadcast a message to all configured Telegram chat IDs."""
    if not TELEGRAM_CHAT_IDS:
        logger.debug("[Notifications] No Telegram chat IDs configured.")
        return []
    return [_send_telegram_message(cid, text, parse_mode) for cid in TELEGRAM_CHAT_IDS]


def register_telegram_chat(chat_id: str) -> None:
    """Dynamically register a new Telegram chat ID (for /start webhook)."""
    if chat_id not in TELEGRAM_CHAT_IDS:
        TELEGRAM_CHAT_IDS.append(chat_id)
        logger.info("[Notifications] Registered new Telegram chat ID: %s", chat_id)


def notify_policy_block_telegram(
    tool_name: str,
    reason: str,
    incident_id: str,
    severity: str = "HIGH",
) -> None:
    """Broadcast a policy BLOCK alert to all Telegram chats."""
    text = (
        f"🚨 <b>AgentShield POLICY BLOCK</b>\n\n"
        f"🔴 <b>Severity:</b> {severity}\n"
        f"🛠 <b>Tool:</b> <code>{tool_name}</code>\n"
        f"📋 <b>Incident:</b> {incident_id}\n"
        f"⛔ <b>Reason:</b> {reason}\n\n"
        f"⏱ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    _broadcast_telegram(text)


def notify_dlp_violation_telegram(
    tool_name: str,
    pattern_ids: List[str],
    incident_id: str,
) -> None:
    """Broadcast a DLP violation alert to all Telegram chats."""
    patterns_str = ", ".join(pattern_ids) or "unknown"
    text = (
        f"⚠️ <b>AgentShield DLP VIOLATION</b>\n\n"
        f"🔍 <b>Tool:</b> <code>{tool_name}</code>\n"
        f"📋 <b>Incident:</b> {incident_id}\n"
        f"🏷 <b>Patterns:</b> {patterns_str}\n\n"
        f"⏱ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    _broadcast_telegram(text)


def notify_hitl_request_telegram(
    action_id: str,
    tool_name: str,
    run_id: str,
    dashboard_url: str = "http://localhost:8000",
) -> None:
    """Broadcast a HITL approval request to all Telegram chats."""
    text = (
        f"🧑‍⚖️ <b>AgentShield HITL APPROVAL NEEDED</b>\n\n"
        f"🛠 <b>Tool:</b> <code>{tool_name}</code>\n"
        f"🆔 <b>Action:</b> {action_id}\n"
        f"🔑 <b>Run ID:</b> {run_id}\n\n"
        f"👉 Review at: {dashboard_url}/#hitl\n\n"
        f"⏱ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    _broadcast_telegram(text)


def notify_welcome_telegram() -> None:
    """Broadcast a welcome message when the dashboard starts."""
    text = (
        f"🛡️ <b>AgentShield Arena is LIVE!</b>\n\n"
        f"The security dashboard has started successfully.\n\n"
        f"You will receive real-time alerts here for:\n"
        f"• 🚨 Policy Gate BLOCK decisions\n"
        f"• ⚠️ DLP data-leakage detections\n"
        f"• 🧑‍⚖️ Human-in-the-Loop approval requests\n"
        f"• 📊 Benchmark completions\n\n"
        f"⏱ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    _broadcast_telegram(text)


def get_telegram_updates() -> List[Dict[str, Any]]:
    """Poll Telegram for new messages (for /start chat ID registration)."""
    if not TELEGRAM_BOT_TOKEN:
        return []
    try:
        import urllib.request

        url = f"{TELEGRAM_API_BASE}/getUpdates"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            return result.get("result", [])
    except Exception as exc:  # noqa: BLE001
        logger.error("[Notifications] Failed to poll Telegram updates: %s", exc)
        return []


# ── Unified Notifier ─────────────────────────────────────────────────────────

def notify_security_event(
    event_type: str,
    incident_id: str,
    details: Dict[str, Any],
    severity: str = "high",
) -> None:
    """Unified entry point — fires both email and Telegram for a security event.

    event_type: 'policy_block' | 'dlp_violation' | 'hitl_request' | 'benchmark_complete'
    """
    tool_name = details.get("tool_name", "unknown")
    reason = details.get("reason", "")
    action_id = details.get("action_id", "")
    run_id = details.get("run_id", "")

    if event_type == "policy_block":
        notify_policy_block_telegram(tool_name, reason, incident_id, severity.upper())
        send_security_alert_email(
            "Policy Gate BLOCK",
            incident_id,
            f"Tool: {tool_name}\nReason: {reason}",
            severity,
        )

    elif event_type == "dlp_violation":
        pattern_ids = details.get("pattern_ids", [])
        notify_dlp_violation_telegram(tool_name, pattern_ids, incident_id)
        send_security_alert_email(
            "DLP Violation Detected",
            incident_id,
            f"Tool: {tool_name}\nPatterns: {', '.join(pattern_ids)}",
            severity,
        )

    elif event_type == "hitl_request":
        notify_hitl_request_telegram(action_id, tool_name, run_id)
        send_hitl_approval_email(action_id, tool_name, details.get("arguments", {}), run_id)

    elif event_type == "benchmark_complete":
        summary = details.get("summary", {})
        send_benchmark_report_email(summary)
        text = (
            f"📊 <b>AgentShield Benchmark Complete</b>\n\n"
            f"Scenarios: {summary.get('scenarios_run', 'N/A')}\n"
            f"Passed: {summary.get('scenarios_passed', 'N/A')}\n"
            f"Avg Score: {summary.get('average_score', 'N/A')}"
        )
        _broadcast_telegram(text)

    else:
        logger.warning("[Notifications] Unknown event_type: %s", event_type)
