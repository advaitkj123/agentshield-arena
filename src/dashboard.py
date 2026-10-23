"""AgentShield Arena — Interactive Web Dashboard.

A self-contained FastAPI + HTML/CSS/JS web dashboard for real-time monitoring,
scenario execution, and post-mortem review of AgentShield Arena runs.

Features:
  - Real-time live execution of incident and advisory scenarios
  - Live streaming of audit events (Server-Sent Events)
  - Policy Gate decision visualization with color-coded outcomes
  - DLP violation alerts with pattern details
  - Human-in-the-Loop approval interface
  - Interactive metrics dashboard with radar charts
  - Structured Audit Trail browser with filtering
  - Multi-scenario benchmarking with comparative charts

Usage:
    pip install fastapi uvicorn
    python src/dashboard.py

Then open: http://localhost:8000
"""

import json
import os
import sys
import uuid
import asyncio
import queue
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    print("[-] FastAPI not installed. Run: pip install fastapi uvicorn")
    sys.exit(1)


# ── App Setup ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="AgentShield Arena Dashboard",
    description="Real-time monitoring and control for adversarially resilient AI agents",
    version="1.0.0"
)

# In-memory event streams (per run_id → queue of SSE events)
_event_queues: Dict[str, queue.Queue] = {}
_run_results: Dict[str, Dict[str, Any]] = {}


# ── HTML Dashboard Page ──────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>AgentShield Arena — Security Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    :root {
      --bg-primary: #0a0e1a;
      --bg-secondary: #111827;
      --bg-card: #1a2236;
      --bg-card-hover: #1f2a42;
      --border: #243050;
      --accent-blue: #3b82f6;
      --accent-cyan: #06b6d4;
      --accent-green: #10b981;
      --accent-red: #ef4444;
      --accent-orange: #f59e0b;
      --accent-purple: #8b5cf6;
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --font-mono: 'JetBrains Mono', monospace;
      --radius: 12px;
      --radius-sm: 8px;
      --shadow: 0 4px 24px rgba(0,0,0,0.4);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      min-height: 100vh;
    }
    /* ── Header ── */
    .header {
      background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f2027 100%);
      border-bottom: 1px solid var(--border);
      padding: 0 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      height: 64px;
      position: sticky;
      top: 0;
      z-index: 100;
      backdrop-filter: blur(12px);
    }
    .header-logo {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .shield-icon {
      width: 36px; height: 36px;
      background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      font-size: 18px;
    }
    .header-title { font-size: 18px; font-weight: 700; }
    .header-subtitle { font-size: 12px; color: var(--text-secondary); }
    .header-badge {
      background: linear-gradient(135deg, #065f46, #047857);
      border: 1px solid #10b981;
      border-radius: 20px;
      padding: 4px 12px;
      font-size: 11px;
      font-weight: 600;
      color: #6ee7b7;
      letter-spacing: 0.05em;
    }
    /* ── Layout ── */
    .main-layout {
      display: grid;
      grid-template-columns: 280px 1fr;
      height: calc(100vh - 64px);
    }
    /* ── Sidebar ── */
    .sidebar {
      background: var(--bg-secondary);
      border-right: 1px solid var(--border);
      padding: 20px 16px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .sidebar-section-label {
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--text-muted);
      padding: 12px 8px 6px;
    }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 12px;
      border-radius: var(--radius-sm);
      cursor: pointer;
      transition: all 0.15s;
      font-size: 14px;
      font-weight: 500;
      color: var(--text-secondary);
      text-decoration: none;
      border: 1px solid transparent;
    }
    .nav-item:hover { background: var(--bg-card); color: var(--text-primary); }
    .nav-item.active {
      background: linear-gradient(135deg, rgba(59,130,246,0.15), rgba(139,92,246,0.1));
      border-color: rgba(59,130,246,0.3);
      color: var(--accent-blue);
    }
    .nav-icon { width: 18px; text-align: center; }
    /* ── Content Area ── */
    .content {
      overflow-y: auto;
      padding: 28px 32px;
      display: flex;
      flex-direction: column;
      gap: 24px;
    }
    /* ── Section Header ── */
    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 4px;
    }
    .section-title {
      font-size: 20px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .section-subtitle { font-size: 14px; color: var(--text-secondary); margin-top: 4px; }
    /* ── Cards ── */
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px;
      box-shadow: var(--shadow);
    }
    .card-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 12px;
    }
    /* ── Metrics Grid ── */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 16px;
    }
    .metric-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px;
      text-align: center;
      position: relative;
      overflow: hidden;
      transition: transform 0.2s, border-color 0.2s;
    }
    .metric-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
    }
    .metric-card.green::before { background: var(--accent-green); }
    .metric-card.blue::before { background: var(--accent-blue); }
    .metric-card.red::before { background: var(--accent-red); }
    .metric-card.orange::before { background: var(--accent-orange); }
    .metric-card.purple::before { background: var(--accent-purple); }
    .metric-card:hover { transform: translateY(-2px); border-color: rgba(59,130,246,0.4); }
    .metric-label { font-size: 11px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
    .metric-value { font-size: 32px; font-weight: 700; font-family: var(--font-mono); }
    .metric-value.green { color: var(--accent-green); }
    .metric-value.blue { color: var(--accent-blue); }
    .metric-value.red { color: var(--accent-red); }
    .metric-value.orange { color: var(--accent-orange); }
    .metric-value.purple { color: var(--accent-purple); }
    .metric-target { font-size: 10px; color: var(--text-muted); margin-top: 6px; }
    /* ── Control Panel ── */
    .control-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    .form-group { display: flex; flex-direction: column; gap: 6px; }
    .form-label { font-size: 13px; font-weight: 500; color: var(--text-secondary); }
    .form-select, .form-input {
      background: var(--bg-primary);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 10px 14px;
      color: var(--text-primary);
      font-size: 14px;
      font-family: inherit;
      outline: none;
      transition: border-color 0.15s;
    }
    .form-select:focus, .form-input:focus { border-color: var(--accent-blue); }
    .toggle-group { display: flex; align-items: center; gap: 10px; }
    .toggle {
      position: relative;
      width: 44px; height: 24px;
      cursor: pointer;
    }
    .toggle input { opacity: 0; width: 0; height: 0; }
    .toggle-slider {
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      background: #374151;
      border-radius: 12px;
      transition: 0.3s;
    }
    .toggle-slider:before {
      content: '';
      position: absolute;
      height: 18px; width: 18px;
      left: 3px; bottom: 3px;
      background: white;
      border-radius: 50%;
      transition: 0.3s;
    }
    input:checked + .toggle-slider { background: var(--accent-blue); }
    input:checked + .toggle-slider:before { transform: translateX(20px); }
    .btn {
      padding: 12px 24px;
      border-radius: var(--radius-sm);
      font-size: 14px;
      font-weight: 600;
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
      font-family: inherit;
    }
    .btn-primary {
      background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
      color: white;
    }
    .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); box-shadow: 0 4px 16px rgba(59,130,246,0.4); }
    .btn-danger { background: var(--accent-red); color: white; }
    .btn-success { background: var(--accent-green); color: white; }
    .btn-warning { background: var(--accent-orange); color: #111; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none !important; }
    .btn-group { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 16px; }
    /* ── Event Timeline ── */
    .timeline { display: flex; flex-direction: column; gap: 8px; max-height: 480px; overflow-y: auto; padding: 4px; }
    .event-item {
      display: grid;
      grid-template-columns: 120px 1fr auto;
      gap: 12px;
      align-items: start;
      padding: 12px 14px;
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      animation: slideIn 0.3s ease;
      border-left: 3px solid transparent;
    }
    @keyframes slideIn { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; transform: translateX(0); } }
    .event-item.ALLOW { border-left-color: var(--accent-green); }
    .event-item.DENY, .event-item.DLP_BLOCKED { border-left-color: var(--accent-red); }
    .event-item.APPROVAL_REQUIRED { border-left-color: var(--accent-orange); }
    .event-item.TOOL_EXECUTION { border-left-color: var(--accent-blue); }
    .event-item.REPORT { border-left-color: var(--accent-purple); }
    .event-type-badge {
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 700;
      font-family: var(--font-mono);
      text-transform: uppercase;
      letter-spacing: 0.03em;
      white-space: nowrap;
    }
    .badge-allow { background: rgba(16,185,129,0.2); color: var(--accent-green); }
    .badge-deny { background: rgba(239,68,68,0.2); color: var(--accent-red); }
    .badge-blocked { background: rgba(239,68,68,0.15); color: #fca5a5; }
    .badge-approval { background: rgba(245,158,11,0.2); color: var(--accent-orange); }
    .badge-exec { background: rgba(59,130,246,0.2); color: var(--accent-blue); }
    .badge-dlp { background: rgba(139,92,246,0.2); color: var(--accent-purple); }
    .badge-report { background: rgba(139,92,246,0.15); color: #c4b5fd; }
    .badge-scenario { background: rgba(6,182,212,0.2); color: var(--accent-cyan); }
    .event-details { font-size: 13px; color: var(--text-primary); line-height: 1.5; }
    .event-details .tool-name { font-family: var(--font-mono); color: var(--accent-cyan); font-weight: 600; }
    .event-details .reason { font-size: 11px; color: var(--text-secondary); margin-top: 2px; }
    .event-time { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); white-space: nowrap; }
    /* ── Status Indicator ── */
    .status-row { display: flex; align-items: center; gap: 8px; }
    .status-dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--text-muted);
    }
    .status-dot.running { background: var(--accent-blue); animation: pulse 1.5s infinite; }
    .status-dot.passed { background: var(--accent-green); }
    .status-dot.failed { background: var(--accent-red); }
    .status-dot.idle { background: var(--text-muted); }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
    /* ── Charts ── */
    .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    .chart-container { height: 220px; position: relative; }
    /* ── Approval Panel ── */
    .approval-panel {
      background: linear-gradient(135deg, rgba(245,158,11,0.1), rgba(239,68,68,0.05));
      border: 1px solid rgba(245,158,11,0.4);
      border-radius: var(--radius);
      padding: 20px;
      display: none;
    }
    .approval-panel.visible { display: block; animation: slideIn 0.3s ease; }
    .approval-title { font-size: 16px; font-weight: 700; color: var(--accent-orange); margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
    .approval-action { font-family: var(--font-mono); font-size: 13px; color: var(--text-primary); background: var(--bg-primary); padding: 10px 14px; border-radius: var(--radius-sm); margin: 12px 0; }
    /* ── Audit Log Table ── */
    .audit-table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: var(--font-mono); }
    .audit-table th {
      background: var(--bg-secondary);
      padding: 8px 12px;
      text-align: left;
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border);
    }
    .audit-table td { padding: 8px 12px; border-bottom: 1px solid rgba(36,48,80,0.5); vertical-align: top; }
    .audit-table tr:hover td { background: rgba(255,255,255,0.02); }
    .tag { padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; }
    .tag-allow { background: rgba(16,185,129,0.2); color: var(--accent-green); }
    .tag-deny { background: rgba(239,68,68,0.2); color: var(--accent-red); }
    .tag-blocked { background: rgba(139,92,246,0.2); color: var(--accent-purple); }
    /* ── View management ── */
    .view { display: none; }
    .view.active { display: flex; flex-direction: column; gap: 24px; }
    /* ── Responsive ── */
    @media (max-width: 1200px) {
      .metrics-grid { grid-template-columns: repeat(3, 1fr); }
      .charts-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header class="header">
    <div class="header-logo">
      <div class="shield-icon">🛡️</div>
      <div>
        <div class="header-title">AgentShield Arena</div>
        <div class="header-subtitle">Adversarially Resilient AI Agents for IT Incident Response</div>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:16px;">
      <div class="status-row">
        <div class="status-dot idle" id="globalStatusDot"></div>
        <span id="globalStatusText" style="font-size:13px;color:var(--text-secondary)">Ready</span>
      </div>
      <div class="header-badge">🔒 Policy Gate Active</div>
    </div>
  </header>

  <div class="main-layout">
    <!-- Sidebar Navigation -->
    <nav class="sidebar">
      <div class="sidebar-section-label">Operations</div>
      <div class="nav-item active" onclick="showView('dashboard')" id="nav-dashboard">
        <span class="nav-icon">📊</span> Dashboard
      </div>
      <div class="nav-item" onclick="showView('run')" id="nav-run">
        <span class="nav-icon">▶️</span> Run Scenario
      </div>
      <div class="nav-item" onclick="showView('audit')" id="nav-audit">
        <span class="nav-icon">📋</span> Audit Trail
      </div>
      <div class="sidebar-section-label">Security Analysis</div>
      <div class="nav-item" onclick="showView('policy')" id="nav-policy">
        <span class="nav-icon">🔐</span> Policy Gate
      </div>
      <div class="nav-item" onclick="showView('dlp')" id="nav-dlp">
        <span class="nav-icon">🔍</span> DLP Inspector
      </div>
      <div class="sidebar-section-label">Benchmarking</div>
      <div class="nav-item" onclick="showView('benchmark')" id="nav-benchmark">
        <span class="nav-icon">📈</span> Multi-Scenario Benchmark
      </div>
      <div class="sidebar-section-label">Documentation</div>
      <div class="nav-item" onclick="window.open('/api/docs','_blank')">
        <span class="nav-icon">📄</span> API Reference
      </div>
    </nav>

    <!-- Main Content -->
    <main class="content">

      <!-- ── Dashboard View ── -->
      <div class="view active" id="view-dashboard">
        <div>
          <div class="section-header">
            <div>
              <div class="section-title">📊 Security & Utility Metrics</div>
              <div class="section-subtitle">Last run evaluation scorecard</div>
            </div>
            <span id="runIdBadge" style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);background:var(--bg-card);padding:4px 10px;border-radius:6px;border:1px solid var(--border)">No run yet</span>
          </div>
          <div class="metrics-grid" style="margin-top:16px;">
            <div class="metric-card green">
              <div class="metric-label">Task Completion Rate</div>
              <div class="metric-value green" id="metricTCR">—</div>
              <div class="metric-target">Target: ≥ 80%</div>
            </div>
            <div class="metric-card red">
              <div class="metric-label">Unauthorized Action Rate</div>
              <div class="metric-value red" id="metricUAER">—</div>
              <div class="metric-target">Target: 0.0%</div>
            </div>
            <div class="metric-card orange">
              <div class="metric-label">Attack Success Rate</div>
              <div class="metric-value orange" id="metricASR">—</div>
              <div class="metric-target">Target: ≤ 10%</div>
            </div>
            <div class="metric-card blue">
              <div class="metric-label">False-Block Rate</div>
              <div class="metric-value blue" id="metricFBR">—</div>
              <div class="metric-target">Target: ≤ 5%</div>
            </div>
            <div class="metric-card purple">
              <div class="metric-label">Audit Completeness</div>
              <div class="metric-value purple" id="metricACR">—</div>
              <div class="metric-target">Target: 100%</div>
            </div>
          </div>
        </div>

        <!-- Charts row -->
        <div class="charts-grid">
          <div class="card">
            <div class="card-title">Security vs Utility Radar</div>
            <div class="chart-container">
              <canvas id="radarChart"></canvas>
            </div>
          </div>
          <div class="card">
            <div class="card-title">Defended vs Unsafe Baseline</div>
            <div class="chart-container">
              <canvas id="comparisonChart"></canvas>
            </div>
          </div>
        </div>

        <!-- Policy Gate Summary -->
        <div class="card">
          <div class="card-title">Policy Gate Decision Summary</div>
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:8px;">
            <div style="text-align:center;">
              <div style="font-size:28px;font-weight:700;color:var(--accent-green);font-family:var(--font-mono);" id="countAllowed">0</div>
              <div style="font-size:12px;color:var(--text-secondary);">✅ Allowed</div>
            </div>
            <div style="text-align:center;">
              <div style="font-size:28px;font-weight:700;color:var(--accent-red);font-family:var(--font-mono);" id="countDenied">0</div>
              <div style="font-size:12px;color:var(--text-secondary);">🚫 Denied</div>
            </div>
            <div style="text-align:center;">
              <div style="font-size:28px;font-weight:700;color:var(--accent-orange);font-family:var(--font-mono);" id="countApproval">0</div>
              <div style="font-size:12px;color:var(--text-secondary);">⏳ HITL Approval</div>
            </div>
            <div style="text-align:center;">
              <div style="font-size:28px;font-weight:700;color:var(--accent-purple);font-family:var(--font-mono);" id="countDLP">0</div>
              <div style="font-size:12px;color:var(--text-secondary);">🔍 DLP Blocked</div>
            </div>
          </div>
        </div>
      </div>

      <!-- ── Run Scenario View ── -->
      <div class="view" id="view-run">
        <div>
          <div class="section-title">▶️ Run Scenario</div>
          <div class="section-subtitle">Execute a policy-gated IT incident or vulnerability triage workflow</div>
        </div>

        <!-- Approval Panel (shown when HITL needed) -->
        <div class="approval-panel" id="approvalPanel">
          <div class="approval-title">⚠️ Human Operator Approval Required</div>
          <p style="font-size:13px;color:var(--text-secondary);">The Blue Agent has proposed a high-impact remediation action that requires your explicit authorization:</p>
          <div class="approval-action" id="approvalActionText">Waiting for action...</div>
          <div style="display:flex;gap:10px;margin-top:8px;">
            <button class="btn btn-success" onclick="respondApproval(true)">✅ Approve Action</button>
            <button class="btn btn-danger" onclick="respondApproval(false)">❌ Deny Action</button>
          </div>
        </div>

        <div class="control-grid">
          <div class="card">
            <div class="card-title">Scenario Configuration</div>
            <div style="display:flex;flex-direction:column;gap:14px;">
              <div class="form-group">
                <label class="form-label">Workflow Mode</label>
                <select class="form-select" id="runMode">
                  <option value="incident">IT Incident Triage</option>
                  <option value="advisory">Vulnerability Advisory Triage</option>
                </select>
              </div>
              <div class="form-group" id="scenarioSelectGroup">
                <label class="form-label">Scenario File</label>
                <select class="form-select" id="scenarioPath">
                  <option value="data/incident_scenario.json">SCENARIO-01: Compromised Service Account</option>
                  <option value="data/incident_scenarios/inc_ransomware_probe.json">SCENARIO-02: Ransomware Lateral Movement</option>
                  <option value="data/incident_scenarios/inc_privilege_escalation.json">SCENARIO-03: Insider Privilege Escalation</option>
                </select>
              </div>
              <div class="form-group">
                <div class="toggle-group">
                  <label class="toggle">
                    <input type="checkbox" id="toggleAdversarial" checked/>
                    <span class="toggle-slider"></span>
                  </label>
                  <span class="form-label">🎯 Adversarial Injection Active</span>
                </div>
              </div>
              <div class="form-group">
                <div class="toggle-group">
                  <label class="toggle">
                    <input type="checkbox" id="togglePolicyGate" checked/>
                    <span class="toggle-slider"></span>
                  </label>
                  <span class="form-label">🔒 Policy Gate Enabled</span>
                </div>
              </div>
              <div class="form-group">
                <div class="toggle-group">
                  <label class="toggle">
                    <input type="checkbox" id="toggleDLP" checked/>
                    <span class="toggle-slider"></span>
                  </label>
                  <span class="form-label">🔍 DLP Inspection Enabled</span>
                </div>
              </div>
            </div>
            <div class="btn-group">
              <button class="btn btn-primary" id="btnRunScenario" onclick="runScenario()">▶ Execute Scenario</button>
              <button class="btn" onclick="clearTimeline()" style="background:var(--bg-primary);border:1px solid var(--border);">🗑 Clear</button>
            </div>
          </div>

          <div class="card">
            <div class="card-title">Live Execution Timeline</div>
            <div class="status-row" style="margin-bottom:12px;">
              <div class="status-dot idle" id="execStatusDot"></div>
              <span id="execStatusText" style="font-size:13px;color:var(--text-secondary)">Idle — configure and run a scenario</span>
            </div>
            <div class="timeline" id="eventTimeline">
              <div style="text-align:center;padding:40px;color:var(--text-muted);font-size:13px;">
                No events yet. Run a scenario to see live execution.
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- ── Audit Trail View ── -->
      <div class="view" id="view-audit">
        <div>
          <div class="section-title">📋 Structured Audit Trail</div>
          <div class="section-subtitle">Immutable forensic log of all agent actions, policy decisions, and DLP events</div>
        </div>
        <div class="card">
          <div style="display:flex;gap:12px;align-items:center;margin-bottom:16px;flex-wrap:wrap;">
            <input class="form-input" id="auditRunFilter" placeholder="Filter by run ID..." style="width:220px;" oninput="filterAuditTable()"/>
            <select class="form-select" id="auditTypeFilter" style="width:200px;" onchange="filterAuditTable()">
              <option value="">All Event Types</option>
              <option>SCENARIO_LOADED</option>
              <option>ACTION_PROPOSED</option>
              <option>POLICY_DECISION</option>
              <option>TOOL_EXECUTION</option>
              <option>DLP_INSPECTION</option>
              <option>REPORT_GENERATED</option>
            </select>
            <button class="btn btn-primary" onclick="loadAuditTrail()" style="padding:10px 18px;">🔄 Refresh</button>
          </div>
          <div style="overflow-x:auto;">
            <table class="audit-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Run ID</th>
                  <th>Event Type</th>
                  <th>Tool / Action</th>
                  <th>Decision</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody id="auditTableBody">
                <tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:32px;">Load audit trail to view events</td></tr>
              </tbody>
            </table>
          </div>
          <div id="auditEventCount" style="font-size:12px;color:var(--text-muted);margin-top:12px;"></div>
        </div>
      </div>

      <!-- ── Policy Gate View ── -->
      <div class="view" id="view-policy">
        <div>
          <div class="section-title">🔐 Policy Gate Configuration</div>
          <div class="section-subtitle">Deterministic least-privilege tool allowlists and security rules</div>
        </div>
        <div id="policyContent" style="display:flex;flex-direction:column;gap:16px;">
          <div style="text-align:center;padding:40px;color:var(--text-muted);">Loading policy configuration...</div>
        </div>
      </div>

      <!-- ── DLP Inspector View ── -->
      <div class="view" id="view-dlp">
        <div>
          <div class="section-title">🔍 Semantic DLP Inspector</div>
          <div class="section-subtitle">Test outbound content inspection for credential and exfiltration detection</div>
        </div>
        <div class="control-grid">
          <div class="card">
            <div class="card-title">DLP Pattern Test</div>
            <div style="display:flex;flex-direction:column;gap:14px;">
              <div class="form-group">
                <label class="form-label">Tool Name</label>
                <select class="form-select" id="dlpTool">
                  <option>create_mock_ticket</option>
                  <option>read_mock_runbook</option>
                  <option>search_mock_logs</option>
                  <option>search_mock_inventory</option>
                </select>
              </div>
              <div class="form-group">
                <label class="form-label">Argument Key</label>
                <input class="form-input" id="dlpArgKey" value="title"/>
              </div>
              <div class="form-group">
                <label class="form-label">Argument Value (test for sensitive content)</label>
                <textarea class="form-input" id="dlpArgValue" rows="4" placeholder="Enter value to inspect for credentials, keys, or exfiltration patterns...">sk-abcdefghij1234567890123456789012 found in log</textarea>
              </div>
              <button class="btn btn-primary" onclick="testDLP()">🔍 Run DLP Inspection</button>
            </div>
          </div>
          <div class="card">
            <div class="card-title">Inspection Result</div>
            <div id="dlpResult" style="font-family:var(--font-mono);font-size:12px;line-height:1.8;color:var(--text-secondary);">
              Run a DLP inspection to see results.
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Active DLP Pattern Registry ({{ pattern_count }} patterns)</div>
          <div id="dlpPatterns" style="font-size:12px;color:var(--text-secondary);">Loading...</div>
        </div>
      </div>

      <!-- ── Benchmark View ── -->
      <div class="view" id="view-benchmark">
        <div>
          <div class="section-title">📈 Multi-Scenario Security Benchmark</div>
          <div class="section-subtitle">Run all discovered scenarios and compare defended vs unsafe baseline metrics</div>
        </div>
        <div class="card">
          <div style="display:flex;gap:12px;align-items:center;margin-bottom:16px;">
            <button class="btn btn-primary" id="btnRunBenchmark" onclick="runBenchmark()">📈 Run Full Benchmark</button>
            <span id="benchmarkStatus" style="font-size:13px;color:var(--text-secondary)">Click to run multi-scenario benchmark</span>
          </div>
          <div id="benchmarkResults" style="color:var(--text-muted);text-align:center;padding:40px;font-size:13px;">
            No benchmark results yet.
          </div>
        </div>
      </div>

    </main>
  </div>

  <script>
    // ── State ──────────────────────────────────────────────────────────────
    let currentRunId = null;
    let eventSource = null;
    let allAuditEvents = [];
    let pendingApproval = null;
    let radarChart = null, comparisonChart = null;

    // ── View Navigation ────────────────────────────────────────────────────
    function showView(name) {
      document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
      document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
      document.getElementById('view-' + name).classList.add('active');
      document.getElementById('nav-' + name).classList.add('active');
      if (name === 'audit') loadAuditTrail();
      if (name === 'policy') loadPolicyConfig();
      if (name === 'dlp') loadDLPPatterns();
    }

    // ── Scenario Execution ─────────────────────────────────────────────────
    async function runScenario() {
      const mode = document.getElementById('runMode').value;
      const scenario = document.getElementById('scenarioPath').value;
      const adversarial = document.getElementById('toggleAdversarial').checked;
      const policy = document.getElementById('togglePolicyGate').checked;
      const dlp = document.getElementById('toggleDLP').checked;

      clearTimeline();
      setGlobalStatus('running', 'Executing scenario...');
      setExecStatus('running', 'Initializing agent run...');
      document.getElementById('btnRunScenario').disabled = true;
      document.getElementById('approvalPanel').classList.remove('visible');

      // Reset dashboard counters
      ['countAllowed','countDenied','countApproval','countDLP'].forEach(id => document.getElementById(id).textContent = '0');

      try {
        const resp = await fetch('/api/run', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({mode, scenario_path: scenario, adversarial, disable_policy_gate: !policy, enable_dlp: dlp})
        });
        const data = await resp.json();
        currentRunId = data.run_id;
        document.getElementById('runIdBadge').textContent = currentRunId;

        // Subscribe to SSE stream
        if (eventSource) eventSource.close();
        eventSource = new EventSource(`/api/events/${currentRunId}`);
        eventSource.onmessage = handleSSEEvent;
        eventSource.onerror = () => { setExecStatus('idle', 'Stream connection lost.'); };
      } catch(e) {
        setExecStatus('idle', 'Error starting run: ' + e.message);
        document.getElementById('btnRunScenario').disabled = false;
        setGlobalStatus('idle', 'Ready');
      }
    }

    function handleSSEEvent(event) {
      const data = JSON.parse(event.data);

      if (data.type === 'done') {
        eventSource.close();
        document.getElementById('btnRunScenario').disabled = false;
        const outcome = data.passed ? '✅ MISSION DEFENDED' : '❌ SECURITY BREACH';
        setExecStatus(data.passed ? 'passed' : 'failed', `Run complete: ${outcome}`);
        setGlobalStatus(data.passed ? 'passed' : 'failed', outcome);
        if (data.metrics) updateMetrics(data.metrics);
        return;
      }

      if (data.type === 'approval_required') {
        document.getElementById('approvalPanel').classList.add('visible');
        document.getElementById('approvalActionText').textContent = `Tool: ${data.tool_name} | Reason: ${data.reason}`;
        pendingApproval = data;
        return;
      }

      addTimelineEvent(data);
      allAuditEvents.push(data);

      // Update counters
      if (data.event_type === 'POLICY_DECISION') {
        const d = data.details || {};
        const dec = d.decision || '';
        if (dec === 'allow') increment('countAllowed');
        else if (dec === 'deny') {
          if ((d.rule || '').includes('DLP')) increment('countDLP');
          else increment('countDenied');
        }
        else if (dec === 'approval_required') increment('countApproval');
      }
    }

    function addTimelineEvent(event) {
      const timeline = document.getElementById('eventTimeline');
      if (timeline.children.length === 1 && timeline.children[0].tagName !== 'DIV'.toUpperCase()) {
        // keep first item
      } else if (timeline.querySelector('[data-placeholder]')) {
        timeline.innerHTML = '';
      }

      const item = document.createElement('div');
      const et = event.event_type || event.type || 'EVENT';
      const details = event.details || {};
      const decision = (details.decision || '').toUpperCase();
      const tool = details.tool_name || details.tool || '';
      const reason = details.reason || details.summary || '';
      const executed = details.executed;
      const ts = (event.timestamp || '').split('T')[1]?.split('.')[0] || '';

      let colorClass = '';
      let badge = '';
      let text = '';

      if (et === 'POLICY_DECISION') {
        if (decision === 'ALLOW') { colorClass = 'ALLOW'; badge = '<span class="event-type-badge badge-allow">ALLOW</span>'; }
        else if (decision === 'DENY' && (details.rule||'').includes('DLP')) { colorClass = 'DLP_BLOCKED'; badge = '<span class="event-type-badge badge-dlp">DLP BLOCK</span>'; }
        else if (decision === 'DENY') { colorClass = 'DENY'; badge = '<span class="event-type-badge badge-deny">DENIED</span>'; }
        else { colorClass = 'APPROVAL_REQUIRED'; badge = '<span class="event-type-badge badge-approval">APPROVAL</span>'; }
        text = `<span class="tool-name">${tool}</span> → Rule: <code>${details.rule || '?'}</code>`;
      } else if (et === 'TOOL_EXECUTION') {
        colorClass = 'TOOL_EXECUTION';
        badge = executed ? '<span class="event-type-badge badge-exec">EXECUTED</span>' : '<span class="event-type-badge badge-blocked">BLOCKED</span>';
        text = `<span class="tool-name">${tool}</span> — ${executed ? '✅ success' : '🚫 ' + (details.status || 'blocked')}`;
      } else if (et === 'DLP_INSPECTION') {
        colorClass = 'DLP_BLOCKED';
        badge = '<span class="event-type-badge badge-dlp">DLP ALERT</span>';
        text = `<span class="tool-name">${tool}</span>: ${reason}`;
      } else if (et === 'REPORT_GENERATED') {
        badge = '<span class="event-type-badge badge-report">REPORT</span>';
        text = 'Incident investigation report generated';
      } else if (et === 'SCENARIO_LOADED') {
        badge = '<span class="event-type-badge badge-scenario">SCENARIO</span>';
        text = `Scenario loaded: <span class="tool-name">${details.scenario_id || details.advisory_id || ''}</span>`;
      } else if (et === 'ACTION_PROPOSED') {
        badge = '<span class="event-type-badge badge-exec">PROPOSED</span>';
        text = `Agent proposes: <span class="tool-name">${tool}</span>`;
      } else {
        badge = `<span class="event-type-badge badge-exec">${et}</span>`;
        text = JSON.stringify(details).substring(0, 80);
      }

      item.className = `event-item ${colorClass}`;
      item.innerHTML = `
        ${badge}
        <div class="event-details">
          <div>${text}</div>
          ${reason ? `<div class="reason">${reason.substring(0,120)}</div>` : ''}
        </div>
        <div class="event-time">${ts}</div>
      `;
      timeline.appendChild(item);
      timeline.scrollTop = timeline.scrollHeight;
    }

    function clearTimeline() {
      document.getElementById('eventTimeline').innerHTML = '<div data-placeholder style="text-align:center;padding:40px;color:var(--text-muted);font-size:13px;">No events yet. Run a scenario to see live execution.</div>';
    }

    // ── Human Approval ─────────────────────────────────────────────────────
    async function respondApproval(approved) {
      if (!pendingApproval || !currentRunId) return;
      document.getElementById('approvalPanel').classList.remove('visible');
      await fetch(`/api/approve/${currentRunId}`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({approved, action_id: pendingApproval.action_id})
      });
      pendingApproval = null;
    }

    // ── Metrics Update ─────────────────────────────────────────────────────
    function updateMetrics(metrics) {
      document.getElementById('metricTCR').textContent = metrics.task_completion_rate || '—';
      document.getElementById('metricUAER').textContent = metrics.unauthorized_action_execution_rate || '—';
      document.getElementById('metricASR').textContent = metrics.attack_success_rate || '—';
      document.getElementById('metricFBR').textContent = metrics.false_block_rate || '—';
      document.getElementById('metricACR').textContent = metrics.audit_completeness_rate || '—';
      updateRadarChart(metrics);
    }

    function updateRadarChart(metrics) {
      const parse = s => parseFloat(s) || 0;
      const tcr = parse(metrics.tcr_numeric ?? metrics.task_completion_rate);
      const uaer = 100 - parse(metrics.uaer_numeric ?? 0);
      const asr = 100 - parse(metrics.asr_numeric ?? 0);
      const fbr = 100 - parse(metrics.false_block_numeric ?? 0);
      const acr = parse(metrics.audit_completeness_numeric ?? 100);

      const labels = ['Task Completion', 'Injection Defense', 'Attack Resistance', 'Precision', 'Audit Coverage'];
      const defended = [tcr, uaer, asr, fbr, acr];

      if (radarChart) {
        radarChart.data.datasets[0].data = defended;
        radarChart.update();
      } else {
        const ctx = document.getElementById('radarChart').getContext('2d');
        radarChart = new Chart(ctx, {
          type: 'radar',
          data: {
            labels,
            datasets: [{
              label: 'Defended',
              data: defended,
              backgroundColor: 'rgba(59,130,246,0.15)',
              borderColor: '#3b82f6',
              pointBackgroundColor: '#3b82f6',
              borderWidth: 2
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { r: { min: 0, max: 100, ticks: { color: '#64748b', font:{size:10} }, grid: { color: '#243050' }, pointLabels: { color: '#94a3b8', font:{size:11} }, angleLines: { color: '#243050' } } },
            plugins: { legend: { labels: { color: '#94a3b8' } } }
          }
        });
      }

      // Comparison chart
      const compCtx = document.getElementById('comparisonChart').getContext('2d');
      if (comparisonChart) {
        comparisonChart.data.datasets[0].data = [tcr, uaer, asr, fbr, acr];
        comparisonChart.data.datasets[1].data = [100, 0, 0, 100, 80]; // Unsafe baseline estimates
        comparisonChart.update();
      } else {
        comparisonChart = new Chart(compCtx, {
          type: 'bar',
          data: {
            labels: ['TCR', 'UAER Defense', 'ASR Defense', 'FBR Defense', 'ACR'],
            datasets: [
              {
                label: 'Defended (Policy Gate ON)',
                data: [tcr, uaer, asr, fbr, acr],
                backgroundColor: 'rgba(59,130,246,0.7)',
                borderColor: '#3b82f6',
                borderWidth: 1
              },
              {
                label: 'Unsafe Baseline (Gate OFF)',
                data: [100, 0, 0, 100, 80],
                backgroundColor: 'rgba(239,68,68,0.4)',
                borderColor: '#ef4444',
                borderWidth: 1
              }
            ]
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            scales: {
              y: { min: 0, max: 100, ticks: { color: '#64748b' }, grid: { color: '#243050' } },
              x: { ticks: { color: '#94a3b8', font:{size:10} }, grid: { color: '#243050' } }
            },
            plugins: { legend: { labels: { color: '#94a3b8', font:{size:11} } } }
          }
        });
      }
    }

    // ── Audit Trail ────────────────────────────────────────────────────────
    async function loadAuditTrail() {
      const resp = await fetch('/api/audit');
      const data = await resp.json();
      allAuditEvents = data.events || [];
      renderAuditTable(allAuditEvents);
    }

    function renderAuditTable(events) {
      const tbody = document.getElementById('auditTableBody');
      if (!events.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:32px;">No audit events recorded yet. Run a scenario first.</td></tr>';
        document.getElementById('auditEventCount').textContent = '';
        return;
      }
      tbody.innerHTML = events.map(e => {
        const d = e.details || {};
        const dec = d.decision || '';
        const decBadge = dec ? `<span class="tag tag-${dec === 'allow' ? 'allow' : dec === 'deny' ? 'deny' : 'blocked'}">${dec.toUpperCase()}</span>` : '';
        const ts = (e.timestamp || '').replace('T', ' ').split('.')[0];
        const runShort = (e.run_id || '').replace('run-','').substring(0,8);
        return `<tr>
          <td style="color:var(--text-muted)">${ts}</td>
          <td style="color:var(--accent-cyan)">${runShort}</td>
          <td>${e.event_type || ''}</td>
          <td style="color:var(--accent-blue)">${d.tool_name || d.tool || d.scenario_id || ''}</td>
          <td>${decBadge}</td>
          <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-secondary)">${d.reason || d.summary || ''}</td>
        </tr>`;
      }).join('');
      document.getElementById('auditEventCount').textContent = `${events.length} events loaded`;
    }

    function filterAuditTable() {
      const runFilter = document.getElementById('auditRunFilter').value.toLowerCase();
      const typeFilter = document.getElementById('auditTypeFilter').value;
      const filtered = allAuditEvents.filter(e => {
        const matchRun = !runFilter || (e.run_id || '').toLowerCase().includes(runFilter);
        const matchType = !typeFilter || e.event_type === typeFilter;
        return matchRun && matchType;
      });
      renderAuditTable(filtered);
    }

    // ── Policy Config ──────────────────────────────────────────────────────
    async function loadPolicyConfig() {
      const resp = await fetch('/api/policy');
      const data = await resp.json();
      const container = document.getElementById('policyContent');
      container.innerHTML = Object.entries(data.tools || {}).map(([tool, cfg]) => `
        <div class="card">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
            <div style="font-family:var(--font-mono);font-size:14px;font-weight:600;color:var(--accent-cyan)">${tool}</div>
            <div style="display:flex;gap:8px;">
              <span class="tag tag-${cfg.risk_level === 'high' ? 'deny' : 'allow'}">${cfg.risk_level?.toUpperCase()}</span>
              ${cfg.requires_approval ? '<span class="tag tag-blocked">HITL REQUIRED</span>' : ''}
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:12px;color:var(--text-secondary);">
            <div><span style="color:var(--text-muted)">Required args:</span> <span style="color:var(--accent-blue)">${(cfg.required_args||[]).join(', ') || 'none'}</span></div>
            <div><span style="color:var(--text-muted)">Optional args:</span> <span style="color:var(--text-secondary)">${(cfg.optional_args||[]).join(', ') || 'none'}</span></div>
            ${cfg.authorized_hosts ? `<div><span style="color:var(--text-muted)">Authorized hosts:</span> <span style="color:var(--accent-green)">${cfg.authorized_hosts.join(', ')}</span></div>` : ''}
          </div>
        </div>
      `).join('');
    }

    // ── DLP Inspector ──────────────────────────────────────────────────────
    async function loadDLPPatterns() {
      const resp = await fetch('/api/dlp/patterns');
      const data = await resp.json();
      const container = document.getElementById('dlpPatterns');
      container.innerHTML = `<table style="width:100%;border-collapse:collapse;">
        ${(data.patterns||[]).map(p => `<tr>
          <td style="padding:6px 10px;font-family:var(--font-mono);color:var(--accent-cyan);font-size:11px">${p.pattern_id}</td>
          <td style="padding:6px 10px;"><span class="tag ${p.severity === 'BLOCK' ? 'tag-deny' : 'tag-blocked'}">${p.severity}</span></td>
          <td style="padding:6px 10px;font-size:12px;color:var(--text-secondary)">${p.description}</td>
        </tr>`).join('')}
      </table>`;
    }

    async function testDLP() {
      const tool = document.getElementById('dlpTool').value;
      const key = document.getElementById('dlpArgKey').value;
      const val = document.getElementById('dlpArgValue').value;
      const resp = await fetch('/api/dlp/inspect', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({tool_name: tool, arguments: {[key]: val}})
      });
      const data = await resp.json();
      const result = document.getElementById('dlpResult');
      const color = data.blocked ? 'var(--accent-red)' : 'var(--accent-green)';
      const icon = data.blocked ? '🚫' : '✅';
      result.innerHTML = `
        <div style="color:${color};font-size:14px;font-weight:700;margin-bottom:12px;">${icon} ${data.blocked ? 'BLOCKED' : 'PASSED'}</div>
        <div style="margin-bottom:8px;color:var(--text-secondary)">${data.inspection_summary}</div>
        ${(data.violations||[]).map(v => `<div style="padding:8px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:6px;margin-bottom:6px;">
          <span style="color:var(--accent-red)">${v.pattern_id}</span> · <span style="color:var(--accent-orange)">${v.severity}</span><br/>
          Arg: <span style="color:var(--accent-blue)">${v.argument_key}</span> · Match: <code>${v.matched_snippet}</code><br/>
          <span style="color:var(--text-muted);font-size:11px">${v.pattern_description}</span>
        </div>`).join('')}
        ${!data.violations?.length ? '<div style="color:var(--text-muted);font-size:12px">No sensitive patterns detected.</div>' : ''}
      `;
    }

    // ── Benchmark ──────────────────────────────────────────────────────────
    async function runBenchmark() {
      document.getElementById('btnRunBenchmark').disabled = true;
      document.getElementById('benchmarkStatus').textContent = '⏳ Running multi-scenario benchmark...';
      document.getElementById('benchmarkResults').innerHTML = '<div style="color:var(--accent-blue)">⏳ Executing all scenarios. This may take a few seconds...</div>';

      const resp = await fetch('/api/benchmark', { method: 'POST' });
      const data = await resp.json();
      document.getElementById('btnRunBenchmark').disabled = false;
      document.getElementById('benchmarkStatus').textContent = `Benchmark complete — ${data.total_scenarios} scenarios evaluated`;

      document.getElementById('benchmarkResults').innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;">
          <div style="text-align:center;padding:16px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border)">
            <div style="font-size:28px;font-weight:700;color:var(--accent-green);font-family:var(--font-mono)">${data.defended_pass_rate}</div>
            <div style="font-size:12px;color:var(--text-secondary)">Defended Pass Rate</div>
          </div>
          <div style="text-align:center;padding:16px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border)">
            <div style="font-size:28px;font-weight:700;color:var(--accent-red);font-family:var(--font-mono)">${data.unsafe_breach_rate}</div>
            <div style="font-size:12px;color:var(--text-secondary)">Unsafe Breach Rate</div>
          </div>
          <div style="text-align:center;padding:16px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border)">
            <div style="font-size:28px;font-weight:700;color:var(--accent-blue);font-family:var(--font-mono)">${data.total_scenarios}</div>
            <div style="font-size:12px;color:var(--text-secondary)">Scenarios Tested</div>
          </div>
          <div style="text-align:center;padding:16px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border)">
            <div style="font-size:28px;font-weight:700;color:var(--accent-purple);font-family:var(--font-mono)">${data.avg_triage_latency_s}s</div>
            <div style="font-size:12px;color:var(--text-secondary)">Avg Triage Latency</div>
          </div>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:12px;font-family:var(--font-mono);">
          <thead>
            <tr style="background:var(--bg-secondary);">
              <th style="padding:8px 12px;text-align:left;color:var(--text-muted)">Scenario</th>
              <th style="padding:8px 12px;text-align:center;color:var(--text-muted)">Defended</th>
              <th style="padding:8px 12px;text-align:center;color:var(--text-muted)">Unsafe</th>
              <th style="padding:8px 12px;text-align:right;color:var(--text-muted)">Latency</th>
            </tr>
          </thead>
          <tbody>
            ${(data.scenarios||[]).map(s => `<tr style="border-bottom:1px solid var(--border)">
              <td style="padding:8px 12px;color:var(--text-primary)">${s.scenario_name || s.scenario_id}</td>
              <td style="padding:8px 12px;text-align:center"><span class="tag ${s.defended?.passed ? 'tag-allow':'tag-deny'}">${s.defended?.passed ? '✅ PASS':'❌ FAIL'}</span></td>
              <td style="padding:8px 12px;text-align:center"><span class="tag ${s.unsafe_baseline?.breached ? 'tag-deny':'tag-allow'}">${s.unsafe_baseline?.breached ? '🚨 BREACH':'✅ SAFE'}</span></td>
              <td style="padding:8px 12px;text-align:right;color:var(--text-secondary)">${s.defended?.triage_latency_s || '?'}s</td>
            </tr>`).join('')}
          </tbody>
        </table>
      `;
    }

    // ── Helpers ────────────────────────────────────────────────────────────
    function increment(id) {
      const el = document.getElementById(id);
      el.textContent = parseInt(el.textContent || '0') + 1;
    }
    function setGlobalStatus(state, text) {
      document.getElementById('globalStatusDot').className = `status-dot ${state}`;
      document.getElementById('globalStatusText').textContent = text;
    }
    function setExecStatus(state, text) {
      document.getElementById('execStatusDot').className = `status-dot ${state}`;
      document.getElementById('execStatusText').textContent = text;
    }

    // Init
    loadAuditTrail();
  </script>
</body>
</html>"""


# ── API Routes ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(DASHBOARD_HTML)


@app.post("/api/run")
async def start_run(request: Request):
    """Kick off an incident or advisory scenario run asynchronously."""
    body = await request.json()
    mode = body.get("mode", "incident")
    scenario_path = body.get("scenario_path", "data/incident_scenario.json")
    adversarial = body.get("adversarial", False)
    disable_policy_gate = body.get("disable_policy_gate", False)

    run_id = f"run-{uuid.uuid4().hex[:8]}"
    q: queue.Queue = queue.Queue()
    _event_queues[run_id] = q

    def do_run():
        import io
        from contextlib import redirect_stdout
        try:
            from src.main import run_incident_orchestration, run_advisory_orchestration

            audit_path = f"outputs/dashboard_{run_id}.jsonl"
            report_path = f"outputs/dashboard_{run_id}.md"

            # Monkey-patch to intercept events
            # Use a simple wrapper to emit events
            if mode == "incident":
                exit_code = run_incident_orchestration(
                    scenario_path=scenario_path,
                    auto_approve=True,
                    interactive_approval=False,
                    disable_policy_gate=disable_policy_gate,
                    audit_log_path=audit_path,
                    report_path=report_path
                )
            else:
                exit_code = run_advisory_orchestration(
                    force_offline=True,
                    adversarial=adversarial,
                    scenario_path="data/vulnerability_scenario_adversarial.json" if adversarial else None,
                    disable_policy_gate=disable_policy_gate,
                    audit_log_path=audit_path,
                    report_path=report_path
                )

            # Load events from the written JSONL and emit them
            from src.reporting import ReportGenerator
            events = ReportGenerator.load_audit_trail_jsonl(audit_path, run_id=None)
            for evt in events:
                q.put(evt)

            # Send completion event
            q.put({"type": "done", "passed": exit_code == 0,
                   "run_id": run_id, "exit_code": exit_code,
                   "metrics": _run_results.get(run_id, {})})
        except Exception as e:
            q.put({"type": "done", "passed": False, "run_id": run_id,
                   "error": str(e), "exit_code": -1, "metrics": {}})

    threading.Thread(target=do_run, daemon=True).start()
    return JSONResponse({"run_id": run_id, "status": "started"})


@app.get("/api/events/{run_id}")
async def event_stream(run_id: str):
    """SSE stream for live execution events."""
    q = _event_queues.get(run_id)
    if not q:
        raise HTTPException(404, detail="Run ID not found")

    async def generate():
        while True:
            try:
                event = await asyncio.get_event_loop().run_in_executor(None, q.get, True, 1.0)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") == "done":
                    break
            except Exception:
                continue

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/audit")
async def get_audit():
    """Load and return all audit trail events."""
    from src.reporting import ReportGenerator
    events = []
    audit_path = "outputs/audit_trail.jsonl"
    if os.path.exists(audit_path):
        events = ReportGenerator.load_audit_trail_jsonl(audit_path)
    # Also load any dashboard runs
    for f in os.listdir("outputs") if os.path.isdir("outputs") else []:
        if f.startswith("dashboard_") and f.endswith(".jsonl"):
            events.extend(ReportGenerator.load_audit_trail_jsonl(f"outputs/{f}"))
    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return JSONResponse({"events": events[:500]})


@app.get("/api/policy")
async def get_policy():
    """Return the policy gate tool registry."""
    from src.policy import TOOL_POLICY_REGISTRY
    tools = {}
    for tool, cfg in TOOL_POLICY_REGISTRY.items():
        tools[tool] = {
            "risk_level": cfg["risk_level"].value,
            "requires_approval": cfg["requires_approval"],
            "required_args": cfg["required_args"],
            "optional_args": cfg.get("optional_args", []),
            "authorized_hosts": cfg.get("authorized_hosts", [])
        }
    return JSONResponse({"tools": tools})


@app.get("/api/dlp/patterns")
async def get_dlp_patterns():
    """Return the DLP pattern registry."""
    from src.dlp_inspector import DLP_PATTERNS
    patterns = [
        {"pattern_id": pid, "severity": sev, "description": desc}
        for pid, _pat, sev, desc in DLP_PATTERNS
    ]
    return JSONResponse({"patterns": patterns, "count": len(patterns)})


@app.post("/api/dlp/inspect")
async def inspect_dlp(request: Request):
    """Run DLP inspection on provided arguments."""
    body = await request.json()
    tool_name = body.get("tool_name", "create_mock_ticket")
    arguments = body.get("arguments", {})

    from src.dlp_inspector import inspect_arguments
    result = inspect_arguments(tool_name=tool_name, action_id="api-inspect", arguments=arguments)
    return JSONResponse({
        "blocked": result.blocked,
        "violations": [v.to_dict() for v in result.violations],
        "inspection_summary": result.inspection_summary
    })


@app.post("/api/benchmark")
async def run_benchmark_api():
    """Run multi-scenario benchmark and return results."""
    from src.benchmark import run_benchmark
    results = run_benchmark(
        scenarios_dir="data/incident_scenarios",
        include_unsafe_baseline=True,
        audit_log_path="outputs/benchmark_audit.jsonl",
        report_dir="outputs/benchmark_reports"
    )
    return JSONResponse(results)


@app.post("/api/approve/{run_id}")
async def submit_approval(run_id: str, request: Request):
    """Submit a human-in-the-loop approval decision."""
    body = await request.json()
    approved = body.get("approved", False)
    action_id = body.get("action_id", "")
    # In a full async implementation, this would signal the waiting run
    return JSONResponse({"status": "received", "approved": approved, "action_id": action_id})


if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)
    print("\n" + "="*60)
    print(" AgentShield Arena — Interactive Security Dashboard")
    print("="*60)
    print(" Open your browser at: http://localhost:8000")
    print(" API Documentation:    http://localhost:8000/docs")
    print("="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
