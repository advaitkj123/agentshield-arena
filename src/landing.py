"""AgentShield Arena — Apple-Style Cinematic Landing Page HTML."""

LANDING_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>AgentShield Arena — Adversarially Resilient AI Security</title>
  <meta name="description" content="The world's first adversarially resilient AI agent evaluation framework for IT incident response. Four-layer Policy Gate. Gemini AI Advisor. Real-time security."/>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --black: #000;
      --white: #fff;
      --gray-1: #f5f5f7;
      --gray-2: #d2d2d7;
      --gray-3: #86868b;
      --gray-4: #424245;
      --gray-5: #1d1d1f;
      --blue: #2997ff;
      --cyan: #06b6d4;
      --green: #30d158;
      --font: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    html { scroll-behavior: smooth; }
    body { background:#000; color:#f5f5f7; font-family:var(--font); overflow-x:hidden; -webkit-font-smoothing:antialiased; }

    /* NAV */
    nav {
      position:fixed; top:0; left:0; right:0; z-index:1000;
      height:52px;
      background:rgba(0,0,0,0.72);
      backdrop-filter:saturate(180%) blur(20px);
      -webkit-backdrop-filter:saturate(180%) blur(20px);
      display:flex; align-items:center; justify-content:space-between;
      padding:0 32px;
      border-bottom:1px solid rgba(255,255,255,0.08);
    }
    .nav-logo { display:flex; align-items:center; gap:10px; text-decoration:none; }
    .nav-logo .shield { width:28px; height:28px; background:linear-gradient(135deg,#2997ff,#06b6d4); border-radius:7px; display:flex; align-items:center; justify-content:center; font-size:15px; }
    .nav-logo span { font-size:15px; font-weight:600; color:#f5f5f7; letter-spacing:-0.3px; }
    .nav-links { display:flex; gap:28px; list-style:none; }
    .nav-links a { font-size:13px; color:rgba(245,245,247,0.7); text-decoration:none; transition:color 0.2s; }
    .nav-links a:hover { color:#2997ff; }
    .nav-cta { font-size:13px; font-weight:500; color:#2997ff; text-decoration:none; background:rgba(41,151,255,0.12); padding:6px 16px; border-radius:20px; border:1px solid rgba(41,151,255,0.3); transition:all 0.2s; }
    .nav-cta:hover { background:rgba(41,151,255,0.22); }

    /* PROGRESS */
    #progress-bar { position:fixed; top:52px; left:0; height:2px; background:linear-gradient(90deg,#2997ff,#06b6d4); z-index:999; width:0%; box-shadow:0 0 8px #2997ff88; pointer-events:none; }

    /* HERO */
    #hero-scroller { position:relative; height:800vh; }
    #hero-sticky { position:sticky; top:0; height:100vh; overflow:hidden; display:flex; flex-direction:column; align-items:center; justify-content:flex-end; }
    #hero-canvas-wrap { position:absolute; inset:0; }
    #hero-canvas { width:100%; height:100%; display:block; }
    #hero-gradient { position:absolute; inset:0; background:linear-gradient(to bottom,rgba(0,0,0,0.1) 0%,rgba(0,0,0,0) 30%,rgba(0,0,0,0) 55%,rgba(0,0,0,0.9) 100%); pointer-events:none; }
    #hero-text-wrap { position:relative; z-index:10; text-align:center; padding:0 24px 90px; width:100%; max-width:900px; margin:0 auto; }
    .hero-badge { display:inline-flex; align-items:center; gap:8px; background:rgba(255,255,255,0.08); border:1px solid rgba(255,255,255,0.15); border-radius:980px; padding:6px 14px 6px 10px; font-size:12px; color:rgba(255,255,255,0.7); margin-bottom:20px; backdrop-filter:blur(10px); }
    .hero-badge .dot { width:6px; height:6px; background:#30d158; border-radius:50%; animation:pulse 2s infinite; }
    @keyframes pulse { 0%,100%{box-shadow:0 0 0 0 rgba(48,209,88,0.5)}50%{box-shadow:0 0 0 5px rgba(48,209,88,0)} }
    #hero-title { font-size:clamp(40px,7vw,88px); font-weight:800; line-height:1.02; letter-spacing:-0.04em; color:#fff; margin-bottom:18px; }
    #hero-subtitle { font-size:clamp(16px,2.2vw,22px); font-weight:400; color:rgba(245,245,247,0.72); margin-bottom:44px; max-width:620px; margin-left:auto; margin-right:auto; line-height:1.5; }
    .hero-btns { display:flex; gap:14px; justify-content:center; flex-wrap:wrap; }
    .btn-primary { display:inline-flex; align-items:center; gap:8px; background:#2997ff; color:#fff; font-size:17px; font-weight:600; padding:14px 28px; border-radius:980px; text-decoration:none; transition:background 0.2s,transform 0.15s; letter-spacing:-0.2px; }
    .btn-primary:hover { background:#0077ed; transform:scale(1.03); }
    .btn-secondary { display:inline-flex; align-items:center; gap:6px; background:rgba(255,255,255,0.1); color:#fff; font-size:17px; font-weight:500; padding:14px 28px; border-radius:980px; text-decoration:none; border:1px solid rgba(255,255,255,0.2); transition:background 0.2s,transform 0.15s; backdrop-filter:blur(10px); }
    .btn-secondary:hover { background:rgba(255,255,255,0.18); transform:scale(1.03); }

    /* scroll hint */
    .scroll-hint { position:absolute; bottom:28px; left:50%; transform:translateX(-50%); display:flex; flex-direction:column; align-items:center; gap:8px; z-index:20; transition:opacity 0.4s; }
    .scroll-hint span { font-size:11px; letter-spacing:0.1em; text-transform:uppercase; color:rgba(255,255,255,0.35); }
    .scroll-mouse { width:22px; height:34px; border:1.5px solid rgba(255,255,255,0.25); border-radius:11px; display:flex; justify-content:center; padding-top:6px; }
    .scroll-wheel { width:3px; height:6px; background:rgba(255,255,255,0.45); border-radius:2px; animation:sw 2s infinite; }
    @keyframes sw { 0%,100%{opacity:1;transform:translateY(0)}50%{opacity:0.3;transform:translateY(6px)} }

    /* TAGLINE */
    #tagline { background:#000; padding:120px 48px; text-align:center; }
    #tagline h2 { font-size:clamp(32px,5vw,56px); font-weight:700; letter-spacing:-0.03em; line-height:1.08; background:linear-gradient(135deg,#f5f5f7 0%,#86868b 100%); -webkit-background-clip:text; -webkit-text-fill-color:transparent; max-width:800px; margin:0 auto 24px; }
    #tagline p { font-size:19px; color:#86868b; max-width:580px; margin:0 auto; line-height:1.6; }

    /* STATS */
    .stats-row { display:grid; grid-template-columns:repeat(4,1fr); gap:1px; background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.07); border-radius:20px; overflow:hidden; margin:60px auto; max-width:1000px; }
    .stat-cell { background:#0d0d0d; padding:40px 24px; text-align:center; }
    .stat-num { font-size:clamp(36px,5vw,52px); font-weight:800; letter-spacing:-0.04em; color:#2997ff; display:block; margin-bottom:6px; }
    .stat-lbl { font-size:13px; color:#86868b; }

    /* FEATURES */
    #features { background:#000; padding:80px 24px 120px; }
    .sec-label { text-align:center; font-size:13px; font-weight:600; letter-spacing:0.1em; text-transform:uppercase; color:#2997ff; margin-bottom:14px; }
    .sec-heading { text-align:center; font-size:clamp(28px,4vw,48px); font-weight:700; letter-spacing:-0.025em; color:#f5f5f7; margin-bottom:64px; line-height:1.1; }
    .feat-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:14px; max-width:1100px; margin:0 auto; }
    @media(max-width:900px){.feat-grid{grid-template-columns:repeat(2,1fr);}}
    @media(max-width:600px){.feat-grid{grid-template-columns:1fr;}}
    .feat-card { background:#0d0d0d; border:1px solid rgba(255,255,255,0.08); border-radius:20px; padding:32px 28px; transition:transform 0.25s,border-color 0.25s,box-shadow 0.25s; position:relative; overflow:hidden; }
    .feat-card::before { content:''; position:absolute; inset:0; background:radial-gradient(600px circle at var(--mx,50%) var(--my,50%),rgba(41,151,255,0.06),transparent 60%); opacity:0; transition:opacity 0.3s; pointer-events:none; }
    .feat-card:hover::before { opacity:1; }
    .feat-card:hover { border-color:rgba(41,151,255,0.3); box-shadow:0 0 40px rgba(41,151,255,0.07); transform:translateY(-4px); }
    .feat-card.span2 { grid-column:span 2; }
    .feat-icon { width:48px; height:48px; background:rgba(41,151,255,0.1); border-radius:13px; display:flex; align-items:center; justify-content:center; font-size:22px; margin-bottom:20px; border:1px solid rgba(41,151,255,0.18); }
    .feat-card h3 { font-size:18px; font-weight:600; color:#f5f5f7; margin-bottom:10px; letter-spacing:-0.02em; }
    .feat-card p { font-size:14px; color:#86868b; line-height:1.65; }
    .feat-tag { display:inline-block; margin-top:14px; font-size:11px; font-weight:600; letter-spacing:0.06em; text-transform:uppercase; color:#30d158; background:rgba(48,209,88,0.1); padding:4px 10px; border-radius:20px; border:1px solid rgba(48,209,88,0.2); }
    .feat-tag.blue { color:#2997ff; background:rgba(41,151,255,0.1); border-color:rgba(41,151,255,0.2); }

    /* HOW IT WORKS */
    #howitworks { background:#080808; padding:120px 24px; }
    .pipeline { display:flex; align-items:flex-start; justify-content:center; gap:0; max-width:1000px; margin:0 auto; flex-wrap:wrap; }
    .pipe-step { flex:1; min-width:140px; text-align:center; padding:0 8px; position:relative; }
    .pipe-step:not(:last-child)::after { content:'→'; position:absolute; right:-8px; top:24px; font-size:18px; color:rgba(41,151,255,0.35); }
    .pipe-icon { width:56px; height:56px; background:linear-gradient(135deg,rgba(41,151,255,0.15),rgba(6,182,212,0.12)); border:1px solid rgba(41,151,255,0.22); border-radius:16px; display:flex; align-items:center; justify-content:center; font-size:24px; margin:0 auto 14px; transition:transform 0.25s,border-color 0.25s; }
    .pipe-step:hover .pipe-icon { transform:scale(1.1); border-color:#2997ff; }
    .pipe-lbl { font-size:13px; font-weight:600; color:#f5f5f7; margin-bottom:5px; }
    .pipe-desc { font-size:11px; color:#86868b; line-height:1.5; }

    /* INTEGRATIONS */
    #integrations { background:#000; padding:80px 24px; text-align:center; border-top:1px solid rgba(255,255,255,0.06); border-bottom:1px solid rgba(255,255,255,0.06); }
    .int-lbl { font-size:12px; letter-spacing:0.1em; text-transform:uppercase; color:#86868b; margin-bottom:32px; }
    .int-chips { display:flex; gap:10px; flex-wrap:wrap; justify-content:center; }
    .int-chip { display:flex; align-items:center; gap:8px; background:#0d0d0d; border:1px solid rgba(255,255,255,0.09); border-radius:12px; padding:10px 18px; font-size:13px; font-weight:500; color:#f5f5f7; transition:border-color 0.2s,transform 0.2s; }
    .int-chip:hover { border-color:#2997ff; transform:translateY(-2px); }
    .int-chip em { font-size:16px; font-style:normal; }

    /* CTA */
    #cta { background:#000; padding:140px 24px; text-align:center; position:relative; overflow:hidden; }
    #cta::before { content:''; position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); width:600px; height:400px; background:radial-gradient(ellipse at center,rgba(41,151,255,0.12),transparent 70%); pointer-events:none; }
    #cta h2 { font-size:clamp(32px,5vw,56px); font-weight:700; letter-spacing:-0.03em; color:#f5f5f7; margin-bottom:20px; position:relative; }
    #cta p { font-size:19px; color:#86868b; margin-bottom:48px; max-width:500px; margin-left:auto; margin-right:auto; position:relative; }
    .cta-btns { display:flex; gap:14px; justify-content:center; flex-wrap:wrap; position:relative; }

    /* FOOTER */
    footer { background:#0d0d0d; border-top:1px solid rgba(255,255,255,0.07); padding:40px 48px; }
    .foot-inner { max-width:1100px; margin:0 auto; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:16px; }
    .foot-copy { font-size:13px; color:#86868b; }
    .foot-links { display:flex; gap:20px; }
    .foot-links a { font-size:13px; color:#86868b; text-decoration:none; transition:color 0.2s; }
    .foot-links a:hover { color:#2997ff; }

    /* FADE-UP */
    .fu { opacity:0; transform:translateY(28px); transition:opacity 0.7s ease,transform 0.7s ease; }
    .fu.in { opacity:1; transform:translateY(0); }
    .fd1 { transition-delay:0.1s; } .fd2 { transition-delay:0.2s; } .fd3 { transition-delay:0.3s; }

    ::-webkit-scrollbar { width:5px; }
    ::-webkit-scrollbar-track { background:#000; }
    ::-webkit-scrollbar-thumb { background:#222; border-radius:3px; }
    ::-webkit-scrollbar-thumb:hover { background:#2997ff; }
  </style>
</head>
<body>

<nav>
  <a class="nav-logo" href="/">
    <div class="shield">🛡️</div>
    <span>AgentShield Arena</span>
  </a>
  <ul class="nav-links">
    <li><a href="#features">Features</a></li>
    <li><a href="#howitworks">Architecture</a></li>
    <li><a href="/docs">API</a></li>
    <li><a href="https://github.com/advaitkj123/agentshield-arena" target="_blank">GitHub ↗</a></li>
  </ul>
  <a href="/dashboard" class="nav-cta">Open Dashboard →</a>
</nav>

<div id="progress-bar"></div>

<!-- HERO SCROLL SEQUENCE -->
<div id="hero-scroller">
  <div id="hero-sticky">
    <div id="hero-canvas-wrap">
      <canvas id="hero-canvas"></canvas>
    </div>
    <div id="hero-gradient"></div>
    <div id="hero-text-wrap">
      <div class="hero-badge">
        <div class="dot"></div>
        Adversarially Resilient AI · Live
      </div>
      <h1 id="hero-title">Defend Every<br/>AI Decision.</h1>
      <p id="hero-subtitle">The world's first framework that pits real adversarial AI attacks against a deterministic four-layer Policy Gate — and proves your agents are safe every time.</p>
      <div class="hero-btns">
        <a href="/dashboard" class="btn-primary">Enter Dashboard →</a>
        <a href="#features" class="btn-secondary">See Features</a>
      </div>
    </div>
    <div class="scroll-hint" id="scroll-hint">
      <div class="scroll-mouse"><div class="scroll-wheel"></div></div>
      <span>Scroll to explore</span>
    </div>
  </div>
</div>

<!-- TAGLINE -->
<div id="tagline">
  <h2 class="fu">Attack the Workflow.<br/>Defend the Mission.</h2>
  <p class="fu fd1">Real adversarial attacks. Deterministic defenses. Sub-millisecond response. No LLM has ever beaten it.</p>
</div>

<!-- STATS -->
<div style="background:#000;padding:0 24px;">
  <div class="stats-row fu">
    <div class="stat-cell">
      <span class="stat-num" data-target="100">0</span>
      <span class="stat-lbl">Defended Pass Rate %</span>
    </div>
    <div class="stat-cell">
      <span class="stat-num" data-target="67">0</span>
      <span class="stat-lbl">Tests Passing</span>
    </div>
    <div class="stat-cell">
      <span class="stat-num" data-target="6">0</span>
      <span class="stat-lbl">Attack Scenarios</span>
    </div>
    <div class="stat-cell">
      <span class="stat-num">&lt;1ms</span>
      <span class="stat-lbl">Mean Time to Defend</span>
    </div>
  </div>
</div>

<!-- FEATURES -->
<div id="features">
  <div class="sec-label fu">Capabilities</div>
  <div class="sec-heading fu fd1">Everything you need to trust your AI agents.</div>
  <div class="feat-grid">
    <div class="feat-card span2 fu" onmousemove="cardGlow(event,this)">
      <div class="feat-icon">🛡️</div>
      <h3>Four-Layer Policy Gate</h3>
      <p>Every tool call passes through four independent enforcement layers — tool allowlist, argument schema validation, Human-in-the-Loop approval, and Semantic DLP inspection — all deterministic code, completely outside LLM influence. Security guarantees don't rely on model compliance.</p>
      <span class="feat-tag blue">Core Architecture</span>
    </div>
    <div class="feat-card fu fd1" onmousemove="cardGlow(event,this)">
      <div class="feat-icon">🤖</div>
      <h3>Gemini AI Advisor</h3>
      <p>Floating chatbot powered by Gemini 2.0 Flash. Explains every policy decision, analyzes incidents in real-time, and answers cybersecurity questions with full session context.</p>
      <span class="feat-tag">New</span>
    </div>
    <div class="feat-card fu" onmousemove="cardGlow(event,this)">
      <div class="feat-icon">🔍</div>
      <h3>Semantic DLP Inspector</h3>
      <p>13 regex patterns detect credentials, AWS keys, shadow file paths, and exfiltration attempts inside permitted tool arguments — stopping what a firewall can't.</p>
    </div>
    <div class="feat-card fu fd1" onmousemove="cardGlow(event,this)">
      <div class="feat-icon">⚔️</div>
      <h3>6 Adversarial Scenarios</h3>
      <p>MITRE ATT&amp;CK + OWASP LLM Top 10 mapped attacks. Indirect prompt injection, credential exfil, privilege escalation — all benchmarked automatically.</p>
    </div>
    <div class="feat-card fu fd2" onmousemove="cardGlow(event,this)">
      <div class="feat-icon">📧</div>
      <h3>Email &amp; Telegram Alerts</h3>
      <p>Brevo transactional emails + Telegram push for every policy block, DLP violation, HITL request, and benchmark completion. Real governance, real-time.</p>
      <span class="feat-tag">New</span>
    </div>
    <div class="feat-card fu" onmousemove="cardGlow(event,this)">
      <div class="feat-icon">🧑‍⚖️</div>
      <h3>Human-in-the-Loop</h3>
      <p>High-risk actions pause and require explicit operator approval — with email + Telegram prompts — before the sandbox ever executes them.</p>
    </div>
    <div class="feat-card fu fd1" onmousemove="cardGlow(event,this)">
      <div class="feat-icon">📊</div>
      <h3>7 Evaluation Metrics</h3>
      <p>TCR, UAER, ASR, FBR, ACR, MTTD, and Threat Score — composited into a live radar chart and benchmarked against the unsafe baseline.</p>
    </div>
    <div class="feat-card fu fd2" onmousemove="cardGlow(event,this)">
      <div class="feat-icon">📺</div>
      <h3>Live Streaming Dashboard</h3>
      <p>FastAPI + Server-Sent Events stream every policy decision directly into the browser. Radar charts, audit trail browser, benchmark comparisons — all real-time dark-mode UI.</p>
      <span class="feat-tag blue">Open Source</span>
    </div>
    <div class="feat-card fu" onmousemove="cardGlow(event,this)">
      <div class="feat-icon">🔐</div>
      <h3>Immutable Audit Trail</h3>
      <p>Append-only JSONL with run ID isolation. Every action, decision, and violation is permanently logged and queryable from the dashboard.</p>
    </div>
  </div>
</div>

<!-- HOW IT WORKS -->
<div id="howitworks">
  <div class="sec-label fu" style="text-align:center;">Architecture</div>
  <div class="sec-heading fu fd1" style="text-align:center;">From attack to audit in milliseconds.</div>
  <div class="pipeline">
    <div class="pipe-step fu">
      <div class="pipe-icon">☠️</div>
      <div class="pipe-lbl">Red Agent</div>
      <div class="pipe-desc">Injects adversarial payloads into incident data</div>
    </div>
    <div class="pipe-step fu fd1">
      <div class="pipe-icon">🤖</div>
      <div class="pipe-lbl">Blue Agent</div>
      <div class="pipe-desc">LLM or deterministic investigator reads the incident</div>
    </div>
    <div class="pipe-step fu fd2">
      <div class="pipe-icon">🚦</div>
      <div class="pipe-lbl">Policy Gate</div>
      <div class="pipe-desc">4-layer deterministic enforcement</div>
    </div>
    <div class="pipe-step fu">
      <div class="pipe-icon">🧑‍⚖️</div>
      <div class="pipe-lbl">HITL</div>
      <div class="pipe-desc">Human approval for high-risk actions</div>
    </div>
    <div class="pipe-step fu fd1">
      <div class="pipe-icon">📦</div>
      <div class="pipe-lbl">Sandbox</div>
      <div class="pipe-desc">Only verified actions reach mock IT env</div>
    </div>
    <div class="pipe-step fu fd2">
      <div class="pipe-icon">📋</div>
      <div class="pipe-lbl">Audit Trail</div>
      <div class="pipe-desc">Append-only log + alerts</div>
    </div>
  </div>
</div>

<!-- INTEGRATIONS -->
<div id="integrations">
  <div class="int-lbl fu">Works with your stack</div>
  <div class="int-chips">
    <div class="int-chip fu"><em>🧠</em> Google Gemini</div>
    <div class="int-chip fu fd1"><em>🤖</em> OpenAI GPT-4</div>
    <div class="int-chip fu fd2"><em>📧</em> Brevo Email</div>
    <div class="int-chip fu"><em>📱</em> Telegram Bot</div>
    <div class="int-chip fu fd1"><em>⚡</em> FastAPI + SSE</div>
    <div class="int-chip fu fd2"><em>📊</em> Chart.js</div>
    <div class="int-chip fu"><em>🔒</em> MITRE ATT&amp;CK</div>
    <div class="int-chip fu fd1"><em>🐙</em> GitHub Actions CI</div>
    <div class="int-chip fu fd2"><em>🐍</em> Python 3.11+</div>
  </div>
</div>

<!-- CTA -->
<div id="cta">
  <h2 class="fu">Ready to defend your AI?</h2>
  <p class="fu fd1">Launch the dashboard and run your first adversarial benchmark in seconds.</p>
  <div class="cta-btns fu fd2">
    <a href="/dashboard" class="btn-primary">🚀 Enter Dashboard</a>
    <a href="/docs" class="btn-secondary">📖 API Reference</a>
  </div>
</div>

<!-- FOOTER -->
<footer>
  <div class="foot-inner">
    <span class="foot-copy">© 2025 AgentShield Arena · MIT License · 67 tests passing</span>
    <div class="foot-links">
      <a href="/dashboard">Dashboard</a>
      <a href="/docs">API Docs</a>
      <a href="https://github.com/advaitkj123/agentshield-arena" target="_blank">GitHub</a>
      <a href="/api/integrations/status">Integrations</a>
    </div>
  </div>
</footer>

<script>
// ── Image Sequence Scroll-Scrubber ────────────────────────────────────────────
const TOTAL = 100;
const BASE = '/hero/gemini_generated_video_8435859a_000/gemini_generated_video_8435859a_';
const canvas = document.getElementById('hero-canvas');
const ctx = canvas.getContext('2d');
const images = new Array(TOTAL);
let curFrame = 0;

function frameUrl(i) {
  return BASE + String(i).padStart(3,'0') + '.jpg';
}
function resize() {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  renderFrame(curFrame);
}
function renderFrame(idx) {
  const img = images[idx];
  if (!img || !img.complete || !img.naturalWidth) return;
  const cw = canvas.width, ch = canvas.height;
  const iw = img.naturalWidth, ih = img.naturalHeight;
  const s = Math.max(cw/iw, ch/ih);
  const dw = iw*s, dh = ih*s;
  ctx.drawImage(img, (cw-dw)/2, (ch-dh)/2, dw, dh);
}
function preload() {
  for (let i = 0; i < TOTAL; i++) {
    const img = new Image();
    img.onload = () => { if(i===0) renderFrame(0); };
    img.src = frameUrl(i);
    images[i] = img;
  }
}
window.addEventListener('resize', resize, {passive:true});
resize();
preload();

// ── Scroll handler ────────────────────────────────────────────────────────────
const heroScroller = document.getElementById('hero-scroller');
const progressBar = document.getElementById('progress-bar');
const scrollHint = document.getElementById('scroll-hint');

window.addEventListener('scroll', () => {
  // Global progress
  const docH = document.documentElement.scrollHeight - window.innerHeight;
  const globalPct = docH > 0 ? (window.scrollY / docH) * 100 : 0;
  progressBar.style.width = globalPct + '%';

  // Hero image scrubbing
  const rect = heroScroller.getBoundingClientRect();
  const scrolled = -rect.top;
  const total = heroScroller.clientHeight - window.innerHeight;
  const frac = Math.max(0, Math.min(1, scrolled / total));
  const frame = Math.min(TOTAL-1, Math.floor(frac * (TOTAL-1)));
  if (frame !== curFrame) { curFrame = frame; renderFrame(frame); }

  // scroll hint fade
  scrollHint.style.opacity = frac < 0.03 ? '1' : '0';
}, {passive:true});

// ── Fade-up observer ──────────────────────────────────────────────────────────
const obs = new IntersectionObserver(entries => {
  entries.forEach(e => { if(e.isIntersecting) e.target.classList.add('in'); });
}, {threshold: 0.12});
document.querySelectorAll('.fu').forEach(el => obs.observe(el));

// ── Stat counters ─────────────────────────────────────────────────────────────
const statObs = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if(e.isIntersecting && e.target.dataset.target) {
      const t = parseInt(e.target.dataset.target);
      const start = performance.now();
      const dur = 1400;
      function tick(now) {
        const p = Math.min((now-start)/dur, 1);
        const ease = 1 - Math.pow(1-p, 3);
        e.target.textContent = Math.floor(ease*t);
        if(p<1) requestAnimationFrame(tick);
        else e.target.textContent = t;
      }
      requestAnimationFrame(tick);
      statObs.unobserve(e.target);
    }
  });
}, {threshold:0.5});
document.querySelectorAll('.stat-num[data-target]').forEach(el => statObs.observe(el));

// ── Feature card glow ─────────────────────────────────────────────────────────
function cardGlow(e, card) {
  const r = card.getBoundingClientRect();
  card.style.setProperty('--mx', ((e.clientX - r.left)/r.width*100)+'%');
  card.style.setProperty('--my', ((e.clientY - r.top)/r.height*100)+'%');
}
</script>
</body>
</html>"""
