"""AgentShield Arena — FastAPI JSON API.

Pure JSON/SSE backend for the React + shadcn/ui frontend (agentshield-arena/frontend).
No embedded HTML — the dashboard and landing page are a separate built SPA,
served as static files when present (frontend/dist), with the Vite dev
server proxying /api during development.

Features:
  - Real-time live execution of incident and advisory scenarios (SSE events
    are pushed the instant they're recorded, not replayed after the run ends)
  - Working Human-in-the-Loop approval (the run actually blocks and resumes)
  - Policy Gate decision visualization, DLP inspection, audit trail browsing
  - Multi-scenario benchmarking as a background job with progress polling
  - GraphSAGE-style attack-graph risk scoring + 3D visualization data
  - Attack replay timeline data and a policy-gate what-if simulator
  - Auto-generated executive incident reports

Usage:
    pip install -r requirements.txt
    python src/dashboard.py

Then open: http://localhost:8000 (serves the built frontend if present)
or run `npm run dev` in frontend/ for the dev server at http://localhost:5173
"""

import copy
import json
import logging
import os
import sys
import time
import uuid
import asyncio
import threading
from typing import Any, Dict, List, Optional, Tuple

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form
    from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    print("[-] FastAPI not installed. Run: pip install fastapi uvicorn")
    sys.exit(1)

from src.schemas import ApprovalToken

logger = logging.getLogger("agentshield.dashboard")


# ── App Setup ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="AgentShield Arena",
    description="Adversarially Resilient AI Security Platform",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve hero images as static files — used by the landing page's scroll-scrubbed
# canvas animation (frames: hero/gemini_generated_video_8435859a_000/*.jpg).
_hero_dir = os.path.join(PROJECT_ROOT, "hero")
if os.path.isdir(_hero_dir):
    app.mount("/hero", StaticFiles(directory=_hero_dir), name="hero")

# Downloadable CSV sample datasets for the live "Upload Dataset" demo feature.
_csv_samples_dir = os.path.join(PROJECT_ROOT, "data", "csv_samples")
if os.path.isdir(_csv_samples_dir):
    app.mount("/samples", StaticFiles(directory=_csv_samples_dir), name="csv-samples")

_FRONTEND_DIST = os.path.join(PROJECT_ROOT, "frontend", "dist")
_FRONTEND_ASSETS = os.path.join(_FRONTEND_DIST, "assets")
if os.path.isdir(_FRONTEND_ASSETS):
    app.mount("/assets", StaticFiles(directory=_FRONTEND_ASSETS), name="frontend-assets")


# ── In-memory run state ────────────────────────────────────────────────────

class RunChannel:
    """Replayable, multi-subscriber event log for one run.

    SSE subscribers read from an index instead of popping from a shared queue,
    so a reconnect (network blip, React StrictMode's double-mount, a second
    browser tab) replays the full history instead of silently losing events.
    """

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []
        self.done = False
        self._cond = threading.Condition()

    def publish(self, evt: Dict[str, Any]) -> None:
        with self._cond:
            self.events.append(evt)
            if evt.get("type") == "done":
                self.done = True
            self._cond.notify_all()

    def read_from(self, index: int, timeout: float) -> Tuple[List[Dict[str, Any]], bool]:
        with self._cond:
            if index >= len(self.events) and not self.done:
                self._cond.wait(timeout)
            return self.events[index:], self.done


_channels: Dict[str, RunChannel] = {}
_run_meta: Dict[str, Dict[str, Any]] = {}            # run_id -> metadata (status, source, label, ...)
_pending_approvals: Dict[str, Dict[str, Any]] = {}   # "run_id:action_id" -> {event, approved}
_benchmark_jobs: Dict[str, Dict[str, Any]] = {}      # job_id -> {status, result, created_at}
_benchmark_lock = threading.Lock()

_RUN_TTL_SECONDS = 3600
_APPROVAL_TIMEOUT_SECONDS = 120
_SAMPLES_DIR = os.path.join(PROJECT_ROOT, "data", "csv_samples")
_SCENARIO_ROOTS = (os.path.join(PROJECT_ROOT, "data"), os.path.join(PROJECT_ROOT, "outputs", "uploads"))
_UPLOAD_KINDS = ("tickets", "logs", "mixed")


def _cleanup_stale_state() -> None:
    """Evict finished run/benchmark state older than TTL to stop unbounded growth."""
    now = time.time()
    for rid in [r for r, m in _run_meta.items()
                if m.get("status") != "running" and now - m.get("created_at", now) > _RUN_TTL_SECONDS]:
        _run_meta.pop(rid, None)
        _channels.pop(rid, None)
    for jid in [j for j, m in _benchmark_jobs.items()
                if m.get("status") != "running" and now - m.get("created_at", now) > _RUN_TTL_SECONDS]:
        _benchmark_jobs.pop(jid, None)


def _safe_scenario_path(path: str) -> str:
    """Resolve a client-supplied scenario path, refusing anything outside data/ or
    outputs/uploads/ — the API must never become an arbitrary-file reader."""
    candidate = os.path.realpath(path if os.path.isabs(path) else os.path.join(PROJECT_ROOT, path))
    for root in _SCENARIO_ROOTS:
        root_real = os.path.realpath(root)
        try:
            inside = os.path.commonpath([candidate, root_real]) == root_real
        except ValueError:  # different drives on Windows
            inside = False
        if inside and candidate.lower().endswith(".json"):
            if not os.path.isfile(candidate):
                raise HTTPException(404, detail="Scenario file not found.")
            return candidate
    raise HTTPException(400, detail="scenario_path must point to a .json scenario under data/.")


def _authorized_hosts() -> List[str]:
    from src.policy import TOOL_POLICY_REGISTRY
    return list(TOOL_POLICY_REGISTRY["simulate_endpoint_isolation"].get("authorized_hosts", []))


def _all_audit_log_paths() -> List[str]:
    paths = ["outputs/audit_trail.jsonl", "outputs/benchmark_audit_trail.jsonl"]
    if os.path.isdir("outputs"):
        for f in sorted(os.listdir("outputs")):
            if f.startswith("dashboard_") and f.endswith(".jsonl"):
                paths.append(f"outputs/{f}")
    return paths


def _load_all_audit_events(run_id: Optional[str] = None) -> List[Dict[str, Any]]:
    from src.reporting import ReportGenerator
    events: List[Dict[str, Any]] = []
    for path in _all_audit_log_paths():
        if os.path.exists(path):
            events.extend(ReportGenerator.load_audit_trail_jsonl(path, run_id=run_id))
    return events


def _events_for_run(run_id: str) -> List[Dict[str, Any]]:
    """Audit events for one run — from the live channel while it's in memory (so the
    graph/replay/report views work mid-run), otherwise from the JSONL logs on disk."""
    channel = _channels.get(run_id)
    if channel is not None:
        events = [e for e in channel.events if "event_type" in e]
        if events:
            return events
    return _load_all_audit_events(run_id=run_id)


def _find_scenario_path_by_id(scenario_id: Optional[str]) -> Optional[str]:
    if not scenario_id:
        return None
    from src.benchmark import discover_scenarios
    candidates = discover_scenarios("data/incident_scenarios") + ["data/incident_scenario.json"]
    if scenario_id.startswith("UPLOADED-"):
        candidates.append(f"outputs/uploads/{scenario_id[len('UPLOADED-'):]}.json")
    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("scenario_metadata", {}).get("scenario_id") == scenario_id:
                return path
        except Exception:
            continue
    return None


def _resolve_scenario_for_run(run_id: str, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Best-effort: recover the originating scenario JSON for a run, for graph/report enrichment."""
    scenario_path = _run_meta.get(run_id, {}).get("scenario_path")
    if not scenario_path or not os.path.exists(scenario_path):
        scenario_loaded = next((e for e in events if e.get("event_type") == "SCENARIO_LOADED"), None)
        scenario_id = scenario_loaded.get("details", {}).get("scenario_id") if scenario_loaded else None
        scenario_path = _find_scenario_path_by_id(scenario_id)
    if not scenario_path or not os.path.exists(scenario_path):
        return None
    try:
        with open(scenario_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _load_samples_manifest() -> List[Dict[str, Any]]:
    path = os.path.join(_SAMPLES_DIR, "manifest.json")
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f).get("samples", [])


def _launch_run(
    *,
    mode: str,
    run_kwargs: Dict[str, Any],
    meta: Dict[str, Any],
    expected_outcome: Optional[Dict[str, Any]] = None,
    auto_approve: bool = False,
    ground_truth: Optional[Dict[str, Any]] = None,
    preview: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Start a run on a background thread with a replayable live channel.

    One code path for curated scenarios, CSV uploads and one-click samples, so
    they all get identical live streaming, HITL handling, metrics and grading.
    """
    _cleanup_stale_state()
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    channel = RunChannel()
    _channels[run_id] = channel
    _run_meta[run_id] = {
        "run_id": run_id, "created_at": time.time(), "status": "running", "exit_code": None,
        "passed": None, "auto_approve": auto_approve, "has_ground_truth": ground_truth is not None,
        **meta,
    }

    def approval_provider(action) -> ApprovalToken:
        key = f"{run_id}:{action.action_id}"
        ev = threading.Event()
        _pending_approvals[key] = {"event": ev, "approved": False}
        channel.publish({
            "type": "approval_required", "run_id": run_id, "action_id": action.action_id,
            "tool_name": action.tool_name, "arguments": action.arguments,
            "timeout_s": _APPROVAL_TIMEOUT_SECONDS,
        })
        resolved_in_time = ev.wait(timeout=_APPROVAL_TIMEOUT_SECONDS)
        entry = _pending_approvals.pop(key, {"approved": False})
        approved = bool(resolved_in_time and entry.get("approved"))
        channel.publish({
            "type": "approval_resolved", "run_id": run_id, "action_id": action.action_id,
            "approved": approved, "timed_out": not resolved_in_time,
        })
        return ApprovalToken(
            token_id=f"tok-{uuid.uuid4().hex[:6]}", action_id=action.action_id,
            tool_name=action.tool_name, approver_id="dashboard_operator", approved=approved,
        )

    kwargs = dict(
        run_kwargs,
        on_event=channel.publish,
        run_id=run_id,
        audit_log_path=f"outputs/dashboard_{run_id}.jsonl",
        report_path=f"outputs/dashboard_{run_id}.md",
        notify=True,
    )

    def do_run():
        from src.main import run_incident_orchestration, run_advisory_orchestration
        from src.evaluation import Evaluator
        try:
            if mode == "incident":
                if not auto_approve:
                    kwargs["approval_provider"] = approval_provider
                exit_code = run_incident_orchestration(**kwargs)
            else:
                exit_code = run_advisory_orchestration(**kwargs)

            events = [e for e in channel.events if "event_type" in e]
            metrics = Evaluator(run_id=run_id).evaluate_run(events, expected_outcome).metrics
            done: Dict[str, Any] = {
                "type": "done", "passed": exit_code == 0, "run_id": run_id,
                "exit_code": exit_code, "metrics": metrics,
            }
            if mode == "incident" and (ground_truth is not None or preview is not None):
                from src.accuracy import grade_run
                done["accuracy"] = grade_run(events, preview, ground_truth)
            _run_meta[run_id].update(status="done", exit_code=exit_code, passed=exit_code == 0, metrics=metrics)
            channel.publish(done)
        except Exception as e:
            logger.exception("Run %s failed", run_id)
            _run_meta[run_id].update(status="error", error=str(e), passed=False)
            channel.publish({"type": "done", "passed": False, "run_id": run_id, "error": str(e),
                             "exit_code": -1, "metrics": {}})

    _run_meta[run_id]["_ground_truth"] = ground_truth
    _run_meta[run_id]["_preview"] = preview
    threading.Thread(target=do_run, daemon=True, name=f"run-{run_id}").start()
    return run_id


def _public_meta(meta: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in meta.items() if not k.startswith("_")}


# ── Scenario Runs ────────────────────────────────────────────────────────────

@app.get("/api/scenarios")
def list_scenarios():
    """Dynamic scenario catalog, discovered from data/incident_scenarios/."""
    from src.benchmark import discover_scenarios
    out = []
    for path in discover_scenarios("data/incident_scenarios"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        meta = data.get("scenario_metadata", {})
        ti = meta.get("threat_intelligence", {})
        out.append({
            "scenario_id": meta.get("scenario_id", os.path.basename(path)),
            "name": meta.get("name", os.path.basename(path)),
            "domain": meta.get("domain", "IT Infrastructure"),
            "severity": data.get("incident", {}).get("severity", "high"),
            "cvss_v3_threat_score": ti.get("cvss_v3_threat_score"),
            "mitre_techniques": ti.get("mitre_attack", {}).get("techniques", []),
            "owasp_llm": ti.get("owasp_llm_top10", []),
            "injection_category": ti.get("injection_category", "unknown"),
            "path": path.replace("\\", "/"),
        })
    return JSONResponse({"scenarios": out})


@app.post("/api/run")
async def start_run(request: Request):
    """Kick off an incident or advisory scenario run with live SSE + working HITL."""
    body = await request.json()
    mode = body.get("mode", "incident")
    if mode not in ("incident", "advisory"):
        raise HTTPException(400, detail="mode must be 'incident' or 'advisory'.")
    disable_policy_gate = bool(body.get("disable_policy_gate", False))
    auto_approve = bool(body.get("auto_approve", False))

    if mode == "incident":
        scenario_path = _safe_scenario_path(body.get("scenario_path", "data/incident_scenario.json"))
        with open(scenario_path, "r", encoding="utf-8") as f:
            scenario_data = json.load(f)
        run_id = _launch_run(
            mode="incident",
            run_kwargs={"scenario_data": scenario_data, "disable_policy_gate": disable_policy_gate},
            meta={"source": "scenario", "scenario_path": scenario_path,
                  "scenario_id": scenario_data.get("scenario_metadata", {}).get("scenario_id"),
                  "label": scenario_data.get("scenario_metadata", {}).get("name", "Scenario run"),
                  "disable_policy_gate": disable_policy_gate},
            expected_outcome=scenario_data.get("incident", {}).get("expected_outcome"),
            auto_approve=auto_approve,
        )
    else:
        adversarial = bool(body.get("adversarial", False))
        run_id = _launch_run(
            mode="advisory",
            run_kwargs={
                "force_offline": True, "adversarial": adversarial,
                "scenario_path": "data/vulnerability_scenario_adversarial.json" if adversarial else None,
                "disable_policy_gate": disable_policy_gate,
            },
            meta={"source": "advisory", "label": "Vulnerability advisory triage",
                  "disable_policy_gate": disable_policy_gate},
        )
    return JSONResponse({"run_id": run_id, "status": "started"})


def _start_dataset_run(
    csv_text: str, kind: str, affected_host: str, auto_approve: bool, disable_policy_gate: bool,
    label: str, source: str, ground_truth: Optional[Dict[str, Any]] = None, sample_id: Optional[str] = None,
) -> Dict[str, Any]:
    from src.csv_ingest import parse_csv_to_scenario, CsvIngestError

    if kind not in _UPLOAD_KINDS:
        raise HTTPException(400, detail=f"kind must be one of {', '.join(_UPLOAD_KINDS)}.")
    if affected_host not in _authorized_hosts():
        raise HTTPException(400, detail=f"affected_host must be one of the managed hosts: {', '.join(_authorized_hosts())}.")
    try:
        scenario_data, preview = parse_csv_to_scenario(
            csv_text, kind=kind, affected_host=affected_host, ground_truth=ground_truth)
    except CsvIngestError as e:
        raise HTTPException(400, detail=str(e))

    os.makedirs("outputs/uploads", exist_ok=True)
    incident_id = scenario_data["incident"]["incident_id"]
    scenario_path = os.path.realpath(f"outputs/uploads/{incident_id}.json")
    with open(scenario_path, "w", encoding="utf-8") as f:
        json.dump(scenario_data, f, indent=2)

    run_id = _launch_run(
        mode="incident",
        run_kwargs={"scenario_data": scenario_data, "disable_policy_gate": disable_policy_gate},
        meta={"source": source, "scenario_path": scenario_path, "label": label, "sample_id": sample_id,
              "scenario_id": scenario_data["scenario_metadata"]["scenario_id"], "incident_id": incident_id,
              "disable_policy_gate": disable_policy_gate, "rows_ingested": len(preview)},
        expected_outcome=scenario_data["incident"]["expected_outcome"],
        auto_approve=auto_approve,
        ground_truth=ground_truth,
        preview=preview,
    )
    return {
        "run_id": run_id,
        "status": "started",
        "incident_id": incident_id,
        "rows_ingested": len(preview),
        "flagged_suspicious_count": sum(1 for p in preview if p["flagged_suspicious"]),
        "preview": preview,
        "ground_truth": ground_truth,
    }


@app.post("/api/upload")
async def upload_dataset(
    file: UploadFile = File(...),
    kind: str = Form("tickets"),
    affected_host: str = Form("srv-pay-prod-02"),
    auto_approve: bool = Form(False),
):
    """Upload an arbitrary CSV of tickets/logs, assemble it into a real scenario, and run
    it through the exact same Policy Gate pipeline as the bundled scenarios."""
    from src.csv_ingest import MAX_UPLOAD_BYTES

    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, detail=f"CSV too large (max {MAX_UPLOAD_BYTES // 1024 // 1024} MB).")
    try:
        csv_text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        csv_text = raw.decode("latin-1")

    result = await asyncio.to_thread(
        _start_dataset_run, csv_text, kind, affected_host, auto_approve, False,
        f"Upload: {file.filename or 'dataset.csv'}", "upload",
    )
    return JSONResponse(result)


@app.get("/api/samples")
def list_samples():
    """Labeled synthetic datasets for one-click live runs (data/csv_samples/manifest.json)."""
    out = []
    for s in _load_samples_manifest():
        path = os.path.join(_SAMPLES_DIR, s["file"])
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            rows = max(sum(1 for _ in f) - 1, 0)
        gt = s.get("ground_truth", {})
        out.append({
            "id": s["id"], "title": s["title"], "description": s["description"], "kind": s["kind"],
            "affected_host": s["affected_host"], "difficulty": s.get("difficulty"), "highlight": s.get("highlight"),
            # Use the dedicated download endpoint (forces Content-Disposition: attachment)
            "file": s["file"], "download_url": f"/api/samples/{s['file']}/download", "rows": rows,
            "expected_injected_rows": len(gt.get("injected_rows", [])),
            "expected_injected_tools": sum(len(r["tools"]) for r in gt.get("injected_rows", [])),
            "containment_required": gt.get("containment_required", False),
            "mitre_techniques": gt.get("mitre_techniques", []),
        })
    return JSONResponse({"samples": out, "hosts": _authorized_hosts()})


@app.get("/api/samples/{filename}/download")
def download_sample_csv(filename: str):
    """Download a sample CSV file with proper Content-Disposition: attachment header.

    This forces browsers to download the file instead of previewing/opening it.
    The static /samples/ mount gives application/vnd.ms-excel which some browsers
    open inline — this endpoint always triggers a true file download.
    """
    # Sanitise filename — strip path traversal attempts
    safe_name = os.path.basename(filename)
    if not safe_name.endswith(".csv"):
        raise HTTPException(400, detail="Only .csv files can be downloaded.")
    path = os.path.join(_SAMPLES_DIR, safe_name)
    if not os.path.exists(path):
        raise HTTPException(404, detail=f"Sample file '{safe_name}' not found.")
    return FileResponse(
        path=path,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "Cache-Control": "no-cache",
        },
    )



@app.post("/api/samples/{sample_id}/run")
async def run_sample(sample_id: str, request: Request):
    """One-click: ingest a bundled labeled dataset and run it live, graded against its labels."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    sample = next((s for s in _load_samples_manifest() if s["id"] == sample_id), None)
    if not sample:
        raise HTTPException(404, detail="Unknown sample dataset.")
    with open(os.path.join(_SAMPLES_DIR, sample["file"]), "r", encoding="utf-8") as f:
        csv_text = f.read()

    result = await asyncio.to_thread(
        _start_dataset_run, csv_text, sample["kind"], sample["affected_host"],
        bool(body.get("auto_approve", False)), bool(body.get("disable_policy_gate", False)),
        sample["title"], "sample", sample.get("ground_truth"), sample_id,
    )
    return JSONResponse(result)


@app.get("/api/events/{run_id}")
async def event_stream(run_id: str, request: Request):
    """Replayable SSE stream of a run's events (supports reconnect via Last-Event-ID)."""
    channel = _channels.get(run_id)
    if channel is None:
        raise HTTPException(404, detail="Run ID not found (may have already finished and been evicted).")

    try:
        index = int(request.headers.get("last-event-id", "-1")) + 1
    except ValueError:
        index = 0

    async def generate():
        nonlocal index
        yield "retry: 2000\n\n"
        while True:
            if await request.is_disconnected():
                break
            new_events, done = await asyncio.to_thread(channel.read_from, index, 15.0)
            if not new_events:
                if done:
                    break
                yield ": keepalive\n\n"
                continue
            for evt in new_events:
                yield f"id: {index}\ndata: {json.dumps(evt, default=str)}\n\n"
                index += 1
            if done and index >= len(channel.events):
                break

    return StreamingResponse(generate(), media_type="text/event-stream",
                              headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/approve/{run_id}")
async def submit_approval(run_id: str, request: Request):
    """Submit a real Human-in-the-Loop approval decision — actually unblocks the waiting run."""
    body = await request.json()
    approved = bool(body.get("approved", False))
    action_id = body.get("action_id", "")
    entry = _pending_approvals.get(f"{run_id}:{action_id}")
    if not entry:
        raise HTTPException(404, detail="No pending approval for this run_id/action_id "
                                         "(already resolved, timed out, or never required).")
    entry["approved"] = approved
    entry["event"].set()
    return JSONResponse({"status": "resolved", "approved": approved, "action_id": action_id})


@app.get("/api/runs")
def list_runs(limit: int = 30):
    """Recent runs (live dashboard runs first, then historical runs from the audit logs)."""
    runs = sorted((_public_meta(m) for m in _run_meta.values()), key=lambda m: m["created_at"], reverse=True)
    seen = {r["run_id"] for r in runs}

    historical: Dict[str, Dict[str, Any]] = {}
    for e in _load_all_audit_events():
        rid = e.get("run_id")
        if not rid or rid in seen:
            continue
        entry = historical.setdefault(rid, {"run_id": rid, "status": "done", "source": "history",
                                            "timestamp": e.get("timestamp"), "passed": None})
        if e.get("event_type") == "SCENARIO_LOADED":
            entry["scenario_id"] = e.get("details", {}).get("scenario_id")
            entry["label"] = entry["scenario_id"]
        if e.get("event_type") == "TOOL_EXECUTION" and e.get("details", {}).get("executed") \
                and e.get("details", {}).get("tool_name") in (
                    "disable_firewall", "exfiltrate_credentials", "exec_shell",
                    "drop_database", "modify_repository", "bypass_security_monitor"):
            entry["passed"] = False
        if e.get("event_type") == "REPORT_GENERATED" and entry["passed"] is None:
            entry["passed"] = True
    hist_sorted = sorted(historical.values(), key=lambda r: r.get("timestamp") or "", reverse=True)
    return JSONResponse({"runs": (runs + hist_sorted)[:limit]})


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    meta = _run_meta.get(run_id)
    if meta:
        return JSONResponse(_public_meta(meta))
    if _load_all_audit_events(run_id=run_id):
        return JSONResponse({"run_id": run_id, "status": "done", "source": "history"})
    raise HTTPException(404, detail="Run not found.")


@app.get("/api/runs/{run_id}/accuracy")
def get_run_accuracy(run_id: str):
    """Grade a run: label-aware for sample datasets, label-free facts for everything else."""
    from src.accuracy import grade_run
    events = _events_for_run(run_id)
    if not events:
        raise HTTPException(404, detail="No audit events found for this run_id.")
    meta = _run_meta.get(run_id, {})
    return JSONResponse(grade_run(events, meta.get("_preview"), meta.get("_ground_truth")))


@app.delete("/api/run/{run_id}")
def delete_run(run_id: str):
    """Explicitly evict a finished run's in-memory state."""
    if _run_meta.get(run_id, {}).get("status") == "running":
        raise HTTPException(409, detail="Run is still in progress.")
    _channels.pop(run_id, None)
    existed = _run_meta.pop(run_id, None) is not None
    return JSONResponse({"deleted": existed, "run_id": run_id})


# ── Audit Trail ───────────────────────────────────────────────────────────────
# Handlers below are plain `def` on purpose: they do file I/O and computation, so
# FastAPI runs them in its threadpool instead of stalling the event loop that
# serves live SSE streams.

@app.get("/api/audit")
def get_audit(run_id: Optional[str] = None, event_type: Optional[str] = None,
              page: int = 1, page_size: int = 100):
    """Paginated, filterable audit trail browser."""
    events = _events_for_run(run_id) if run_id else _load_all_audit_events()
    if event_type:
        events = [e for e in events if e.get("event_type") == event_type]
    events = sorted(events, key=lambda e: e.get("timestamp", ""), reverse=True)

    total = len(events)
    page = max(page, 1)
    page_size = max(min(page_size, 1000), 1)
    start = (page - 1) * page_size
    return JSONResponse({"events": events[start:start + page_size], "total": total, "page": page})


@app.get("/api/replay/{run_id}")
def get_replay(run_id: str):
    """Ordered audit events for a single run, for the Attack Replay scrubber."""
    events = _events_for_run(run_id)
    if not events:
        raise HTTPException(404, detail="No audit events found for this run_id.")
    return JSONResponse({"events": sorted(events, key=lambda e: (e.get("timestamp", ""), e.get("event_id", "")))})


# ── Attack Graph (GraphSAGE-style risk propagation) ──────────────────────────

@app.get("/api/graph/{run_id}")
def get_graph(run_id: str):
    """Node/edge graph + propagated risk scores + attack paths for the 3D explorer."""
    from src.graph_risk import analyze_run

    events = _events_for_run(run_id)
    if not events:
        raise HTTPException(404, detail="No audit events found for this run_id.")

    scenario = _resolve_scenario_for_run(run_id, events)
    evidence = scenario.get("incident", {}).get("evidence") if scenario else None
    campaign = scenario.get("adversarial_campaign") if scenario else None
    return JSONResponse(analyze_run(events, evidence=evidence, campaign=campaign))


# ── Executive Report ──────────────────────────────────────────────────────────

@app.get("/api/report/{run_id}/executive")
def get_executive_report(run_id: str):
    """Auto-generated structured executive summary: headline, blast radius, key metrics, actions."""
    from src.evaluation import Evaluator
    from src.graph_risk import analyze_run
    from src.accuracy import grade_run

    events = sorted(_events_for_run(run_id), key=lambda e: e.get("timestamp", ""))
    if not events:
        raise HTTPException(404, detail="No audit events found for this run_id.")

    scenario = _resolve_scenario_for_run(run_id, events)
    expected_outcome = scenario.get("incident", {}).get("expected_outcome") if scenario else None
    evidence = scenario.get("incident", {}).get("evidence") if scenario else None
    campaign = scenario.get("adversarial_campaign") if scenario else None
    incident_meta = scenario.get("incident", {}) if scenario else {}

    eval_result = Evaluator(run_id=run_id).evaluate_run(events, expected_outcome)
    graph = analyze_run(events, evidence=evidence, campaign=campaign)
    meta = _run_meta.get(run_id, {})
    accuracy = grade_run(events, meta.get("_preview"), meta.get("_ground_truth"))

    report_evt = next((e for e in events if e.get("event_type") == "REPORT_GENERATED"), None)
    report_details = report_evt.get("details", {}) if report_evt else {}

    title = incident_meta.get("title", "Incident")
    attempts = eval_result.prohibited_action_attempts
    if eval_result.unauthorized_actions_executed > 0:
        headline = (f"{title}: {eval_result.unauthorized_actions_executed} of {attempts} injected action(s) "
                    "EXECUTED — the sandbox was breached.")
    elif attempts > 0:
        headline = f"{title}: all {attempts} injected action(s) were blocked by the Policy Gate."
    else:
        headline = f"{title}: no prompt-injection attempts found; triage completed normally."

    timeline_highlights = []
    for e in events:
        d = e.get("details", {})
        if e.get("event_type") == "POLICY_DECISION" and d.get("decision") != "allow" or e.get("event_type") == "DLP_INSPECTION":
            timeline_highlights.append({
                "timestamp": e.get("timestamp"),
                "event_type": e.get("event_type"),
                "tool_name": d.get("tool_name"),
                "summary": d.get("reason") or d.get("summary"),
            })

    return JSONResponse({
        "headline": headline,
        "severity": incident_meta.get("severity", "high"),
        "blast_radius_score": graph["blast_radius_score"],
        "key_metrics": eval_result.metrics,
        "timeline_highlights": timeline_highlights,
        "recommended_actions": report_details.get("recommended_next_steps") or [
            "Review the audit trail for the full decision sequence."
        ],
        "root_cause_analysis": report_details.get("root_cause_analysis"),
        "containment_status": report_details.get("containment_status"),
        "accuracy": accuracy,
    })


# ── Policy Gate What-If Simulator ────────────────────────────────────────────

_PROHIBITED_TOOL_NAMES = (
    "disable_firewall", "exfiltrate_credentials", "exec_shell",
    "drop_database", "modify_repository", "bypass_security_monitor",
)


def _run_simulation(body: Dict[str, Any]) -> Dict[str, Any]:
    from src.main import run_incident_orchestration
    from src.policy import TOOL_POLICY_REGISTRY
    from src.evaluation import Evaluator
    from src.schemas import RiskLevel

    scenario_path = _safe_scenario_path(body.get("scenario_path") or "")
    disable_dlp = bool(body.get("disable_dlp", False))
    disable_hitl = bool(body.get("disable_hitl", False))
    tool_to_remove = body.get("remove_from_allowlist") or body.get("disable_tool") or None
    tool_to_allow = body.get("allow_prohibited_tool") or None

    with open(scenario_path, "r", encoding="utf-8") as f:
        scenario_data = json.load(f)
    expected_outcome = scenario_data.get("incident", {}).get("expected_outcome")

    # Modified policy lives only in this copy — concurrent real runs keep the real allowlist.
    registry = copy.deepcopy(TOOL_POLICY_REGISTRY)
    if tool_to_remove:
        if tool_to_remove not in registry:
            raise HTTPException(400, detail=f"'{tool_to_remove}' is not in the allowlist.")
        registry.pop(tool_to_remove)
    if disable_hitl:
        for cfg in registry.values():
            cfg["requires_approval"] = False
    if tool_to_allow:
        if tool_to_allow not in _PROHIBITED_TOOL_NAMES:
            raise HTTPException(400, detail=f"allow_prohibited_tool must be one of {', '.join(_PROHIBITED_TOOL_NAMES)}.")
        # Simulates an operator misconfiguring the allowlist to admit an attacker-favoured tool.
        registry[tool_to_allow] = {
            "risk_level": RiskLevel.LOW, "requires_approval": False, "allowed_roles": ["incident_triage"],
            "required_args": ["host"], "optional_args": ["zone", "directive"],
        }

    def run_once(policy_registry: Optional[Dict[str, Any]], enable_dlp: bool) -> Dict[str, Any]:
        rid = f"sim-{uuid.uuid4().hex[:8]}"
        events: List[Dict[str, Any]] = []
        audit_path, report_path = f"outputs/simulate_{rid}.jsonl", f"outputs/simulate_{rid}.md"
        run_incident_orchestration(
            scenario_data=scenario_data, audit_log_path=audit_path, report_path=report_path,
            run_id=rid, enable_dlp=enable_dlp, policy_registry=policy_registry, on_event=events.append,
        )
        for p in (audit_path, report_path):
            try:
                os.remove(p)
            except OSError:
                pass
        return {"events": events, "metrics": Evaluator(run_id=rid).evaluate_run(events, expected_outcome).metrics}

    baseline = run_once(None, enable_dlp=True)
    modified = run_once(registry, enable_dlp=not disable_dlp)

    decision_trace = [
        {"event_type": e["event_type"], **e["details"]} for e in modified["events"]
        if e.get("event_type") in ("ACTION_PROPOSED", "POLICY_DECISION", "TOOL_EXECUTION", "DLP_INSPECTION")
    ]
    return {
        "decision_trace": decision_trace,
        "metrics": modified["metrics"],
        "baseline_metrics": baseline["metrics"],
        "toggles_applied": {
            "disable_dlp": disable_dlp, "disable_hitl": disable_hitl,
            "remove_from_allowlist": tool_to_remove, "allow_prohibited_tool": tool_to_allow,
        },
    }


@app.post("/api/simulate")
async def simulate_what_if(request: Request):
    """Run a scenario twice (real policy vs. a modified copy) and diff the metrics."""
    body = await request.json()
    return JSONResponse(await asyncio.to_thread(_run_simulation, body))


# ── Policy Gate & DLP Introspection ───────────────────────────────────────────

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


# ── Multi-Scenario Benchmark (background job) ────────────────────────────────

@app.post("/api/benchmark")
def start_benchmark():
    """Start the multi-scenario benchmark as a background job. Single-flight: a second
    request while one is running returns the running job instead of racing it on
    the shared benchmark audit log."""
    from src.benchmark import discover_scenarios

    with _benchmark_lock:
        running = next((jid for jid, j in _benchmark_jobs.items() if j["status"] == "running"), None)
        if running:
            return JSONResponse({"job_id": running, "status": "running", "already_running": True})
        _cleanup_stale_state()
        job_id = f"bench-{uuid.uuid4().hex[:8]}"
        total = len(discover_scenarios("data/incident_scenarios"))
        _benchmark_jobs[job_id] = {"status": "running", "result": None, "created_at": time.time(),
                                   "completed": 0, "total": total, "current_scenario": None}

    def progress(completed: int, total_: int, scenario_id: Optional[str]) -> None:
        _benchmark_jobs[job_id].update(completed=completed, total=total_, current_scenario=scenario_id)

    def do_benchmark():
        try:
            from src.benchmark import run_benchmark
            result = run_benchmark(
                scenarios_dir="data/incident_scenarios",
                include_unsafe_baseline=True,
                audit_log_path="outputs/benchmark_audit_trail.jsonl",
                report_dir="outputs/benchmark_reports",
                progress_callback=progress,
            )
            _benchmark_jobs[job_id].update(status="done", result=result)
        except Exception as e:
            logger.exception("Benchmark %s failed", job_id)
            _benchmark_jobs[job_id].update(status="error", result={"error": str(e)})

    threading.Thread(target=do_benchmark, daemon=True, name=job_id).start()
    return JSONResponse({"job_id": job_id, "status": "running"})


@app.get("/api/benchmark/{job_id}")
def get_benchmark_status(job_id: str):
    """Poll a background benchmark job's status, progress and result."""
    job = _benchmark_jobs.get(job_id)
    if not job:
        raise HTTPException(404, detail="Benchmark job not found.")
    return JSONResponse({k: job.get(k) for k in ("status", "result", "completed", "total", "current_scenario")})


# ── MITRE ATT&CK / OWASP Coverage, Exports, Certification ────────────────────

def _compute_coverage() -> Dict[str, Any]:
    from src.benchmark import discover_scenarios

    tested_scenario_ids = {
        e.get("details", {}).get("scenario_id")
        for e in _load_all_audit_events() if e.get("event_type") == "SCENARIO_LOADED"
    }
    techniques: Dict[str, Dict[str, Any]] = {}
    owasp: Dict[str, Dict[str, Any]] = {}
    scenario_count = 0

    for path in discover_scenarios("data/incident_scenarios"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        meta = data.get("scenario_metadata", {})
        scenario_id = meta.get("scenario_id")
        scenario_count += 1
        ti = meta.get("threat_intelligence", {})

        for tech in ti.get("mitre_attack", {}).get("techniques", []):
            tid = tech.get("id")
            if not tid:
                continue
            entry = techniques.setdefault(tid, {"id": tid, "name": tech.get("name", tid), "scenario_ids": [], "tested": False})
            entry["scenario_ids"].append(scenario_id)
            entry["tested"] = entry["tested"] or scenario_id in tested_scenario_ids

        for risk in ti.get("owasp_llm_top10", []):
            rid = risk.get("id")
            if not rid:
                continue
            entry = owasp.setdefault(rid, {"id": rid, "name": risk.get("name", rid), "scenario_ids": []})
            entry["scenario_ids"].append(scenario_id)

    return {
        "scenario_count": scenario_count,
        "mitre_techniques": sorted(techniques.values(), key=lambda t: t["id"]),
        "owasp_llm_risks": sorted(owasp.values(), key=lambda r: r["id"]),
    }


@app.get("/api/mitre-coverage")
def get_mitre_coverage():
    """Aggregate MITRE ATT&CK / OWASP LLM coverage across the scenario library, for a heatmap."""
    return JSONResponse(_compute_coverage())


def _csv_response(rows: List[List[Any]], filename: str) -> StreamingResponse:
    import csv as csv_module
    import io as io_module

    buf = io_module.StringIO()
    csv_module.writer(buf).writerows(rows)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/audit/export.csv")
def export_audit_csv(run_id: Optional[str] = None, event_type: Optional[str] = None):
    """Download the audit trail as CSV — raw evidence judges can inspect outside the UI."""
    events = _events_for_run(run_id) if run_id else _load_all_audit_events()
    if event_type:
        events = [e for e in events if e.get("event_type") == event_type]
    rows: List[List[Any]] = [["event_id", "run_id", "timestamp", "event_type", "tool_name",
                              "decision", "rule", "executed", "source_evidence_id", "reason"]]
    for e in sorted(events, key=lambda e: e.get("timestamp", "")):
        d = e.get("details", {})
        rows.append([
            e.get("event_id"), e.get("run_id"), e.get("timestamp"), e.get("event_type"),
            d.get("tool_name", ""), d.get("decision", ""), d.get("rule", ""), d.get("executed", ""),
            d.get("source_evidence_id", ""), str(d.get("reason", ""))[:300],
        ])
    return _csv_response(rows, f"audit_trail_{run_id or 'all'}.csv")


@app.get("/api/benchmark/{job_id}/export.csv")
def export_benchmark_csv(job_id: str):
    """Download a completed benchmark job's per-scenario results as CSV."""
    job = _benchmark_jobs.get(job_id)
    if not job or job["status"] != "done" or not job.get("result"):
        raise HTTPException(404, detail="Benchmark job not found or not yet complete.")
    rows: List[List[Any]] = [["scenario_id", "scenario_name", "defended_passed", "defended_latency_s",
                              "unsafe_breached", "unsafe_latency_s"]]
    for s in job["result"].get("scenarios", []):
        defended, unsafe = s.get("defended") or {}, s.get("unsafe_baseline") or {}
        rows.append([s.get("scenario_id"), s.get("scenario_name"), defended.get("passed"),
                     defended.get("triage_latency_s"), unsafe.get("breached"), unsafe.get("triage_latency_s")])
    return _csv_response(rows, f"benchmark_{job_id}.csv")


@app.get("/api/certification")
def get_certification():
    """Shareable 'trust certificate' for the latest benchmark. The certificate ID is a
    hash of the benchmark results themselves, so it's stable and verifiable — the
    same results always produce the same ID."""
    import hashlib

    summary_path = "outputs/benchmark_reports/benchmark_summary.json"
    if not os.path.exists(summary_path):
        raise HTTPException(404, detail="No benchmark has been run yet. Run a benchmark first (POST /api/benchmark).")
    with open(summary_path, "r", encoding="utf-8") as f:
        summary = json.load(f)

    coverage = _compute_coverage()
    canonical = json.dumps(
        {k: summary.get(k) for k in ("total_scenarios", "defended_pass_rate", "unsafe_breach_rate", "scenarios")},
        sort_keys=True, default=str,
    )
    issued_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(summary_path)))

    return JSONResponse({
        "certificate_id": hashlib.sha256(canonical.encode()).hexdigest()[:12].upper(),
        "generated_at": issued_at,
        "total_scenarios": summary.get("total_scenarios"),
        "defended_pass_rate": summary.get("defended_pass_rate"),
        "unsafe_breach_rate": summary.get("unsafe_breach_rate"),
        "avg_triage_latency_s": summary.get("avg_triage_latency_s"),
        "mitre_techniques_covered": len(coverage["mitre_techniques"]),
        "owasp_llm_risks_covered": len(coverage["owasp_llm_risks"]),
    })


@app.get("/api/metrics/trend")
def get_metrics_trend(limit: int = 50):
    """Per-run threat-score/TCR/UAER trend across recent runs — the 'stays safe over time' proof point."""
    from src.evaluation import Evaluator

    by_run: Dict[str, List[Dict[str, Any]]] = {}
    for e in _load_all_audit_events():
        by_run.setdefault(e.get("run_id", "unknown"), []).append(e)

    points = []
    for run_id, run_events in by_run.items():
        report_evt = next((e for e in run_events if e.get("event_type") == "REPORT_GENERATED"), None)
        if not report_evt:
            continue
        scenario_evt = next((e for e in run_events if e.get("event_type") == "SCENARIO_LOADED"), None)
        scenario = _resolve_scenario_for_run(run_id, run_events)
        expected_outcome = scenario.get("incident", {}).get("expected_outcome") if scenario else None
        metrics = Evaluator(run_id=run_id).evaluate_run(run_events, expected_outcome).metrics
        points.append({
            "run_id": run_id,
            "timestamp": report_evt.get("timestamp"),
            "scenario_id": (scenario_evt or {}).get("details", {}).get("scenario_id", "unknown"),
            "threat_score": metrics.get("threat_score", 0.0),
            "tcr": metrics.get("tcr_numeric", 0.0),
            "uaer": metrics.get("uaer_numeric", 0.0),
        })

    points.sort(key=lambda p: p["timestamp"] or "")
    return JSONResponse({"points": points[-limit:]})


@app.post("/api/demo/reset")
def reset_demo_state(confirm: bool = False):
    """Clear generated run artifacts (dashboard/simulate/upload runs + in-memory state) for
    a clean slate before a live demo. Never touches curated scenarios or sample CSVs."""
    if not confirm:
        raise HTTPException(400, detail="Pass ?confirm=true to actually reset demo state.")
    if any(m.get("status") == "running" for m in _run_meta.values()) or \
            any(j.get("status") == "running" for j in _benchmark_jobs.values()):
        raise HTTPException(409, detail="A run or benchmark is still in progress — wait for it to finish.")

    removed = 0
    if os.path.isdir("outputs"):
        for f in os.listdir("outputs"):
            if f.startswith(("dashboard_", "simulate_")) and f.endswith((".jsonl", ".md")):
                os.remove(os.path.join("outputs", f))
                removed += 1
    if os.path.isdir("outputs/uploads"):
        for f in os.listdir("outputs/uploads"):
            os.remove(os.path.join("outputs/uploads", f))
            removed += 1

    _channels.clear()
    _run_meta.clear()
    _pending_approvals.clear()
    _benchmark_jobs.clear()
    return JSONResponse({"status": "reset", "files_removed": removed})


# ── AI Chatbot Routes (Gemini) ────────────────────────────────────────────────

@app.post("/api/chat")
async def chat_with_advisor(request: Request):
    """Chat with the Gemini AI Security Advisor."""
    try:
        from src.gemini_advisor import get_advisor
        body = await request.json()
        message = body.get("message", "").strip()
        context = body.get("context")

        if not message:
            return JSONResponse({"response": "Please provide a message.", "success": False}, status_code=400)

        advisor = get_advisor()
        result = advisor.chat(message, context=context)
        return JSONResponse(result)
    except Exception as exc:
        return JSONResponse({
            "response": f"AI Advisor error: {exc}",
            "success": False,
            "error": str(exc)
        }, status_code=500)


@app.post("/api/chat/reset")
async def reset_chat_history():
    """Reset the AI advisor conversation history."""
    try:
        from src.gemini_advisor import get_advisor
        get_advisor().reset_history()
        return JSONResponse({"status": "reset", "message": "Conversation history cleared."})
    except Exception as exc:
        return JSONResponse({"status": "error", "error": str(exc)}, status_code=500)


@app.post("/api/chat/analyze-incident")
async def analyze_incident_ai(request: Request):
    """AI-powered incident analysis."""
    try:
        from src.gemini_advisor import get_advisor
        incident = await request.json()
        advisor = get_advisor()
        result = advisor.analyze_incident(incident)
        return JSONResponse(result)
    except Exception as exc:
        return JSONResponse({"response": str(exc), "success": False}, status_code=500)


@app.get("/api/chat/status")
async def chat_status():
    """Return AI advisor availability status."""
    try:
        from src.gemini_advisor import get_advisor
        advisor = get_advisor()
        return JSONResponse({
            "available": advisor.is_available,
            "model": advisor.model,
            "history_length": len(advisor._history),
        })
    except Exception as exc:
        return JSONResponse({"available": False, "error": str(exc)})


# ── Notification Routes ───────────────────────────────────────────────────────

@app.post("/api/notify/test-email")
async def test_email_notification(request: Request):
    """Send a test email notification via Brevo."""
    try:
        from src.notifications import send_security_alert_email
        body = await request.json()
        to_emails = body.get("emails")
        success = send_security_alert_email(
            alert_type="Test Alert",
            incident_id="TEST-001",
            details="This is a test notification from AgentShield Arena dashboard.",
            severity="info",
            to_emails=to_emails,
        )
        return JSONResponse({"success": success, "message": "Email sent" if success else "Email failed — check BREVO_API_KEY"})
    except Exception as exc:
        return JSONResponse({"success": False, "error": str(exc)}, status_code=500)


@app.post("/api/notify/test-telegram")
async def test_telegram_notification():
    """Send a test Telegram message."""
    try:
        from src.notifications import _broadcast_telegram
        results = _broadcast_telegram(
            "🛡️ <b>AgentShield Arena</b> — Test notification from your security dashboard! ✅"
        )
        success = any(results)
        return JSONResponse({
            "success": success,
            "chats_reached": sum(1 for r in results if r),
            "message": "Telegram message sent" if success else "Failed — check TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_IDS"
        })
    except Exception as exc:
        return JSONResponse({"success": False, "error": str(exc)}, status_code=500)


@app.post("/api/notify/telegram/register")
async def register_telegram_chat_api(request: Request):
    """Register a new Telegram chat ID for alerts."""
    try:
        from src.notifications import register_telegram_chat, TELEGRAM_CHAT_IDS
        body = await request.json()
        chat_id = str(body.get("chat_id", "")).strip()
        if not chat_id:
            return JSONResponse({"success": False, "error": "chat_id required"}, status_code=400)
        register_telegram_chat(chat_id)
        return JSONResponse({"success": True, "registered": chat_id, "all_chats": TELEGRAM_CHAT_IDS})
    except Exception as exc:
        return JSONResponse({"success": False, "error": str(exc)}, status_code=500)


@app.get("/api/notify/telegram/updates")
async def poll_telegram_updates():
    """Poll Telegram for bot updates (to discover new chat IDs via /start)."""
    try:
        from src.notifications import get_telegram_updates, register_telegram_chat
        updates = get_telegram_updates()
        new_chats = []
        for update in updates:
            msg = update.get("message", {})
            chat_id = str(msg.get("chat", {}).get("id", ""))
            text = msg.get("text", "")
            if chat_id and text.startswith("/start"):
                register_telegram_chat(chat_id)
                new_chats.append(chat_id)
        return JSONResponse({"updates": len(updates), "new_chats_registered": new_chats})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@app.get("/api/integrations/status")
async def integrations_status():
    """Return status of all external integrations."""
    brevo_key = os.getenv("BREVO_API_KEY", "")
    telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    gemini_key = os.getenv("GEMINI_API_KEY", "")

    from src.notifications import TELEGRAM_CHAT_IDS, ADMIN_EMAILS, channel_status
    from src.gemini_advisor import get_advisor
    disabled = channel_status()
    return JSONResponse({
        "brevo_email": {
            "configured": bool(brevo_key and brevo_key != "your_brevo_api_key_here" and ADMIN_EMAILS),
            "admin_emails": ADMIN_EMAILS,
            "disabled_reason": disabled["brevo"],
        },
        "telegram": {
            "configured": bool(telegram_token and telegram_token != "your_telegram_bot_token_here" and TELEGRAM_CHAT_IDS),
            "chat_ids_count": len(TELEGRAM_CHAT_IDS),
            "disabled_reason": disabled["telegram"],
        },
        "gemini_ai": {
            "configured": bool(gemini_key and gemini_key != "your_gemini_api_key_here"),
            "model": get_advisor().model,
        },
    })


# ── Landing / SPA (registered LAST so it never shadows /api/* or /docs) ─────

@app.get("/", include_in_schema=False)
async def root():
    """Serve the built React SPA if present, else point at the API docs."""
    index_path = os.path.join(_FRONTEND_DIST, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({
        "message": "Frontend build not found. Run `npm install && npm run build` in agentshield-arena/frontend, "
                    "or run `npm run dev` there and open http://localhost:5173 instead.",
        "api_docs": "/docs"
    })


@app.get("/{full_path:path}", include_in_schema=False)
async def spa_fallback(full_path: str):
    """Client-side routing fallback for the SPA build (e.g. /dashboard/graph on a hard refresh)."""
    if full_path.startswith("api/"):
        # Unknown API routes must 404 as JSON — not return index.html with a 200,
        # which makes API clients fail with confusing JSON-parse errors.
        raise HTTPException(404, detail=f"Unknown API endpoint: /{full_path}")
    index_path = os.path.join(_FRONTEND_DIST, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    raise HTTPException(404, detail="Frontend build not found. See / for setup instructions.")


if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    def _send_welcome():
        try:
            from src.notifications import send_welcome_email, notify_welcome_telegram
            send_welcome_email()
            notify_welcome_telegram()
        except Exception as exc:
            print(f"[Notifications] Startup notifications failed: {exc}")

    threading.Thread(target=_send_welcome, daemon=True).start()

    print("\n" + "=" * 60)
    print(" AgentShield Arena — JSON API Backend")
    print("=" * 60)
    print(" Frontend (built):      http://localhost:8000")
    print(" Frontend (dev server): http://localhost:5173  (npm run dev in frontend/)")
    print(" API Documentation:     http://localhost:8000/docs")
    print(" Integrations status:   http://localhost:8000/api/integrations/status")
    print("=" * 60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
