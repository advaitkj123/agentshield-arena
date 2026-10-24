# AgentShield Arena — Frontend

React + Vite + TypeScript + Tailwind v4 + shadcn-style (Radix) components + Framer Motion +
Recharts + `3d-force-graph`. Replaces the old Python-embedded HTML in `src/landing.py` /
`src/dashboard.py`.

## Develop

```bash
cd frontend
npm install
npm run dev
```

Vite runs on `http://localhost:5173` and proxies `/api` and `/hero` to `http://localhost:8000`
(the FastAPI backend — run it separately, e.g. `uvicorn src.dashboard:app --reload` from the repo
root). CORS must be enabled on the backend for the dev server origin.

Every dashboard page falls back to realistic sample data if its backend endpoint isn't reachable
yet, so the UI is fully demoable even while backend work is still landing.

## Build

```bash
npm run build
```

Outputs to `frontend/dist`. In production, FastAPI should mount this directory as static files at
`/` (landing + dashboard SPA) while keeping all `/api/*` routes as JSON.

## Structure

- `src/pages/landing/*` — marketing/landing page sections (`LandingPage.tsx` composes them)
- `src/pages/dashboard/*` — dashboard shell (`DashboardLayout.tsx`) + one file per route
- `src/components/ui/*` — hand-built shadcn-style primitives on Radix (no CLI dependency)
- `src/components/ForceGraph3D.tsx` — shared 3D graph viewer (landing teaser + Graph Explorer)
- `src/components/ChatWidget.tsx` — single shared Gemini advisor chat (floating + embedded modes)
- `src/lib/api.ts` — typed API client; exact contract expected from the backend
- `src/lib/sampleData.ts` — fallback data used whenever a live endpoint isn't reachable
- `src/hooks/useApiData.ts` — fetch-with-sample-fallback hook used by every dashboard page

## API contract this frontend expects

See `src/lib/api.ts` for the full typed contract (every endpoint path, request body, response
shape). Summary of what the backend needs to implement for full functionality (beyond what already
existed): `GET /api/scenarios` (dynamic catalog), `GET /api/graph/{run_id}`, `GET /api/replay/{run_id}`,
`POST /api/simulate`, `GET /api/report/{run_id}/executive`, `POST /api/benchmark` + `GET
/api/benchmark/{job_id}` (background job instead of blocking), `GET /api/audit` with
`page`/`page_size` pagination, and a real (non-stub) `POST /api/approve/{run_id}`.
