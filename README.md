# Maximus AI — single-file backend

The **entire backend** (API, agents, router, planner, runtime, OmniRoute client,
memory, tools/MCP, sandbox, verification, workers, 18-table SQLite schema) lives in **`app.py`**.

## Run

```powershell
cd maximus_single
python -m pip install -r requirements.txt
python app.py
# docs: http://127.0.0.1:8000/docs
```

All data stays on your computer in `./data/` (`maximus.db`, `projects/`, `sandboxes/`).

## Flow

1. `POST /v1/auth/register` → tokens
2. `POST /v1/projects` → project
3. `POST /v1/keys` → BYOK (`{"provider_slug":"openai","api_key":"sk-..."}` — only fingerprint returned)
4. `POST /v1/tasks` → `{"project_id": "...", "goal": "Build me a production-ready SaaS application."}`
5. `GET /v1/runs/{task_id}/stream` (SSE) → live events
6. `GET /v1/tasks/{id}` → DAG + checkpoints · `POST /v1/tasks/{id}/resume` after failure

Without OmniRoute running, agents use deterministic offline plans so the pipeline works end-to-end.
Set `OMNIROUTE_BASE_URL` + `OMNIROUTE_API_KEY` in `.env` to use real models
(expected gateway shape: `GET /models`, `POST /v1/chat/completions`, optional `GET /health`).
