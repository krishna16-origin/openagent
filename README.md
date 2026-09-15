# Maximus

An autonomous multi-agent platform that runs entirely on your own machine. 480 specialist
agents, your own API keys, no cloud sandbox, no vendor lock-in.

```
MAXIMUS    orchestration — goals, task graphs, agent teams
OMNIROUTE  model routing — which provider, which model, what it costs
MCP/TOOLS  capabilities — search, fetch, files, data
SANDBOX    execution — your computer, sealed off
MEMORY     context — conversation, episodic, semantic
```

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:8000 — the control room loads in the browser. API docs are at `/docs`.

Everything lives in `./data/` (`maximus.db`, `projects/`, `sandboxes/`). Nothing leaves the
machine unless you point it at a model gateway.

## Two speeds

Not every message deserves a task graph. Maximus classifies each turn before spending anything:

| You send | What happens | Typical time |
|---|---|---|
| "hi", "what is a foreign key?" | one model call, answered directly | 60–120 ms |
| "build a production SaaS app" | 16 specialist agents, planned and queued | 30 ms to plan |

Force either path with a `/chat` or `/task` prefix, or `"mode": "chat" \| "task"` in the
request body. `POST /v1/chat/classify` shows the decision without spending tokens.

## Depth scales with difficulty

Agents run an explicit reasoning cycle. How much of it they run depends on the work:

```
UNDERSTAND → PLAN → ACT → CRITIQUE → REVISE → VERIFY
```

A trivial low-risk step runs one pass. A security review, a code change, a retry after a
failure, or a high-complexity goal earns the full cycle including a hostile self-review that
can send the draft back for repair. Set the baseline with `THINK_DEPTH` (0–4).

Only phase names and short status lines are streamed. The model's internal reasoning is never
sent to clients or written to logs.

## The 480 agents

Agents are data, not services. `agents.json` holds 480 definitions across 40 fields —
software, data, security, legal, finance, accounting, healthcare, research, marketing,
education, creative writing, localisation and more. One `GenericAgent` class runs all of them.

```bash
python gen_agents.py      # rebuild the catalogue
```

Routing matches the goal to domains through a keyword lexicon, then ranks agents inside those
domains by role fit, cost and measured past performance. It takes about 1.5 ms per plan.

```
"reconcile last quarter ledger and prepare the payroll tax filing"
  → accounting.payroll_analyst, accounting.tax_analyst,
    accounting.reconciliation_analyst, accounting.close_coordinator

"audit our Kubernetes cluster for security vulnerabilities"
  → security.hardening_engineer, security.dependency_auditor
```

Add your own by editing `agents.json` and calling `POST /v1/agents/reload` — no restart.

## Free tier support

Provider limits are enforced before a request leaves, not discovered through 429s.

Each provider gets a gate combining a **sliding 60-second window** (the hard guarantee) with a
**token bucket** (smooth pacing). A token bucket alone is not enough — its burst capacity
stacks on the refill rate, so a 30,000/minute budget can emit ~37,000 in the first minute. The
window prevents that.

Measured against a 30,000 TPM (500 tok/s) configuration: sustained **520 tok/s**, peak usage
in any 60-second window **13,600 of 30,000**, never breached. You get the full rate you paid
for — or in this case, didn't pay for — and never go over.

On a 429 the gate drops to 70% of its ceiling, honours `Retry-After`, and creeps back up as
calls succeed. Daily caps, per-user quotas, concurrency limits and circuit breakers are all
enforced.

Defaults ship for Groq, Gemini, Mistral, OpenRouter, DeepSeek, NVIDIA, OpenAI, Anthropic,
Cohere and Together. They will drift as providers change them — override with
`PROVIDER_LIMITS_JSON`. Live state: `GET /v1/providers/limits`.

## Bring your own key

Add a key and Maximus calls that provider's own model endpoint, validates the key, and imports
the catalogue with inferred capabilities, context windows and pricing:

```bash
curl -XPOST localhost:8000/v1/keys -H "Authorization: Bearer $TOK" \
  -d '{"provider_slug":"groq","api_key":"gsk_..."}'
# {"provider":"groq","is_valid":true,"models_discovered":21,"fingerprint":"…4f2a"}
```

Keys are encrypted at rest, never returned by any endpoint, never logged, and never reach the
sandbox environment. `GET /v1/keys` returns fingerprints only. `POST /v1/models/refresh`
re-scans.

Supported: OpenAI, Anthropic, Gemini, Groq, Mistral, DeepSeek, NVIDIA, OpenRouter, Together,
Cohere, plus any OpenAI-compatible base URL.

## Your computer is the sandbox

There is no E2B, no Docker, no remote runner. Generated code executes here, inside a jail built
from Linux user namespaces:

- its own mount, network and PID namespaces
- chrooted to a read-only system with only the workspace writable
- no network route at all — TCP, HTTP and DNS all fail
- environment scrubbed, so no API key is ever visible to executed code
- CPU, memory, file size, process and open-file ceilings
- explicit approval required for every execution

Verified behaviour inside the jail:

```
socket.create_connection(('1.1.1.1',53))  → blocked
urllib.request.urlopen('http://...')      → blocked
socket.gethostbyname('github.com')        → blocked
cat /etc/shadow                           → No such file or directory
ls /home /mnt                             → No such file or directory
touch /usr/x                              → Read-only file system
bytearray(900MB)                          → MemoryError
while True: pass                          → killed
```

`GET /v1/sandboxes/capabilities` reports exactly which layers are active on your machine. If
the full jail cannot be built, `STRICT_ISOLATION=true` (the default) refuses to execute rather
than pretending. It does not claim a guarantee it cannot deliver.

## Tools, all free

No API key, no paid account, no tracking:

`web_search` (SearXNG if you host one, otherwise DuckDuckGo) · `wikipedia` · `arxiv` ·
`crossref` · `hackernews` · `open_meteo` · `osm_geocode` · `fetch` · `filesystem` · `sqlite` ·
`terminal`

Every tool declares permission scopes and is refused if the calling agent lacks them. Outbound
URLs pass an SSRF allowlist.

## Long-horizon execution

Goals become a persistent DAG with dependencies, parallelism, checkpoints, retries, timeouts,
budgets and human approval gates. Beyond that:

- **Dynamic expansion** — an agent that discovers work outside its specialism can add nodes
  mid-run, bounded by `MAX_DAG_EXPANSIONS`.
- **Deadlines** — `TASK_DEADLINE_S` caps wall-clock time; the task is marked `expired`.
- **Resume** — `POST /v1/tasks/{id}/resume` restarts failed nodes; incomplete tasks are
  recovered on startup.
- **Approval gates** — 18 high-risk roles (deploy, release, tax filing, smart contracts) stop
  and wait for `POST /v1/tasks/{id}/approve`.

## API

```
/v1/auth/*       register, login, me
/v1/chat         conversation or task, decided automatically
/v1/chat/classify  see the routing decision
/v1/tasks/*      create, get, cancel, resume, approve, events
/v1/runs/{id}/stream   SSE, accepts ?token= for browsers
/v1/agents/*     list, search, stats, reload, get one
/v1/models/*     list, discover, refresh
/v1/providers/*  list, health, limits
/v1/keys/*       add, list, delete — fingerprints only
/v1/tools/*      list, invoke
/v1/mcp/*        servers
/v1/memory/*     store, search
/v1/sandboxes/*  create, exec, capabilities
/v1/artifacts    list
/health /ready   liveness and readiness
```

## Configuration

Copy `.env.example` to `.env`. Everything has a working default; the only thing you need for
real model output is a gateway:

```
OMNIROUTE_BASE_URL=http://127.0.0.1:9000
OMNIROUTE_API_KEY=
```

Expected gateway shape: `GET /models`, `POST /v1/chat/completions`, optional `GET /health`.
`mock_gateway.py` implements it for testing. Without a gateway the pipeline still runs
end-to-end using deterministic offline output, so you can verify orchestration before spending
anything.

## Tests

```bash
python -m pytest tests/ -q          # unit tests, no server needed
python mock_gateway.py &            # then, with the server running:
python integration.py               # 30 end-to-end checks
```

## Scaling up

The default is a single-user local install on SQLite. For multi-user, point `DATABASE_URL` at
PostgreSQL — pooling is already configured — and run the API and workers as separate processes.
Nothing else changes.
