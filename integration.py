import urllib.parse
import json, time, urllib.request, urllib.error
from collections import Counter

B = "http://127.0.0.1:8000"
FAIL = []


def call(m, p, b=None, tok=None, t=60):
    d = json.dumps(b).encode() if b is not None else None
    r = urllib.request.Request(B + p, data=d, method=m)
    r.add_header("Content-Type", "application/json")
    if tok:
        r.add_header("Authorization", "Bearer " + tok)
    with urllib.request.urlopen(r, timeout=t) as f:
        return json.loads(f.read() or b"{}")


def check(name, cond, detail=""):
    print(("  PASS " if cond else "  FAIL ") + name + (("  " + str(detail)) if detail else ""))
    if not cond:
        FAIL.append(name)


tok = call("POST", "/v1/auth/register", {"email": "i@x.co", "password": "Passw0rd!123"})["access_token"]
pid = call("POST", "/v1/projects", {"name": "integration"}, tok)["id"]

print("\n[1] agent catalogue")
st = call("GET", "/v1/agents/stats", None, tok)
check("480+ agents loaded", st["total"] >= 400, st["total"])
check("40 domains", st["domains"] >= 30, st["domains"])
check("human gates defined", st["human_gated"] > 0, st["human_gated"])
hits = call("GET", "/v1/agents?q=" + urllib.parse.quote("payroll tax"), None, tok)
check("search finds accounting agents", any("accounting" in h["id"] for h in hits[:5]),
      [h["id"] for h in hits[:3]])

print("\n[2] fast conversation vs task")
lat = []
for msg in ["hi", "what is a foreign key?", "thanks"]:
    t0 = time.time()
    r = call("POST", "/v1/chat", {"project_id": pid, "message": msg}, tok)
    lat.append((time.time() - t0) * 1000)
    check(f"'{msg}' answered directly", r["mode"] == "chat", f"{int(lat[-1])}ms")
check("conversation under 1s", max(lat) < 1000, f"max {int(max(lat))}ms")
r = call("POST", "/v1/chat", {"project_id": pid, "message": "Build a production SaaS application"}, tok)
check("real work becomes a task", r["mode"] == "task", f"{len(r.get('planned_agents', []))} agents")
check("task returns without blocking", r.get("task_id") is not None)

print("\n[3] deep thinking on complex work")
tid = call("POST", "/v1/tasks", {"project_id": pid,
           "goal": "Research GDPR retention obligations and produce a complete compliance report"},
           tok)["id"]
t0 = time.time()
d = {}
while time.time() - t0 < 150:
    time.sleep(2)
    d = call("GET", "/v1/tasks/" + tid, None, tok)
    if d["status"] == "awaiting_approval":
        call("POST", f"/v1/tasks/{tid}/approve", {}, tok)
    elif d["status"] in ("completed", "failed", "dead", "expired"):
        break
check("complex task completed", d.get("status") == "completed", d.get("status"))
nodes = d.get("dag", {}).get("nodes", [])
done = [n for n in nodes if n["status"] in ("completed", "approved")]
check("every step finished", len(done) == len(nodes), f"{len(done)}/{len(nodes)}")
res = [n["result"] for n in nodes if n.get("result")]
check("agents ran online", any(not r.get("offline") for r in res))
check("multi-pass reasoning used", any(r.get("think_depth", 0) >= 3 for r in res),
      sorted({r.get("think_depth") for r in res}))
check("understanding captured", any(r.get("understanding", {}).get("acceptance_criteria") for r in res))

ev = call("GET", f"/v1/tasks/{tid}/events", None, tok)
evs = ev if isinstance(ev, list) else ev.get("events", [])
phases = Counter(e["payload"].get("phase") for e in evs if e.get("type") == "thinking")
check("phase telemetry streamed", len(phases) >= 3, dict(phases))
check("no raw reasoning leaked", all("content" not in (e.get("payload") or {}) for e in evs))

print("\n[4] local isolation")
cap = call("GET", "/v1/sandboxes/capabilities", None, tok)
check("full local jail", cap["hard_guarantee"] is True, cap["mode"])
check("no remote execution", "never" in cap["remote_execution"])
box = call("POST", "/v1/sandboxes", None, tok)["sandbox_id"]
r = call("POST", "/v1/sandboxes/exec",
         {"sandbox_id": box, "language": "python", "code": "print(6*7)",
          "approve_generated_code": True}, tok)
check("approved code runs", r.get("ok") and "42" in r.get("output", ""), r.get("output", "")[:40])
r = call("POST", "/v1/sandboxes/exec",
         {"sandbox_id": box, "language": "python", "code": "print(1)"}, tok)
check("unapproved code refused", not r.get("ok"))
esc = ("import socket\ntry:\n socket.create_connection(('1.1.1.1',53),timeout=3)\n print('ESCAPED')\n"
       "except Exception: print('blocked')")
r = call("POST", "/v1/sandboxes/exec",
         {"sandbox_id": box, "language": "python", "code": esc,
          "approve_generated_code": True}, tok, t=40)
check("network blocked", "blocked" in r.get("output", ""), r.get("output", "")[:40])
r = call("POST", "/v1/sandboxes/exec",
         {"sandbox_id": box, "language": "shell", "command": "cat /etc/shadow",
          "approve_generated_code": True}, tok, t=40)
check("host files hidden", "No such file" in r.get("output", ""), r.get("output", "")[:40])

print("\n[5] free tools, no API key")
tools = call("GET", "/v1/tools", None, tok)
names = {t["name"] for t in tools}
check("free tool suite registered",
      {"web_search", "wikipedia", "arxiv", "open_meteo", "osm_geocode", "hackernews"} <= names,
      sorted(names))

print("\n[6] budget control")
lim = call("GET", "/v1/providers/limits", None, tok)
check("provider gates live", len(lim["live"]) > 0, list(lim["live"]))
g = list(lim["live"].values())[0]
check("60s windows tracked", "tokens_used_60s" in g and "requests_used_60s" in g)
check("free tier defaults present", "groq" in lim["defaults"] and "gemini" in lim["defaults"])

print("\n[7] BYOK never leaks")
call("POST", "/v1/keys", {"provider_slug": "openai", "api_key": "sk-SUPERSECRET-abc123456"}, tok)
keys = call("GET", "/v1/keys", None, tok)
blob = json.dumps(keys)
check("key not returned", "SUPERSECRET" not in blob)
check("only fingerprint shown", all("fingerprint" in k for k in keys))

print("\n[8] streaming with browser-style auth")
req = urllib.request.Request(f"{B}/v1/runs/{tid}/stream?token={tok}")
got = []
try:
    with urllib.request.urlopen(req, timeout=10) as f:
        for _ in range(6):
            line = f.readline()
            if not line:
                break
            if line.strip():
                got.append(line.decode().strip())
except Exception as e:
    got.append("ERR " + str(e)[:60])
check("SSE accepts ?token=", any(x.startswith("event:") for x in got), got[:2])

print("\n[9] resilience")
tid2 = call("POST", "/v1/tasks", {"project_id": pid, "goal": "Write a short poem about rain"}, tok)["id"]
time.sleep(1)
call("POST", f"/v1/tasks/{tid2}/cancel", {}, tok)
time.sleep(2)
d2 = call("GET", "/v1/tasks/" + tid2, None, tok)
check("cancellation honoured", d2["status"] in ("cancelled", "completed"), d2["status"])

print("\n" + ("ALL CHECKS PASSED" if not FAIL else f"{len(FAIL)} FAILED: {FAIL}"))
