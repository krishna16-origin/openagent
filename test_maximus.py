"""Unit tests. No server, no network, no model gateway required.

    python -m pytest tests/ -q
"""
import asyncio
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app  # noqa: E402


# ----------------------------------------------------------------- catalogue
def test_catalogue_size_and_shape():
    assert len(app.REGISTRY) >= 400
    assert len({d.domain for d in app.REGISTRY.values()}) >= 30
    for d in app.REGISTRY.values():
        assert d.id and d.name and d.system_instructions
        assert d.cost_level in {"low", "medium", "high"}
        assert d.risk_level in {"low", "medium", "high"}
        assert d.verification_strategy in {
            "factual", "code", "tests", "security", "quality", "completion"}


def test_ids_and_names_unique():
    ids = [d.id for d in app.REGISTRY.values()]
    assert len(ids) == len(set(ids))


def test_legacy_aliases_still_resolve():
    for short in ("goal_analyzer", "backend", "security", "critic", "final_verifier"):
        assert app.resolve_agent(short) is not None


def test_unknown_agent_resolves_to_none():
    assert app.resolve_agent("does.not.exist") is None


# -------------------------------------------------------------------- router
@pytest.mark.parametrize("goal,expect_domain", [
    ("Reconcile the ledger and prepare the payroll tax filing", "accounting"),
    ("Audit our Kubernetes cluster for security vulnerabilities", "security"),
    ("Write a fantasy novel outline with character arcs", "creative_writing"),
    ("Design and validate a financial model for a subscription business", "finance"),
    ("Fix the flaky tests in our CI pipeline", "quality_assurance"),
    ("Translate our marketing site into Japanese", "localization"),
])
def test_router_picks_the_right_field(goal, expect_domain):
    plan = app.route_goal(goal)
    domains = {st.agent_id.split(".")[0] for st in plan.steps}
    assert expect_domain in domains, domains


def test_plan_always_has_a_spine():
    plan = app.route_goal("do something vague")
    ids = [st.agent_id for st in plan.steps]
    assert any("goal_decomposer" in i for i in ids)
    assert any("final_verifier" in i for i in ids)


def test_router_is_fast_over_the_whole_catalogue():
    t0 = time.monotonic()
    for _ in range(200):
        app.route_goal("Build a production SaaS application with payments and search")
    per_plan_ms = (time.monotonic() - t0) / 200 * 1000
    assert per_plan_ms < 15, per_plan_ms


def test_first_layer_has_no_dependencies():
    plan = app.route_goal("Build a production-ready SaaS application")
    assert plan.steps[0].depends_on == []


# ------------------------------------------------------------------- intent
@pytest.mark.parametrize("msg,mode", [
    ("hi", "chat"), ("hey there", "chat"), ("thanks!", "chat"),
    ("what is a foreign key?", "chat"), ("why is the sky blue", "chat"),
    ("explain recursion", "chat"), ("who invented python", "chat"),
    ("Build me a production-ready SaaS application.", "task"),
    ("fix the flaky tests in CI", "task"),
    ("write a python script to parse csv", "task"),
    ("Research GDPR and write a compliance report", "task"),
    ("design a database schema for orders", "task"),
])
def test_intent_routing(msg, mode):
    assert app.classify_intent(msg)["mode"] == mode, msg


def test_intent_survives_odd_input():
    for msg in ["", "   ", "是什么", "こんにちは", "!!!", "?"]:
        assert app.classify_intent(msg)["mode"] in ("chat", "task")


def test_intent_prefix_overrides():
    assert app.classify_intent("/task hi")["mode"] == "task"
    assert app.classify_intent("/chat build me an entire platform")["mode"] == "chat"


# -------------------------------------------------------------- rate limits
def test_sliding_window_never_breaches():
    async def run():
        w = app.SlidingWindow(limit=100, window_s=60)
        for _ in range(100):
            await w.acquire(1)
        assert w.used == 100
        with pytest.raises(app.AppError):
            await w.acquire(1, timeout_s=0.2)
    asyncio.run(run())


def test_window_gives_capacity_back():
    async def run():
        w = app.SlidingWindow(limit=10, window_s=60)
        await w.acquire(10)
        await w.give_back(5)
        await w.acquire(5, timeout_s=1)      # must not raise
    asyncio.run(run())


def test_token_bucket_paces_to_its_rate():
    async def run():
        b = app.TokenBucket(rate_per_sec=100, capacity=100)
        await b.acquire(100)                  # drain
        t0 = time.monotonic()
        await b.acquire(50)                   # needs ~0.5s of refill
        assert 0.35 < time.monotonic() - t0 < 0.9
    asyncio.run(run())


def test_gate_respects_daily_cap():
    async def run():
        g = app.ProviderGate("t", dict(rpm=6000, tpm=0, rpd=3, concurrency=4))
        for _ in range(3):
            await g.acquire(1)
        with pytest.raises(app.AppError):
            await g.acquire(1)
    asyncio.run(run())


def test_gate_throttles_itself_on_429():
    g = app.ProviderGate("t", dict(rpm=100, tpm=1000, rpd=0, concurrency=2))
    assert g.scale == 1.0
    g.on_rate_limited(None)
    assert g.scale < 1.0
    assert g.req_window.limit < 100


def test_circuit_breaker_opens_and_recovers():
    b = app.CircuitBreaker(threshold=2, cooldown_s=0.2)
    b.record(False); b.record(False)
    assert b.state == "open"
    with pytest.raises(app.AppError):
        b.check()
    time.sleep(0.25)
    assert b.state == "half_open"
    b.record(True)
    assert b.state == "closed"


def test_token_estimate_errs_high():
    msgs = [{"role": "user", "content": "x" * 400}]
    assert app.estimate_tokens(msgs, 0) >= 100


# ------------------------------------------------------- model discovery
def test_normalise_openai_shape():
    out = app._normalise_models("openai", {"data": [{"id": "gpt-4o-mini"}, {"id": "o3"}]})
    ids = {m["model_id"] for m in out}
    assert ids == {"gpt-4o-mini", "o3"}
    assert [m for m in out if m["model_id"] == "o3"][0]["tier"] == "premium"


def test_normalise_gemini_strips_prefix_and_filters_non_chat():
    payload = {"models": [
        {"name": "models/gemini-2.0-flash", "inputTokenLimit": 1048576,
         "supportedGenerationMethods": ["generateContent"]},
        {"name": "models/embedding-001", "supportedGenerationMethods": ["embedContent"]}]}
    out = app._normalise_models("gemini", payload)
    assert [m["model_id"] for m in out] == ["gemini-2.0-flash"]
    assert "long-context" in out[0]["capability_tags"]


def test_normalise_openrouter_pricing():
    out = app._normalise_models("openrouter", {"data": [
        {"id": "deepseek/deepseek-r1", "context_length": 163840,
         "pricing": {"prompt": "0.00000055", "completion": "0.00000219"}}]})
    assert out[0]["cost_in_per_1k"] > 0
    assert out[0]["context_window"] == 163840


def test_capability_inference():
    assert "code" in app.infer_capabilities("qwen2.5-coder-32b")
    assert "vision" in app.infer_capabilities("pixtral-12b")
    assert "embedding" in app.infer_capabilities("text-embedding-3-small")
    assert "cheap" in app.infer_capabilities("claude-haiku-4")


def test_pick_model_prefers_cheap_on_small_budget():
    models = [{"model_id": "big", "capability_tags": ["reasoning", "general"],
               "cost_in_per_1k": 0.01, "tier": "premium", "context_window": 200000},
              {"model_id": "small", "capability_tags": ["reasoning", "general"],
               "cost_in_per_1k": 0.0001, "tier": "cheap", "context_window": 128000}]
    assert app.pick_model(models, "reasoning", budget_usd=0.2)["model_id"] == "small"


# ---------------------------------------------------------------- security
def test_path_jail():
    root = app.data_dir()
    for bad in ("../../etc/passwd", "/etc/passwd", "a/../../../x"):
        with pytest.raises(Exception):
            app.assert_path_inside(root, bad)


def test_ssrf_guard_blocks_private_space():
    for bad in ("http://127.0.0.1/x", "http://169.254.169.254/latest/meta-data",
                "http://10.0.0.1/", "file:///etc/passwd"):
        with pytest.raises(Exception):
            app.assert_url_allowed(bad)


def test_secret_roundtrip_and_fingerprint():
    secret = "sk-test-abcdef0123456789"
    blob = app.encrypt_secret(secret)
    assert secret not in blob
    assert app.decrypt_secret(blob) == secret
    assert secret not in app.fingerprint(secret)


def test_redaction_strips_keys():
    text = "here is sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 and more"
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in app.redact(text)


def test_password_hash_is_not_reversible():
    h = app.hash_password("Passw0rd!123")
    assert "Passw0rd" not in h
    assert app.verify_password("Passw0rd!123", h)
    assert not app.verify_password("wrong", h)


# ------------------------------------------------------------------ sandbox
def test_isolation_report_is_honest():
    rep = app.isolation_report()
    assert rep["mode"] in ("chroot_ns", "netns", "none")
    # the report must not claim a guarantee the mode cannot deliver
    assert rep["hard_guarantee"] == (rep["mode"] == "chroot_ns")
    assert rep["layers"]["explicit_approval_required"] is True


def test_execution_requires_approval():
    async def run():
        rt = app.get_sandbox()
        box = await rt.create("unit")
        res = await rt.exec(box, "python", "print(1)", "", approve=False)
        assert not res["ok"] and "approval" in res["error"]
    asyncio.run(run())


@pytest.mark.skipif(app.ISOLATION_MODE != "chroot_ns", reason="needs user namespaces")
def test_sandbox_has_no_network_and_no_host_files():
    async def run():
        rt = app.get_sandbox()
        box = await rt.create("unit-sec")
        code = ("import socket\n"
                "try:\n socket.create_connection(('1.1.1.1',53),timeout=3); print('ESCAPED')\n"
                "except Exception: print('blocked')")
        r = await rt.exec(box, "python", code, "", approve=True)
        assert "blocked" in r["output"] and "ESCAPED" not in r["output"]
        r = await rt.exec(box, "shell", "", "cat /etc/shadow", approve=True)
        assert "No such file" in r.get("output", "")
    asyncio.run(run())


# ------------------------------------------------------------------ planner
def test_dag_lifecycle():
    plan = app.route_goal("Build a production-ready SaaS application")
    dag = app.plan_to_dag(plan)
    assert dag["nodes"] and dag["deadline_at"] > time.time()
    ready = app.ready_nodes(dag)
    assert ready and all(n["depends_on"] == [] for n in ready)
    for n in dag["nodes"]:
        n["status"] = "completed"
    assert app.dag_status(dag) == "completed"


def test_expansion_is_bounded():
    plan = app.route_goal("Build something")
    dag = app.plan_to_dag(plan)
    dag["max_expansions"] = 1
    parent = dag["nodes"][0]
    subs = [{"agent": "quality_assurance.unit_test_writer", "description": "write tests"}]
    assert app.expand_dag(dag, parent, subs, "g") == 1
    assert app.expand_dag(dag, parent, subs, "g") == 0   # budget spent


def test_deadline_detection():
    dag = {"nodes": [], "deadline_at": time.time() - 1}
    assert app.dag_expired(dag)
    assert not app.dag_expired({"nodes": [], "deadline_at": time.time() + 60})


def test_human_gates_exist_for_risky_roles():
    assert app.needs_human_gate("devops.release_manager")
    assert not app.needs_human_gate("creative_writing.poet")


# ---------------------------------------------------------------- reasoning
def test_json_recovery_from_messy_output():
    assert app._safe_json('```json\n{"a":1}\n```') == {"a": 1}
    assert app._safe_json('Sure! Here you go: {"a": 2} hope that helps') == {"a": 2}
    assert app._safe_json("no json here") is None
    assert app._safe_json("") is None


def test_depth_scales_with_risk_and_complexity():
    low = app.resolve_agent("creative_writing.poet")
    high = app.resolve_agent("security.appsec_reviewer")
    assert app.depth_for({"complexity": 0.5}, high) > app.depth_for({"complexity": 0.0}, low)
    assert app.depth_for({"attempts": 3}, low) >= app.depth_for({"attempts": 1}, low)


def test_upstream_handoff_is_structured_and_bounded():
    dag = {"nodes": [
        {"node_id": "n0", "depends_on": [], "status": "completed",
         "result": {"agent": "a", "domain": "d", "deliverable": "x" * 50000,
                    "understanding": {"acceptance_criteria": ["c1"], "unknowns": ["u1"]}}},
        {"node_id": "n1", "depends_on": ["n0"], "status": "pending", "result": None}]}
    up = app.collect_upstream(dag, dag["nodes"][1], max_chars=2000)
    assert "n0" in up
    assert len(up["n0"]["deliverable"]) < 50000
    assert up["n0"]["acceptance_criteria"] == ["c1"]


# ------------------------------------------------------------------- cache
def test_response_cache_hits_and_expires():
    c = app.ResponseCache(max_items=4, ttl_s=10)
    msgs = [{"role": "user", "content": "hello"}]
    assert c.get(msgs, "general", 100, "") is None
    c.put(msgs, "general", 100, "", {"ok": True})
    hit = c.get(msgs, "general", 100, "")
    assert hit and hit["_cached"] is True
    assert c.stats()["hits"] == 1


def test_cache_evicts_oldest():
    c = app.ResponseCache(max_items=2, ttl_s=60)
    for i in range(4):
        c.put([{"role": "user", "content": str(i)}], "g", 10, "", {"i": i})
    assert c.stats()["size"] == 2


# ------------------------------------------------------------------- tools
def test_every_tool_declares_scopes():
    for t in app.TOOLS.list():
        assert t.name and t.description
        assert isinstance(t.scopes, list)


def test_free_tools_are_registered():
    names = {t.name for t in app.TOOLS.list()}
    assert {"web_search", "wikipedia", "arxiv", "open_meteo",
            "osm_geocode", "crossref", "hackernews"} <= names


def test_tool_permission_is_enforced():
    async def run():
        res = await app.TOOLS.call("filesystem", {"op": "list"}, {"project_id": "p"}, granted=[])
        assert not res.ok and "permission denied" in res.error
    asyncio.run(run())


def test_html_stripper():
    assert "alert" not in app._strip_html("<script>alert(1)</script>hello")
    assert "hello" in app._strip_html("<p>hello</p>")
