#!/usr/bin/env python3
"""OmniRoute-shaped gateway — the missing piece between app.py and a real model provider.

app.py never calls OpenAI/Anthropic/Groq directly. It calls this gateway's
POST /v1/chat/completions with {"messages": [...], "capability": "cheap", ...} and
expects back {"choices": [{"message": {"content": "..."}}], "usage": {...}} — the
same shape mock_gateway.py fakes for tests. This version calls a REAL provider.

Stdlib only. No pip install needed.

Run locally (drop-in replacement for mock_gateway.py, same port):
    GATEWAY_PROVIDER=groq GATEWAY_API_KEY=gsk_... python omniroute_gateway.py
    # then point the main app at it: OMNIROUTE_BASE_URL=http://127.0.0.1:9000

Run on Render: see render.yaml. Set these env vars on THIS service:
    GATEWAY_PROVIDER      openai | anthropic | groq | openai_compatible   (default: groq)
    GATEWAY_API_KEY       your real provider API key                     (required)
    GATEWAY_AUTH_TOKEN    a shared secret; if set, callers must send
                           Authorization: Bearer <this>. Set the SAME value as
                           OMNIROUTE_API_KEY on the main app.py service.   (recommended)
    GATEWAY_BASE_URL      override the provider's base URL — required for
                           GATEWAY_PROVIDER=openai_compatible, optional otherwise
    MODEL_MAP_JSON        override which model id each "capability" maps to, e.g.
                           '{"cheap":"llama-3.1-8b-instant","general":"llama-3.3-70b-versatile"}'
Then on the MAIN app.py service, set:
    OMNIROUTE_BASE_URL    this gateway's URL, e.g. https://openagent-gateway.onrender.com
    OMNIROUTE_API_KEY     same value as GATEWAY_AUTH_TOKEN above
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------------------

def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


PROVIDER = _env("GATEWAY_PROVIDER", "groq").strip().lower()
API_KEY = _env("GATEWAY_API_KEY", "").strip()
AUTH_TOKEN = _env("GATEWAY_AUTH_TOKEN", "").strip()
TIMEOUT_S = float(_env("GATEWAY_TIMEOUT_S", "60"))

# Per-provider defaults. "openai_compatible" covers OpenRouter, DeepSeek, Together,
# Mistral, NVIDIA, a self-hosted vLLM/Ollama server, etc. — anything that implements
# POST {base_url}/chat/completions the same way OpenAI does.
_PROVIDER_DEFAULTS = {
    "groq": {
        "kind": "openai_compatible",
        "base_url": "https://api.groq.com/openai/v1",
        "models": {
            "cheap": "openai/gpt-oss-20b",
            "general": "openai/gpt-oss-120b",
            "reasoning": "openai/gpt-oss-120b",
            "code": "openai/gpt-oss-120b",
            "vision": "openai/gpt-oss-120b",
            "long-context": "openai/gpt-oss-120b",
        },
    },
    "openai": {
        "kind": "openai_compatible",
        "base_url": "https://api.openai.com/v1",
        "models": {
            "cheap": "gpt-4o-mini",
            "general": "gpt-4o-mini",
            "reasoning": "gpt-4o",
            "code": "gpt-4o",
            "vision": "gpt-4o",
            "long-context": "gpt-4o",
        },
    },
    "anthropic": {
        "kind": "anthropic",
        "base_url": "https://api.anthropic.com",
        "models": {
            "cheap": "claude-haiku-4-5-20251001",
            "general": "claude-sonnet-5",
            "reasoning": "claude-sonnet-5",
            "code": "claude-sonnet-5",
            "vision": "claude-sonnet-5",
            "long-context": "claude-sonnet-5",
        },
    },
    "openai_compatible": {
        "kind": "openai_compatible",
        "base_url": "",  # must come from GATEWAY_BASE_URL
        "models": {},    # must come from MODEL_MAP_JSON
    },
}

if PROVIDER not in _PROVIDER_DEFAULTS:
    raise SystemExit(
        f"GATEWAY_PROVIDER={PROVIDER!r} not recognised. "
        f"Use one of: {', '.join(_PROVIDER_DEFAULTS)}"
    )

_cfg = _PROVIDER_DEFAULTS[PROVIDER]
BASE_URL = (_env("GATEWAY_BASE_URL", "") or _cfg["base_url"]).rstrip("/")
MODEL_MAP = dict(_cfg["models"])
_override = _env("MODEL_MAP_JSON", "")
if _override:
    try:
        MODEL_MAP.update(json.loads(_override))
    except Exception as e:
        print(f"[gateway] MODEL_MAP_JSON ignored, invalid JSON: {e}")

if not API_KEY:
    print("[gateway] WARNING: GATEWAY_API_KEY is not set — every request will fail with 401.")
if PROVIDER == "openai_compatible" and not BASE_URL:
    raise SystemExit("GATEWAY_PROVIDER=openai_compatible requires GATEWAY_BASE_URL.")

DEFAULT_MODEL = MODEL_MAP.get("general") or next(iter(MODEL_MAP.values()), None)

_MODEL_ALIASES = {
    "llama-3.1-8b-instant": "openai/gpt-oss-20b",
    "llama-3.3-70b-versatile": "openai/gpt-oss-120b",
}


def _normalize_model(model: str | None) -> str | None:
    return _MODEL_ALIASES.get(model, model) if model else model

# Render (and most PaaS hosts) inject PORT and expect 0.0.0.0. Local default matches
# mock_gateway.py's port (9000) so this is a drop-in replacement.
_ON_RENDER = bool(_env("RENDER") or _env("PORT"))
HOST = _env("GATEWAY_HOST", "0.0.0.0" if _ON_RENDER else "127.0.0.1")
PORT = int(_env("PORT", _env("GATEWAY_PORT", "9000")))

_KEY_PATTERN = re.compile(r"(sk-[A-Za-z0-9\-_]{8,}|gsk_[A-Za-z0-9\-_]{8,})")


def _redact(text: str) -> str:
    return _KEY_PATTERN.sub("[REDACTED]", text or "")


# --------------------------------------------------------------------------------------
# Outbound HTTP (stdlib only — no httpx/requests dependency needed for this service)
# --------------------------------------------------------------------------------------

class UpstreamError(Exception):
    def __init__(self, status: int, body: str, retry_after: str | None = None):
        super().__init__(f"upstream {status}: {body[:300]}")
        self.status = status
        self.body = body
        self.retry_after = retry_after


def _post_json(url: str, headers: dict, payload: dict, timeout_s: float) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise UpstreamError(e.code, body, e.headers.get("Retry-After") if e.headers else None) from e
    except urllib.error.URLError as e:
        raise UpstreamError(502, f"could not reach {url}: {e.reason}") from e


# --------------------------------------------------------------------------------------
# Provider adapters — each returns the normalized {"choices": [...], "usage": {...}} shape
# --------------------------------------------------------------------------------------

def _call_openai_compatible(model: str, messages: list[dict], temperature: float,
                             max_tokens: int, timeout_s: float, api_key: str) -> dict:
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    payload = {"model": model, "messages": messages, "temperature": temperature,
               "max_tokens": max_tokens}
    if PROVIDER == "groq":
        payload["max_completion_tokens"] = payload.pop("max_tokens")
    data = _post_json(f"{BASE_URL}/chat/completions", headers, payload, timeout_s)
    # Already in OpenAI's shape — pass through, but make sure the fields the main
    # app reads (choices[0].message.content, usage.total_tokens) are present.
    data.setdefault("model", model)
    return data


def _call_anthropic(model: str, messages: list[dict], temperature: float,
                    max_tokens: int, timeout_s: float, api_key: str) -> dict:
    system_parts = [m.get("content", "") for m in messages if m.get("role") == "system"]
    convo = [m for m in messages if m.get("role") in ("user", "assistant")]
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    payload = {
        "model": model,
        "max_tokens": max_tokens or 1024,
        "temperature": temperature,
        "messages": convo,
    }
    if system_parts:
        payload["system"] = "\n\n".join(p for p in system_parts if p)
    data = _post_json(f"{BASE_URL}/v1/messages", headers, payload, timeout_s)
    text = "".join(
        block.get("text", "") for block in data.get("content", []) if block.get("type") == "text"
    )
    usage = data.get("usage", {}) or {}
    prompt_tokens = int(usage.get("input_tokens") or 0)
    completion_tokens = int(usage.get("output_tokens") or 0)
    return {
        "model": model,
        "choices": [{"message": {"role": "assistant", "content": text}}],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


def complete(capability: str, model_hint: str | None, messages: list[dict],
             temperature: float, max_tokens: int, timeout_s: float,
             api_key: str | None = None, provider_slug: str = "") -> dict:
    # The main app may provide a user-scoped BYOK key through X-Provider-Key.
    # The gateway still controls provider/model selection via its deployment config.
    active_key = (api_key or API_KEY).strip()
    if not active_key:
        raise UpstreamError(401, "no provider API key configured")
    model = _normalize_model(model_hint or MODEL_MAP.get(capability) or DEFAULT_MODEL)
    if not model:
        raise UpstreamError(400, f"no model configured for capability={capability!r}")
    if _cfg["kind"] == "anthropic":
        return _call_anthropic(model, messages, temperature, max_tokens, timeout_s, active_key)
    return _call_openai_compatible(model, messages, temperature, max_tokens, timeout_s, active_key)


# --------------------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "OmniRouteGateway/1.0"

    def log_message(self, fmt: str, *args) -> None:  # quieter, redacted logs
        print(f"[gateway] {self.address_string()} - {_redact(fmt % args)}")

    def _send(self, obj: dict, code: int = 200, extra_headers: dict | None = None) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if not AUTH_TOKEN:
            return True
        got = self.headers.get("Authorization", "")
        return got == f"Bearer {AUTH_TOKEN}"

    def do_GET(self) -> None:
        if self.path.startswith("/health"):
            self._send({"status": "healthy", "provider": PROVIDER, "base_url": BASE_URL})
            return
        if self.path.startswith("/models"):
            self._send({"data": [{"id": m} for m in sorted(set(MODEL_MAP.values()))]})
            return
        self._send({"error": "not found"}, 404)

    def do_POST(self) -> None:
        if not self.path.startswith("/v1/chat/completions"):
            self._send({"error": "not found"}, 404)
            return
        if not self._authorized():
            self._send({"error": "unauthorized"}, 401)
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._send({"error": "invalid JSON body"}, 400)
            return

        messages = body.get("messages") or []
        capability = body.get("capability") or "general"
        model_hint = body.get("model") or None
        temperature = float(body.get("temperature", 0.2))
        max_tokens = int(body.get("max_tokens", 700))
        provider_key = self.headers.get("X-Provider-Key", "").strip() or API_KEY
        provider_slug = self.headers.get("X-Provider-Slug", "").strip()

        t0 = time.monotonic()
        try:
            data = complete(capability, model_hint, messages, temperature, max_tokens, TIMEOUT_S,
                            api_key=provider_key, provider_slug=provider_slug)
            data["_latency_ms"] = int((time.monotonic() - t0) * 1000)
            self._send(data)
        except UpstreamError as e:
            headers = {"Retry-After": e.retry_after} if e.retry_after else {}
            # Pass the real status through: app.py treats 429 as rate-limit-and-retry
            # and >=500 as a retryable provider error, so this preserves that behaviour.
            status = e.status if e.status in (401, 403, 404, 429) or e.status >= 500 else 502
            self._send({"error": _redact(str(e))}, status, headers)
        except Exception as e:  # never let one bad request take the server down
            self._send({"error": f"gateway error: {_redact(str(e))[:300]}"}, 500)


def main() -> None:
    print(f"[gateway] provider={PROVIDER} base_url={BASE_URL} "
          f"models={MODEL_MAP} auth={'on' if AUTH_TOKEN else 'off'}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
