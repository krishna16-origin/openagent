#!/usr/bin/env python3
"""Maximus AI — complete backend in a SINGLE file.

Autonomous multi-agent OS. Local-storage only: SQLite file + local folders.
MAXIMUS = orchestration · OMNIROUTE = model gateway · MCP = tools · SANDBOX = execution · MEMORY = context.

Run:
    pip install fastapi "uvicorn[standard]" "sqlalchemy[asyncio]" aiosqlite pydantic python-jose cryptography httpx
    cp .env.example .env   (optional)
    python app.py
    # docs: http://127.0.0.1:8000/docs

Data lives in ./data/ (maximus.db, projects/, sandboxes/). No external DB/server needed.
"""
from __future__ import annotations

import asyncio
import copy
import base64
import hashlib
import ipaddress
import random
import json
import logging
import math
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import sqlite3
import tempfile
import time
import urllib.parse
import uuid
from collections import OrderedDict, defaultdict, deque
from enum import Enum
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# =====================================================================================
# 1. SETTINGS (.env supported, no extra dependency)
# =====================================================================================
BASE_DIR = Path(__file__).resolve().parent


def _load_dotenv() -> None:
    env = BASE_DIR / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


# Render provides a private host/port for service-to-service traffic.  The old
# default pointed at localhost, which is only correct when app.py and the
# gateway are running in the same local machine/process namespace.
_ON_RENDER = bool(_env("RENDER") or _env("PORT"))
_RENDER_GATEWAY_HOST = _env("OMNIROUTE_RENDER_HOST", "openagent-gateway")
_RENDER_GATEWAY_PORT = _env("OMNIROUTE_RENDER_PORT", "10000")
_DEFAULT_OMNIROUTE_BASE_URL = (
    f"http://{_RENDER_GATEWAY_HOST}:{_RENDER_GATEWAY_PORT}" if _ON_RENDER
    else "http://127.0.0.1:9000"
)


class S:
    APP_NAME = _env("APP_NAME", "MaximusAI")
    SECRET_KEY = _env("SECRET_KEY", "dev-only-change-me-min-32-chars-1234567890")
    JWT_ALGORITHM = _env("JWT_ALGORITHM", "HS256")
    JWT_ACCESS_MINUTES = int(_env("JWT_ACCESS_MINUTES", "15"))
    JWT_REFRESH_DAYS = int(_env("JWT_REFRESH_DAYS", "30"))
    DATABASE_URL = _env("DATABASE_URL", f"sqlite+aiosqlite:///{(BASE_DIR / 'data' / 'maximus.db').as_posix()}")
    DATA_DIR = _env("DATA_DIR", str(BASE_DIR / "data"))
    SECRETS_MASTER_KEY = _env("SECRETS_MASTER_KEY", "")
    # An explicitly configured URL always wins.  An empty Render variable (the
    # previous render.yaml value) is treated as unset so it cannot produce a
    # relative URL or silently fall back to localhost.
    OMNIROUTE_BASE_URL = (
        _env("OMNIROUTE_BASE_URL", "").strip() or _DEFAULT_OMNIROUTE_BASE_URL
    ).rstrip("/")
    OMNIROUTE_API_KEY = _env("OMNIROUTE_API_KEY", "")
    OMNIROUTE_TIMEOUT_S = int(_env("OMNIROUTE_TIMEOUT_S", "60"))
    OMNIROUTE_DEFAULT_CAPABILITY = _env("OMNIROUTE_DEFAULT_CAPABILITY", "reasoning")
    ALLOWED_SANDBOX_ROOT = _env("ALLOWED_SANDBOX_ROOT", str(BASE_DIR / "data" / "sandboxes"))
    MAX_TOKENS_PER_TASK = int(_env("MAX_TOKENS_PER_TASK", "120000"))
    MAX_COST_USD_PER_TASK = float(_env("MAX_COST_USD_PER_TASK", "5.0"))
    MAX_RETRIES = int(_env("MAX_RETRIES", "3"))
    RATE_LIMIT_PER_MIN = int(_env("RATE_LIMIT_PER_MIN", "60"))
    # Local setup (unchanged): `python app.py` with no env vars still binds 127.0.0.1:8000.
    # Cloud setup (new): Render (and most PaaS hosts) inject PORT and require the process to
    # listen on 0.0.0.0. If PORT is present — or RENDER is set, which Render always sets — we
    # bind 0.0.0.0 and use that port automatically. API_HOST/API_PORT still win if set explicitly.
    API_HOST = _env("API_HOST", "0.0.0.0" if _ON_RENDER else "127.0.0.1")
    API_PORT = int(_env("PORT", _env("API_PORT", "8000")))


def data_dir() -> Path:
    p = Path(S.DATA_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return p


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("maximus")

# =====================================================================================
# 2. ERRORS + SECRET REDACTION (never log keys)
# =====================================================================================
REDACTED = "[REDACTED]"
_KEY_PATTERNS = [
    re.compile(r"(sk-[A-Za-z0-9\-_]{8,})"),
    re.compile(r"(xox[bap]-[A-Za-z0-9\-_]{8,})"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)(['\"]?)([A-Za-z0-9\-_\.]{8,})"),
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9\-_\.]+)"),
]


def redact(text: str) -> str:
    if not text or not isinstance(text, str):
        return text
    out = text
    for pat in _KEY_PATTERNS:
        def _sub(m: re.Match) -> str:
            s = m.group(0)
            for g in range(len(m.groups()), 0, -1):
                val = m.group(g)
                if val and len(val) >= 8 and not val.strip().lower().startswith(("api", "bearer", "key")):
                    return s.replace(val, REDACTED)
            return REDACTED
        out = pat.sub(_sub, out)
    return out


class AppError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

# =====================================================================================
# 3. GUARDS — SSRF / paths / commands / prompt-injection / budgets / rate limits
# =====================================================================================
_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254", "metadata.google.internal"}


def _ip_is_forbidden(ip: ipaddress._BaseAddress) -> bool:
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified
                or (getattr(ip, "ipv4_mapped", None) and _ip_is_forbidden(ip.ipv4_mapped)))


_DNS_CACHE: dict[str, tuple[float, list[str]]] = {}


def _resolve(host: str, ttl: float = 60.0) -> list[str]:
    now = time.time()
    hit = _DNS_CACHE.get(host)
    if hit and now - hit[0] < ttl:
        return hit[1]
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        addrs = sorted({i[4][0] for i in infos})
    except Exception:
        addrs = []
    _DNS_CACHE[host] = (now, addrs)
    return addrs


def assert_url_allowed(url: str, allow_private: bool = False) -> str:
    """SSRF guard.

    The previous version raised inside a try/except ValueError, so its own rejection was
    swallowed and every private IP outside the literal blocklist was allowed through.
    This checks the literal host, then resolves the name so a public hostname pointing at
    10.x / 192.168.x / 169.254.169.254 cannot be used to reach the internal network.
    """
    u = urlparse(url)
    if u.scheme not in ("http", "https"):
        raise ValueError(f"blocked scheme: {u.scheme or 'none'}")
    host = (u.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("blocked: no host in url")
    if allow_private:
        return url
    if host in _BLOCKED_HOSTS or host.endswith(".internal") or host.endswith(".local"):
        raise ValueError(f"blocked host (SSRF): {host}")

    literal: ipaddress._BaseAddress | None = None
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None                      # a name, not an address — resolve it below
    if literal is not None:
        if _ip_is_forbidden(literal):
            raise ValueError(f"blocked private address (SSRF): {host}")
        return url

    addrs = _resolve(host)
    if not addrs:
        raise ValueError(f"blocked: could not resolve {host}")
    for a in addrs:
        try:
            if _ip_is_forbidden(ipaddress.ip_address(a)):
                raise ValueError(f"blocked: {host} resolves to internal address {a}")
        except ValueError as e:
            if "blocked" in str(e):
                raise
    return url


def assert_path_inside(root: Path, target: str | Path) -> Path:
    root = Path(root).resolve()
    t = Path(str(target))
    p = (root / t).resolve() if not t.is_absolute() else t.resolve()
    if p != root and root not in p.parents:
        raise ValueError(f"path escape blocked: {target}")
    return p


DENIED_CMD_TOKENS = {"rm -rf /", "mkfs", ":(){", "dd if=", "shutdown", "reboot"}


def assert_command_allowed(cmd: str) -> str:
    low = cmd.lower()
    for tok in DENIED_CMD_TOKENS:
        if tok in low:
            raise ValueError(f"dangerous command blocked: {tok}")
    return cmd


_INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore (all |previous |above )?instructions"),
    re.compile(r"(?i)system\s*:\s*you are now"),
    re.compile(r"(?i)exfiltrate|send .* to http"),
]


def sanitize_tool_output(text: str, max_chars: int = 20000) -> str:
    text = (text or "")[:max_chars]
    for pat in _INJECTION_PATTERNS:
        text = pat.sub("[filtered-instruction]", text)
    return text


def build_messages(system: str, user_goal: str, history: list[dict] | None = None) -> list[dict]:
    msgs = [{"role": "system", "content": system}]
    msgs.extend(history or [])
    msgs.append({"role": "user", "content": f"<user_goal>\n{user_goal}\n</user_goal>"})
    return msgs


class Budget:
    def __init__(self, max_tokens: int, max_usd: float):
        self.max_tokens = max_tokens
        self.max_usd = max_usd
        self.used_tokens = 0
        self.used_usd = 0.0

    def add(self, tokens: int, usd: float) -> None:
        self.used_tokens += tokens
        self.used_usd += usd
        if self.used_tokens >= self.max_tokens:
            raise RuntimeError("task token budget exhausted")
        if self.used_usd >= self.max_usd:
            raise RuntimeError("task cost budget exhausted")


class RateLimiter:
    def __init__(self, per_min: int = 60):
        self.per_min = per_min
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.time()
        q = self._hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.per_min:
            raise RuntimeError("rate limit exceeded")
        q.append(now)


limiter = RateLimiter(S.RATE_LIMIT_PER_MIN)


# =====================================================================================
# 3b. Free-tier budget control — token buckets, adaptive limits, circuit breakers
# =====================================================================================
# These are DEFAULTS for well-known free tiers. They are starting points, not gospel:
# providers change them, and they differ per model and per account. Every field can be
# overridden per provider via PROVIDER_LIMITS_JSON, and every gate adapts downward
# automatically when the provider answers 429.
FREE_TIER_DEFAULTS: dict[str, dict] = {
    #                     rpm    tpm      rpd     concurrency
    "groq":        dict(rpm=30,  tpm=6000,    rpd=14400, concurrency=2),
    "gemini":      dict(rpm=15,  tpm=1000000, rpd=1500,  concurrency=2),
    "mistral":     dict(rpm=60,  tpm=500000,  rpd=0,     concurrency=2),
    "openrouter":  dict(rpm=20,  tpm=0,       rpd=50,    concurrency=2),
    "deepseek":    dict(rpm=60,  tpm=0,       rpd=0,     concurrency=4),
    "nvidia":      dict(rpm=40,  tpm=0,       rpd=1000,  concurrency=2),
    "openai":      dict(rpm=500, tpm=30000,   rpd=10000, concurrency=8),
    "anthropic":   dict(rpm=50,  tpm=20000,   rpd=0,     concurrency=4),
    "cohere":      dict(rpm=20,  tpm=0,       rpd=1000,  concurrency=2),
    "together":    dict(rpm=60,  tpm=0,       rpd=0,     concurrency=4),
    "_default":    dict(rpm=600, tpm=0,       rpd=0,     concurrency=8),
    "local":       dict(rpm=0,   tpm=0,       rpd=0,     concurrency=16),
}


def _limits_for(provider: str) -> dict:
    override = _env("PROVIDER_LIMITS_JSON", "")
    if override:
        try:
            table = json.loads(override)
            if provider in table:
                base = dict(FREE_TIER_DEFAULTS.get(provider, FREE_TIER_DEFAULTS["_default"]))
                base.update(table[provider])
                return base
        except Exception as e:
            log.warning("PROVIDER_LIMITS_JSON ignored: %s", e)
    return dict(FREE_TIER_DEFAULTS.get(provider, FREE_TIER_DEFAULTS["_default"]))


class TokenBucket:
    """Continuous-refill bucket. Lets callers run right up to the limit, never past it.

    A bucket with rate=500/s and capacity=500 sustains exactly 500 tokens/second:
    each acquire waits only as long as the refill actually needs.
    """

    def __init__(self, rate_per_sec: float, capacity: float | None = None):
        self.rate = max(0.0, float(rate_per_sec))
        self.capacity = float(capacity if capacity is not None else max(rate_per_sec, 1.0))
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        delta = now - self._last
        if delta > 0:
            self._tokens = min(self.capacity, self._tokens + delta * self.rate)
            self._last = now

    async def acquire(self, amount: float = 1.0, timeout_s: float = 300.0) -> float:
        """Block until `amount` is available. Returns seconds waited."""
        if self.rate <= 0:
            return 0.0                      # unlimited
        amount = min(max(amount, 0.0), self.capacity)
        waited = 0.0
        deadline = time.monotonic() + timeout_s
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= amount:
                    self._tokens -= amount
                    return waited
                deficit = amount - self._tokens
                sleep_s = deficit / self.rate
            if time.monotonic() + sleep_s > deadline:
                raise AppError(f"rate limit wait exceeded {timeout_s:.0f}s", 429)
            sleep_s = min(max(sleep_s, 0.005), 5.0)
            await asyncio.sleep(sleep_s)
            waited += sleep_s

    async def give_back(self, amount: float) -> None:
        if self.rate <= 0 or amount <= 0:
            return
        async with self._lock:
            self._refill()
            self._tokens = min(self.capacity, self._tokens + amount)

    def set_rate(self, rate_per_sec: float) -> None:
        self.rate = max(0.0, float(rate_per_sec))
        self.capacity = max(self.capacity, self.rate)

    @property
    def available(self) -> float:
        self._refill()
        return round(self._tokens, 2)


class SlidingWindow:
    """Hard guarantee: no 60s window ever exceeds `limit`.

    A token bucket alone cannot promise this — its burst capacity stacks on top of the
    refill rate, so a 30k/min budget can emit ~37k in the first minute. This keeps
    60 one-second slots and refuses anything that would breach the window total, which
    is what providers actually measure.
    """

    __slots__ = ("limit", "window_s", "_slots", "_base", "_lock")

    def __init__(self, limit: int, window_s: int = 60):
        self.limit = int(limit)
        self.window_s = int(window_s)
        self._slots: deque[tuple[int, float]] = deque()   # (second, amount)
        self._base = 0.0
        self._lock = asyncio.Lock()

    def _evict(self, now: int) -> None:
        cutoff = now - self.window_s
        while self._slots and self._slots[0][0] <= cutoff:
            self._base -= self._slots.popleft()[1]
        if self._base < 0:
            self._base = 0.0

    def _total(self, now: int) -> float:
        self._evict(now)
        return self._base

    async def acquire(self, amount: float, timeout_s: float = 300.0) -> float:
        if self.limit <= 0:
            return 0.0
        amount = min(amount, self.limit)
        waited = 0.0
        deadline = time.monotonic() + timeout_s
        while True:
            async with self._lock:
                now = int(time.monotonic())
                if self._total(now) + amount <= self.limit:
                    if self._slots and self._slots[-1][0] == now:
                        sec, amt = self._slots.pop()
                        self._slots.append((sec, amt + amount))
                    else:
                        self._slots.append((now, amount))
                    self._base += amount
                    return waited
                oldest = self._slots[0][0] if self._slots else now
                sleep_s = max(0.02, (oldest + self.window_s) - time.monotonic() + 0.01)
            if time.monotonic() + sleep_s > deadline:
                raise AppError(f"rate limit wait exceeded {timeout_s:.0f}s", 429)
            sleep_s = min(sleep_s, 2.0)
            await asyncio.sleep(sleep_s)
            waited += sleep_s

    async def give_back(self, amount: float) -> None:
        if self.limit <= 0 or amount <= 0:
            return
        async with self._lock:
            now = int(time.monotonic())
            self._evict(now)
            give = min(amount, self._base)
            self._base -= give
            while give > 0 and self._slots:
                sec, amt = self._slots.pop()
                if amt > give:
                    self._slots.append((sec, amt - give))
                    break
                give -= amt

    @property
    def used(self) -> float:
        return round(self._total(int(time.monotonic())), 2)


class DailyCounter:
    def __init__(self, limit: int):
        self.limit = int(limit)
        self.count = 0
        self.day = time.gmtime().tm_yday

    def _roll(self) -> None:
        d = time.gmtime().tm_yday
        if d != self.day:
            self.day, self.count = d, 0

    def check_and_add(self, n: int = 1) -> None:
        if self.limit <= 0:
            return
        self._roll()
        if self.count + n > self.limit:
            raise AppError("provider daily request quota exhausted", 429)
        self.count += n

    @property
    def remaining(self) -> int:
        if self.limit <= 0:
            return -1
        self._roll()
        return max(0, self.limit - self.count)


class CircuitBreaker:
    def __init__(self, threshold: int = 5, cooldown_s: float = 30.0):
        self.threshold, self.cooldown_s = threshold, cooldown_s
        self.failures = 0
        self.opened_at = 0.0

    @property
    def state(self) -> str:
        if self.failures < self.threshold:
            return "closed"
        if time.monotonic() - self.opened_at > self.cooldown_s:
            return "half_open"
        return "open"

    def check(self) -> None:
        if self.state == "open":
            raise AppError("provider circuit breaker open", 503)

    def record(self, ok: bool) -> None:
        if ok:
            self.failures = 0
        else:
            self.failures += 1
            if self.failures == self.threshold:
                self.opened_at = time.monotonic()


def estimate_tokens(messages: list[dict] | str, max_out: int = 0) -> int:
    """Conservative pre-flight estimate. Deliberately over-estimates rather than under."""
    if isinstance(messages, str):
        chars = len(messages)
    else:
        chars = sum(len(str(m.get("content", ""))) + 8 for m in messages)
    return int(chars / 3.2) + max_out + 16      # 3.2 chars/token errs high for English


class ProviderGate:
    """Everything needed to stay inside one provider's limits and still go flat out."""

    def __init__(self, provider: str, limits: dict | None = None):
        self.provider = provider
        lim = limits or _limits_for(provider)
        self.configured = dict(lim)
        self.rpm, self.tpm, self.rpd = int(lim["rpm"]), int(lim["tpm"]), int(lim["rpd"])
        # pacing buckets hold at most ~1 second of burst; the windows are authoritative
        self.req_bucket = TokenBucket(self.rpm / 60.0, capacity=max(1.0, self.rpm / 60.0))
        self.tok_bucket = TokenBucket(self.tpm / 60.0, capacity=max(1.0, self.tpm / 60.0)) if self.tpm else TokenBucket(0)
        self.req_window = SlidingWindow(self.rpm)
        self.tok_window = SlidingWindow(self.tpm)
        self.daily = DailyCounter(self.rpd)
        self.sem = asyncio.Semaphore(max(1, int(lim["concurrency"])))
        self.breaker = CircuitBreaker()
        self.scale = 1.0                    # adaptive multiplier, shrinks on 429
        self.stats = {"requests": 0, "tokens": 0, "throttled_s": 0.0, "rate_limited": 0, "errors": 0}

    async def acquire(self, est_tokens: int) -> float:
        self.breaker.check()
        self.daily.check_and_add(1)
        waited = await self.req_window.acquire(1.0)
        waited += await self.req_bucket.acquire(1.0)
        if self.tpm:
            waited += await self.tok_window.acquire(est_tokens)
            waited += await self.tok_bucket.acquire(est_tokens)
        self.stats["throttled_s"] = round(self.stats["throttled_s"] + waited, 3)
        return waited

    async def settle(self, est_tokens: int, actual_tokens: int) -> None:
        """Reconcile the estimate against reality so the budget stays accurate."""
        self.stats["requests"] += 1
        self.stats["tokens"] += max(0, actual_tokens)
        if not self.tpm:
            return
        diff = est_tokens - actual_tokens
        if diff > 0:
            await self.tok_window.give_back(diff)       # we over-reserved, hand it back
            await self.tok_bucket.give_back(diff)
        elif diff < 0:
            await self.tok_window.acquire(-diff, timeout_s=60)

    def on_rate_limited(self, retry_after_s: float | None = None) -> float:
        """Provider said 429: shrink our own ceiling and respect Retry-After."""
        self.stats["rate_limited"] += 1
        self.scale = max(0.2, self.scale * 0.7)
        self.req_bucket.set_rate(self.rpm * self.scale / 60.0)
        self.req_window.limit = max(1, int(self.rpm * self.scale))
        if self.tpm:
            self.tok_bucket.set_rate(self.tpm * self.scale / 60.0)
            self.tok_window.limit = max(1, int(self.tpm * self.scale))
        log.warning("provider %s rate-limited; throttling to %.0f%% of configured",
                    self.provider, self.scale * 100)
        return float(retry_after_s) if retry_after_s else min(60.0, 2.0 / self.scale)

    def on_success(self) -> None:
        self.breaker.record(True)
        if self.scale < 1.0:                              # creep back up after recovery
            self.scale = min(1.0, self.scale * 1.05)
            self.req_bucket.set_rate(self.rpm * self.scale / 60.0)
            self.req_window.limit = max(1, int(self.rpm * self.scale))
            if self.tpm:
                self.tok_bucket.set_rate(self.tpm * self.scale / 60.0)
                self.tok_window.limit = max(1, int(self.tpm * self.scale))

    def on_error(self) -> None:
        self.stats["errors"] += 1
        self.breaker.record(False)

    def snapshot(self) -> dict:
        return {
            "provider": self.provider, "configured": self.configured,
            "effective_scale": round(self.scale, 3), "breaker": self.breaker.state,
            "requests_used_60s": self.req_window.used,
            "tokens_used_60s": self.tok_window.used if self.tpm else -1,
            "requests_remaining_60s": max(0.0, self.rpm - self.req_window.used),
            "tokens_remaining_60s": max(0.0, self.tpm - self.tok_window.used) if self.tpm else -1,
            "daily_remaining": self.daily.remaining, **self.stats,
        }


GATES: dict[str, ProviderGate] = {}


def gate_for(provider: str) -> ProviderGate:
    p = (provider or "_default").lower()
    if p not in GATES:
        GATES[p] = ProviderGate(p)
    return GATES[p]


class UserQuota:
    """Per-user ceilings so one tenant cannot drain a shared free tier."""

    def __init__(self, tokens_per_day: int, requests_per_min: int):
        self.tokens_per_day = tokens_per_day
        self.req_bucket = TokenBucket(requests_per_min / 60.0, capacity=max(1.0, requests_per_min / 4.0))
        self.daily_tokens = 0
        self.day = time.gmtime().tm_yday

    async def acquire(self, est_tokens: int) -> None:
        d = time.gmtime().tm_yday
        if d != self.day:
            self.day, self.daily_tokens = d, 0
        if self.tokens_per_day and self.daily_tokens + est_tokens > self.tokens_per_day:
            raise AppError("daily token quota exhausted for this user", 429)
        await self.req_bucket.acquire(1.0)
        self.daily_tokens += est_tokens


USER_QUOTAS: dict[str, UserQuota] = {}


def quota_for(user_id: str) -> UserQuota:
    if user_id not in USER_QUOTAS:
        USER_QUOTAS[user_id] = UserQuota(
            int(_env("USER_TOKENS_PER_DAY", "0")),
            int(_env("USER_REQUESTS_PER_MIN", "120")))
    return USER_QUOTAS[user_id]


# =====================================================================================
# 4. SECRETS — BYOK encryption at rest (Fernet). Plaintext never stored/logged/returned.
# =====================================================================================
_FERNET: Fernet | None = None


def _fernet() -> Fernet:
    global _FERNET
    if _FERNET is None:
        key = S.SECRETS_MASTER_KEY
        if not key:
            key = base64.urlsafe_b64encode(hashlib.sha256(b"maximus-local-dev-only").digest()).decode()
        _FERNET = Fernet(key.encode())
    return _FERNET


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as e:
        raise ValueError("cannot decrypt secret (wrong SECRETS_MASTER_KEY?)") from e


def fingerprint(secret: str) -> str:
    return f"…{hashlib.sha256(secret.encode()).hexdigest()[-4:]}"

# =====================================================================================
# 5. SECURITY — passwords (pbkdf2, bcrypt-compat verify) + JWT
# =====================================================================================
try:
    from passlib.context import CryptContext as _CryptContext  # type: ignore
    _pwd_ctx = _CryptContext(schemes=["bcrypt"], deprecated="auto")
except Exception:
    _pwd_ctx = None  # type: ignore


def hash_password(pw: str) -> str:
    iters = 200_000
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters)
    return f"pbkdf2${iters}${base64.b64encode(salt).decode()}${base64.b64encode(h).decode()}"


def verify_password(plain: str, hashed: str) -> bool:
    try:
        if hashed.startswith("pbkdf2$"):
            _, iters, salt_b, hash_b = hashed.split("$")
            h = hashlib.pbkdf2_hmac("sha256", plain.encode(), base64.b64decode(salt_b), int(iters))
            return hmac_compare(h, base64.b64decode(hash_b))
        if _pwd_ctx is not None:  # legacy bcrypt hashes from older versions
            return bool(_pwd_ctx.verify(plain, hashed))
        return False
    except Exception:
        return False


def hmac_compare(a: bytes, b: bytes) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(a, b)


def _encode(payload: dict, expires: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload.update({"iat": now, "exp": now + expires})
    return jwt.encode(payload, S.SECRET_KEY, algorithm=S.JWT_ALGORITHM)


def create_access_token(user_id: str) -> str:
    return _encode({"sub": user_id, "type": "access"}, timedelta(minutes=S.JWT_ACCESS_MINUTES))


def create_refresh_token(user_id: str) -> str:
    return _encode({"sub": user_id, "type": "refresh"}, timedelta(days=S.JWT_REFRESH_DAYS))


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, S.SECRET_KEY, algorithms=[S.JWT_ALGORITHM])
    except JWTError as e:
        raise ValueError(f"invalid token: {e}") from e

# =====================================================================================
# 6. DATABASE — async SQLite (single file). Same 18-table shape as the production plan.
# =====================================================================================
_engine = None
_Session: async_sessionmaker[AsyncSession] | None = None


def _tune_sqlite(engine) -> None:
    """WAL + NORMAL sync + a real busy timeout. Without these, concurrent agent writes
    serialise on the default rollback journal and throw 'database is locked'."""
    from sqlalchemy import event as _event

    @_event.listens_for(engine.sync_engine, "connect")
    def _set_pragmas(dbapi_conn, _rec):  # pragma: no cover - driver level
        try:
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA busy_timeout=10000")
            cur.execute("PRAGMA temp_store=MEMORY")
            cur.execute("PRAGMA cache_size=-32000")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
        except Exception as e:
            log.debug("sqlite pragma setup skipped: %s", e)


def get_engine():
    global _engine, _Session
    if _engine is None:
        url = S.DATABASE_URL
        if url.startswith("sqlite+aiosqlite://"):
            f = url.split("sqlite+aiosqlite://", 1)[1].split("?")[0]
            # SQLAlchemy uses /C:/... in Windows SQLite URLs; pathlib needs C:/...
            # without the leading slash when creating the parent directory.
            if sys.platform == "win32" and re.match(r"^/[A-Za-z]:[\\\\/]", f):
                f = f[1:]
            Path(f).parent.mkdir(parents=True, exist_ok=True)
        if url.startswith("sqlite"):
            _engine = create_async_engine(url, echo=False, future=True,
                                          pool_pre_ping=True, connect_args={"timeout": 30})
            _tune_sqlite(_engine)
        else:
            _engine = create_async_engine(
                url, echo=False, future=True, pool_pre_ping=True,
                pool_size=int(_env("DB_POOL_SIZE", "20")),
                max_overflow=int(_env("DB_MAX_OVERFLOW", "10")),
                pool_recycle=1800)
        _Session = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)
    return _engine


def session_factory() -> async_sessionmaker[AsyncSession]:
    get_engine()
    assert _Session is not None
    return _Session


class Base(DeclarativeBase):
    pass


def _uid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32), default="user")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    goals: Mapped[str] = mapped_column(Text, default="")
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    agent_config: Mapped[dict] = mapped_column(JSON, default=dict)
    mcp_config: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Provider(Base):
    __tablename__ = "providers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128))
    base_url: Mapped[str] = mapped_column(String(512), default="")
    openai_compatible: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(32), default="unknown")


class Model(Base):
    __tablename__ = "models"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    provider_id: Mapped[str] = mapped_column(String(36), ForeignKey("providers.id"), index=True)
    model_id: Mapped[str] = mapped_column(String(256), index=True)
    capability_tags: Mapped[list] = mapped_column(JSON, default=list)
    context_window: Mapped[int] = mapped_column(Integer, default=128000)
    cost_in_per_1k: Mapped[float] = mapped_column(Float, default=0.0)
    cost_out_per_1k: Mapped[float] = mapped_column(Float, default=0.0)
    tier: Mapped[str] = mapped_column(String(32), default="standard")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class ProviderKey(Base):
    __tablename__ = "provider_keys"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    project_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("projects.id"), nullable=True, index=True)
    provider_id: Mapped[str] = mapped_column(String(36), ForeignKey("providers.id"), index=True)
    encrypted_blob: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(32))
    is_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    slug: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    tools: Mapped[list] = mapped_column(JSON, default=list)
    model_requirements: Mapped[dict] = mapped_column(JSON, default=dict)
    cost_level: Mapped[str] = mapped_column(String(32), default="low")
    risk_level: Mapped[str] = mapped_column(String(32), default="low")
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    system_prompt: Mapped[str] = mapped_column(Text, default="")
    verification_strategy: Mapped[str] = mapped_column(String(64), default="quality")
    version: Mapped[str] = mapped_column(String(32), default="1.0")
    performance_score: Mapped[float] = mapped_column(Float, default=0.5)


class Task(Base):
    __tablename__ = "tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    goal: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    priority: Mapped[str] = mapped_column(String(16), default="default")
    budget_tokens: Mapped[int] = mapped_column(Integer, default=120000)
    budget_usd: Mapped[float] = mapped_column(Float, default=5.0)
    dag: Mapped[dict] = mapped_column(JSON, default=dict)
    checkpoint: Mapped[dict] = mapped_column(JSON, default=dict)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class TaskDependency(Base):
    __tablename__ = "task_dependencies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    task_id: Mapped[str] = mapped_column(String(36), ForeignKey("tasks.id"), index=True)
    depends_on_id: Mapped[str] = mapped_column(String(36), ForeignKey("tasks.id"), index=True)


class AgentRun(Base):
    __tablename__ = "agent_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    task_id: Mapped[str] = mapped_column(String(36), ForeignKey("tasks.id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), index=True)
    model_used: Mapped[str] = mapped_column(String(256), default="")
    tokens_in: Mapped[int] = mapped_column(Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    output_json: Mapped[dict] = mapped_column(JSON, default=dict)
    verification_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class TaskEvent(Base):
    __tablename__ = "task_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    task_id: Mapped[str] = mapped_column(String(36), ForeignKey("tasks.id"), index=True)
    run_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("agent_runs.id"), nullable=True)
    type: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ToolDefinition(Base):
    __tablename__ = "tool_definitions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    slug: Mapped[str] = mapped_column(String(128), unique=True)
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    schema_json: Mapped[dict] = mapped_column(JSON, default=dict)
    mcp_server_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("mcp_servers.id"), nullable=True)


class MCPServer(Base):
    __tablename__ = "mcp_servers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    project_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("projects.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    transport: Mapped[str] = mapped_column(String(32), default="stdio")
    url_or_cmd: Mapped[str] = mapped_column(String(1024), default="")
    allowed_scopes: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Memory(Base):
    __tablename__ = "memories"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    project_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("projects.id"), nullable=True, index=True)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    task_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("tasks.id"), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("agents.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(32), default="semantic", index=True)
    content: Mapped[str] = mapped_column(Text)
    embedding: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Artifact(Base):
    __tablename__ = "artifacts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), index=True)
    task_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("tasks.id"), nullable=True)
    run_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("agent_runs.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(64), default="file")
    uri: Mapped[str] = mapped_column(String(1024))
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class SandboxRow(Base):
    __tablename__ = "sandboxes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    project_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("projects.id"), nullable=True)
    task_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("tasks.id"), nullable=True)
    adapter: Mapped[str] = mapped_column(String(32), default="local")
    status: Mapped[str] = mapped_column(String(32), default="created")
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Evaluation(Base):
    __tablename__ = "evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    task_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("tasks.id"), nullable=True)
    run_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("agent_runs.id"), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("agents.id"), nullable=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    dimensions: Mapped[dict] = mapped_column(JSON, default=dict)
    feedback: Mapped[str] = mapped_column(Text, default="")


class Usage(Base):
    __tablename__ = "usage"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    project_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("projects.id"), nullable=True)
    provider_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("providers.id"), nullable=True)
    model: Mapped[str] = mapped_column(String(256), default="")
    tokens_in: Mapped[int] = mapped_column(Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    task_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("tasks.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uid)
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    project_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(128))
    resource: Mapped[str] = mapped_column(String(256), default="")
    result: Mapped[str] = mapped_column(String(32), default="ok")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


async def init_db() -> None:
    eng = get_engine()
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        try:
            await conn.exec_driver_sql("PRAGMA journal_mode=WAL;")
        except Exception:
            pass

# =====================================================================================
# 7. SCHEMAS (Pydantic request/response)
# =====================================================================================
class RegisterIn(BaseModel):
    email: str
    password: str = Field(min_length=8)


class LoginIn(BaseModel):
    email: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class ProjectIn(BaseModel):
    name: str
    goals: str = ""
    settings: dict = {}


class TaskCreate(BaseModel):
    project_id: str
    goal: str
    priority: str = "default"
    budget_tokens: int = 120000
    budget_usd: float = 5.0
    idempotency_key: str | None = None


class KeyCreate(BaseModel):
    provider_slug: str
    api_key: str
    project_id: str | None = None


class ChatIn(BaseModel):
    mode: str = "auto"                       # auto | chat | task
    history: list[dict] = []
    project_id: str
    message: str
    model: str | None = None                 # explicit model id from the UI's model picker
    provider: str | None = None              # provider slug that model belongs to, e.g. "openai"


class MemoryStore(BaseModel):
    project_id: str | None = None
    task_id: str | None = None
    kind: str = "semantic"
    content: str


class MCPServerIn(BaseModel):
    name: str
    transport: str = "stdio"
    url_or_cmd: str = ""
    allowed_scopes: list[str] = []
    project_id: str | None = None


class SandboxExec(BaseModel):
    sandbox_id: str
    language: str = "python"
    code: str = ""
    command: str = ""
    approve_generated_code: bool = False


class AgentMessage(BaseModel):
    kind: str
    from_agent: str
    to_agent: str | None = None
    payload: dict[str, Any] = {}

# =====================================================================================
# 8. AGENTS — interface + inline registry (scales to 400+; add dicts, no new services)
# =====================================================================================
class AgentDefinition(BaseModel):
    id: str
    name: str
    domain: str = "general"
    description: str = ""
    capabilities: list[str] = []
    tools: list[str] = []
    model_requirements: dict = {}
    cost_level: str = "low"
    risk_level: str = "low"
    permissions: list[str] = []
    system_instructions: str = ""
    verification_strategy: str = "quality"
    human_gate: bool = False
    version: str = "1.0"


@dataclass
class AgentContext:
    goal: str
    project_id: str
    task_id: str
    node_id: str = "root"
    memory_snippets: list[str] = field(default_factory=list)
    upstream: dict = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    budget_tokens: int = 120000
    budget_usd: float = 5.0


@dataclass
class AgentResult:
    status: str
    structured_output: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    usage_tokens: int = 0
    usage_usd: float = 0.0


AGENT_DEFS: list[dict] = [
    dict(id="goal_analyzer", name="Goal Analyzer", description="Breaks vague goals into scope, constraints, deliverables.",
         capabilities=["planning", "requirements", "analysis"], tools=[], model_requirements={"capability": "reasoning"},
         cost_level="low", risk_level="low", permissions=["delegate"],
         system_instructions="You are the Goal Analyzer. Turn the user goal into scope, constraints, deliverables and acceptance criteria as structured JSON.",
         verification_strategy="quality"),
    dict(id="requirements", name="Requirements Agent", description="Writes functional/non-functional requirements.",
         capabilities=["requirements", "planning", "documentation"], tools=["filesystem"], model_requirements={"capability": "reasoning"},
         cost_level="low", risk_level="low", permissions=["fs:read", "fs:write"],
         system_instructions="You write crisp requirements: user stories, API surface, data model, NFRs.", verification_strategy="quality"),
    dict(id="architecture", name="Architecture Agent", description="Designs system architecture and service boundaries.",
         capabilities=["architecture", "planning", "backend"], tools=["filesystem"], model_requirements={"capability": "reasoning"},
         cost_level="medium", risk_level="low", permissions=["delegate", "fs:read"],
         system_instructions="You design modular architectures with components, data flow, and tradeoffs.", verification_strategy="quality"),
    dict(id="researcher", name="Researcher", description="Web/docs research with cited findings.",
         capabilities=["research", "analysis", "web"], tools=["fetch"], model_requirements={"capability": "general"},
         cost_level="low", risk_level="low", permissions=["net:fetch"],
         system_instructions="You research with citations. Flag uncertainty. No absolute claims without sources.", verification_strategy="factual"),
    dict(id="analyst", name="Analyst", description="Synthesizes research into decisions.",
         capabilities=["analysis", "reasoning", "documentation"], tools=[], model_requirements={"capability": "reasoning"},
         cost_level="low", risk_level="low", permissions=[],
         system_instructions="You synthesize options into decision tables and recommendations.", verification_strategy="factual"),
    dict(id="ui", name="UI Agent", description="Designs UX flows and component specs.",
         capabilities=["ui", "design", "frontend"], tools=["filesystem"], model_requirements={"capability": "general"},
         cost_level="low", risk_level="low", permissions=["fs:read"],
         system_instructions="You produce UX flows, wireframe descriptions and component props.", verification_strategy="quality"),
    dict(id="frontend", name="Frontend Agent", description="Builds frontend code and components.",
         capabilities=["frontend", "code", "ui"], tools=["filesystem"], model_requirements={"capability": "code"},
         cost_level="medium", risk_level="medium", permissions=["fs:read", "fs:write"],
         system_instructions="You write clean frontend code with types and tests in mind.", verification_strategy="code"),
    dict(id="backend", name="Backend Agent", description="Builds APIs, workers, integrations.",
         capabilities=["backend", "code", "api"], tools=["filesystem", "sqlite"], model_requirements={"capability": "code"},
         cost_level="medium", risk_level="medium", permissions=["fs:read", "fs:write", "db:query"],
         system_instructions="You write production backend code with schemas and error handling.", verification_strategy="code"),
    dict(id="database", name="Database Agent", description="Designs schemas and migrations.",
         capabilities=["database", "backend", "schema"], tools=["sqlite", "filesystem"], model_requirements={"capability": "code"},
         cost_level="low", risk_level="medium", permissions=["db:query", "fs:read"],
         system_instructions="You design normalized schemas, indexes and migrations.", verification_strategy="code"),
    dict(id="ai_integrator", name="AI Integrator", description="Wires LLM/agent capabilities into the app.",
         capabilities=["ai", "backend", "code"], tools=["filesystem"], model_requirements={"capability": "code"},
         cost_level="medium", risk_level="medium", permissions=["fs:read", "fs:write"],
         system_instructions="You integrate model calls with budgets, retries and fallbacks.", verification_strategy="code"),
    dict(id="security", name="Security Agent", description="Threat-models outputs, enforces guardrails.",
         capabilities=["security", "review", "backend"], tools=["filesystem"], model_requirements={"capability": "reasoning"},
         cost_level="medium", risk_level="low", permissions=["fs:read"],
         system_instructions="You audit for secrets, injection, SSRF, auth gaps. Output findings + fixes.", verification_strategy="security"),
    dict(id="testing", name="Testing Agent", description="Writes and runs tests.",
         capabilities=["testing", "code", "qa"], tools=["filesystem"], model_requirements={"capability": "code"},
         cost_level="low", risk_level="low", permissions=["fs:read", "fs:write"],
         system_instructions="You write pytest tests and report pass/fail with reproduction steps.", verification_strategy="tests"),
    dict(id="devops", name="DevOps Agent", description="Packaging, Docker, CI and deploy configs.",
         capabilities=["devops", "deploy", "backend"], tools=["filesystem"], model_requirements={"capability": "code"},
         cost_level="low", risk_level="medium", permissions=["fs:read", "fs:write"],
         system_instructions="You produce Dockerfiles, compose files and health checks.", verification_strategy="completion"),
    dict(id="deployment", name="Deployment Agent", description="Release checklists (approval-gated).",
         capabilities=["deploy", "devops", "release"], tools=["filesystem"], model_requirements={"capability": "general"},
         cost_level="low", risk_level="high", permissions=["fs:read"],
         system_instructions="You produce safe rollout/rollback plans. Never execute deploys without approval.", verification_strategy="completion"),
    dict(id="critic", name="Critic", description="Judge agent; rejects weak outputs, triggers repair.",
         capabilities=["review", "qa", "reasoning"], tools=[], model_requirements={"capability": "reasoning"},
         cost_level="medium", risk_level="low", permissions=["delegate"],
         system_instructions="You are a strict critic. Reject vague/insecure/incomplete outputs with specific repair instructions.",
         verification_strategy="quality"),
    dict(id="final_verifier", name="Final Verifier", description="Task-completion verification vs acceptance criteria.",
         capabilities=["qa", "verification", "review"], tools=[], model_requirements={"capability": "reasoning"},
         cost_level="low", risk_level="low", permissions=[],
         system_instructions="You verify all acceptance criteria are met and summarize what was delivered.", verification_strategy="completion"),
]

# ---- Catalogue loader: 400+ agents live in agents.json, not in code ----
AGENT_CATALOGUE_PATH = Path(_env("AGENT_CATALOGUE", str(BASE_DIR / "agents.json")))

REGISTRY: dict[str, AgentDefinition] = {}
ALIASES: dict[str, str] = {}
CAP_INDEX: dict[str, set[str]] = defaultdict(set)      # capability -> agent ids
DOMAIN_INDEX: dict[str, set[str]] = defaultdict(set)   # domain -> agent ids
TOKEN_INDEX: dict[str, set[str]] = defaultdict(set)    # word -> agent ids
AGENT_TOKENS: dict[str, set[str]] = {}                 # agent id -> its own words


def _index_agent(d: AgentDefinition) -> None:
    for c in d.capabilities:
        CAP_INDEX[c.lower()].add(d.id)
    DOMAIN_INDEX[d.domain.lower()].add(d.id)
    words = re.findall(r"[a-z0-9]+", f"{d.id} {d.name} {d.domain} {' '.join(d.capabilities)}".lower())
    keep = {w for w in words if len(w) > 2}
    AGENT_TOKENS[d.id] = keep
    for w in keep:
        TOKEN_INDEX[w].add(d.id)


def load_catalogue(path: Path | None = None) -> int:
    """Load agent definitions from disk. Falls back to the built-in core set."""
    global ALIASES
    REGISTRY.clear(); CAP_INDEX.clear(); DOMAIN_INDEX.clear(); TOKEN_INDEX.clear(); AGENT_TOKENS.clear()
    ALIASES = {}
    p = path or AGENT_CATALOGUE_PATH
    loaded = 0
    if p.exists():
        try:
            raw = json.loads(p.read_text())
            for rec in raw.get("agents", []):
                try:
                    d = AgentDefinition(**rec)
                except Exception as e:
                    log.warning("skipping malformed agent %s: %s", rec.get("id"), e)
                    continue
                REGISTRY[d.id] = d
                _index_agent(d)
                loaded += 1
            ALIASES = {k: v for k, v in raw.get("aliases", {}).items() if v in REGISTRY}
        except Exception as e:
            log.error("agent catalogue %s unreadable: %s", p, e)
    # built-in core agents always present (as fallbacks / short ids)
    for rec in AGENT_DEFS:
        if rec["id"] in ALIASES:
            continue
        if rec["id"] not in REGISTRY:
            d = AgentDefinition(**rec)
            REGISTRY[d.id] = d
            _index_agent(d)
            loaded += 1
    return loaded


def resolve_agent(agent_id: str) -> AgentDefinition | None:
    """Resolve a short id, alias or full id to a definition."""
    if agent_id in REGISTRY:
        return REGISTRY[agent_id]
    target = ALIASES.get(agent_id)
    if target and target in REGISTRY:
        return REGISTRY[target]
    return None


load_catalogue()


def registry_search(q: str, limit: int = 100) -> list[AgentDefinition]:
    """Index-backed search so 480 agents stay cheap to query."""
    q = (q or "").lower().strip()
    if not q:
        return list(REGISTRY.values())[:limit]
    words = [w for w in re.findall(r"[a-z0-9]+", q) if len(w) > 2]
    hits: dict[str, int] = defaultdict(int)
    for w in words:
        for aid in TOKEN_INDEX.get(w, ()):
            hits[aid] += 2
        for token, ids in TOKEN_INDEX.items():   # prefix match
            if token.startswith(w) and token != w:
                for aid in ids:
                    hits[aid] += 1
    if not hits:
        return [d for d in REGISTRY.values() if q in d.id or q in d.name.lower()][:limit]
    ranked = sorted(hits.items(), key=lambda kv: -kv[1])[:limit]
    return [REGISTRY[a] for a, _ in ranked if a in REGISTRY]


# =====================================================================================
# 6b. Deliberation engine — structured multi-pass reasoning
# =====================================================================================
# Depth is a dial, not a constant: trivial nodes get one pass, hard ones get the full
# understand -> plan -> draft -> critique -> revise cycle. Only safe phase summaries are
# streamed; the model's internal reasoning is never emitted to clients or logs.
THINK_DEPTH = int(_env("THINK_DEPTH", "3"))          # 0=single pass .. 4=full deliberation
THINK_MAX_DEPTH = 4


class Phase(str, Enum):
    UNDERSTAND = "UNDERSTAND"
    PLAN = "PLAN"
    TOOL_CALL = "TOOL_CALL"
    OBSERVE = "OBSERVE"
    ACT = "ACT"
    CRITIQUE = "CRITIQUE"
    REVISE = "REVISE"
    VERIFY = "VERIFY"
    COMPLETE = "COMPLETE"


PHASE_SUMMARY = {
    Phase.UNDERSTAND: "reading the goal and pinning down assumptions",
    Phase.PLAN: "choosing an approach",
    Phase.TOOL_CALL: "calling tools",
    Phase.OBSERVE: "reading tool results",
    Phase.ACT: "producing the deliverable",
    Phase.CRITIQUE: "checking its own work for gaps",
    Phase.REVISE: "applying fixes it found",
    Phase.VERIFY: "verifying against acceptance criteria",
    Phase.COMPLETE: "done",
}

UNDERSTAND_PROMPT = """Before answering, establish the ground truth of this task.
Return STRICT JSON only:
{"restated_goal": "...", "deliverable": "what concretely must exist when done",
 "assumptions": ["..."], "unknowns": ["things you cannot determine from the input"],
 "acceptance_criteria": ["checkable conditions"], "risks": ["..."]}"""

PLAN_PROMPT = """Given your understanding, choose an approach.
Return STRICT JSON only:
{"approach": "one paragraph", "steps": ["ordered steps"],
 "rejected_alternatives": [{"option": "...", "why_not": "..."}],
 "needs_tools": ["tool names or empty"],
 "subtasks": [{"agent": "agent id or capability", "description": "work you cannot do yourself"}]}

Only list subtasks for work that genuinely belongs to a different specialist. An empty
list is the normal and correct answer."""

CRITIQUE_PROMPT = """You are reviewing the draft below as a hostile expert reviewer.
Find real problems, not stylistic nitpicks. If the draft is genuinely sound, say so.
Return STRICT JSON only:
{"verdict": "accept" | "revise", "severity": "none"|"minor"|"major",
 "issues": [{"problem": "...", "why_it_matters": "...", "fix": "concrete instruction"}],
 "missing": ["anything the acceptance criteria require but the draft lacks"]}"""

REVISE_PROMPT = """Rewrite the deliverable so every issue below is fixed.
Output ONLY the corrected deliverable. Do not describe the changes, do not apologise."""


def _safe_json(text: str) -> dict | None:
    """Models wrap JSON in prose and fences. Recover it without trusting the format."""
    if not text:
        return None
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.MULTILINE).strip()
    try:
        v = json.loads(t)
        return v if isinstance(v, dict) else None
    except Exception:
        pass
    depth, start = 0, -1
    for i, ch in enumerate(t):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    v = json.loads(t[start:i + 1])
                    if isinstance(v, dict):
                        return v
                except Exception:
                    start = -1
    return None


def depth_for(node: dict, defn: AgentDefinition) -> int:
    """Hard, risky or verification work earns more passes. Cheap lookups do not."""
    d = THINK_DEPTH
    if defn.risk_level == "high" or defn.verification_strategy in ("security", "code", "tests"):
        d += 1
    if defn.cost_level == "low" and defn.risk_level == "low":
        d -= 1
    if node.get("attempts", 0) > 1:
        d += 1                                  # a retry means the first attempt was wrong
    c = float(node.get("complexity", 0.0) or 0.0)
    if c >= 0.35:
        d += 1                                  # hard goals earn a critique pass
    elif c <= 0.08 and defn.risk_level == "low":
        d -= 1                                  # trivial goals do not need five calls
    return max(0, min(THINK_MAX_DEPTH, d))


class GenericAgent:
    """One runtime class driven by a definition. No per-agent services, 480 behaviours."""

    def __init__(self, definition: AgentDefinition):
        self.definition = definition

    def _system(self) -> str:
        return (self.definition.system_instructions
                or f"You are {self.definition.name}. {self.definition.description}")

    async def _call(self, deps, messages: list[dict], cap: str, max_tokens: int,
                    ctx: AgentContext, label: str) -> tuple[str, int, float, str]:
        """One model call. Returns (text, tokens, usd, model)."""
        resp = await deps.omni.complete(messages, capability=cap, max_tokens=max_tokens,
                                        timeout_s=int(_env("AGENT_CALL_TIMEOUT_S", "45")),
                                        provider_key=deps.provider_key, provider=deps.provider_slug,
                                        cache_key_extra=f"{self.definition.id}:{label}:{deps.provider_slug or 'gateway'}")
        text = (resp.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
        usage = resp.get("usage") or {}
        tokens = int(usage.get("total_tokens") or (len(text) // 4) + 1)
        return text, tokens, float(resp.get("_cost_usd", 0.0)), str(resp.get("model", ""))

    async def run(self, ctx: AgentContext, deps, node: dict | None = None,
                  emit_phase=None) -> AgentResult:
        node = node or {}
        depth = depth_for(node, self.definition)
        cap = (self.definition.model_requirements or {}).get("capability", "general")
        system = self._system()
        mem = "\n".join(ctx.memory_snippets[:5])
        upstream = json.dumps(ctx.upstream, ensure_ascii=False)[:4000] if getattr(ctx, "upstream", None) else ""
        base_user = (f"GOAL\n{ctx.goal}\n\n"
                     + (f"CONTEXT FROM MEMORY\n{mem}\n\n" if mem else "")
                     + (f"STRUCTURED INPUT FROM UPSTREAM AGENTS\n{upstream}\n\n" if upstream else ""))

        tokens = 0
        cost = 0.0
        model_used = ""
        understanding: dict = {}
        plan: dict = {}
        critique: dict = {}
        offline_reason = ""

        async def phase(p: Phase) -> None:
            if emit_phase:
                await emit_phase(p.value, PHASE_SUMMARY[p])

        try:
            # --- 1. UNDERSTAND -------------------------------------------------
            if depth >= 2:
                await phase(Phase.UNDERSTAND)
                txt, t, c, m = await self._call(
                    deps, build_messages(system, base_user + UNDERSTAND_PROMPT), cap, 700, ctx, "understand")
                tokens += t; cost += c; model_used = m or model_used
                understanding = _safe_json(txt) or {"restated_goal": ctx.goal}

            # --- 2. PLAN -------------------------------------------------------
            if depth >= 3:
                await phase(Phase.PLAN)
                ptxt, t, c, m = await self._call(
                    deps, build_messages(system, base_user
                                         + f"YOUR UNDERSTANDING\n{json.dumps(understanding)[:2000]}\n\n"
                                         + PLAN_PROMPT), cap, 700, ctx, "plan")
                tokens += t; cost += c; model_used = m or model_used
                plan = _safe_json(ptxt) or {}

            # --- 3. ACT --------------------------------------------------------
            await phase(Phase.ACT)
            act_user = base_user
            if understanding:
                act_user += f"AGREED UNDERSTANDING\n{json.dumps(understanding)[:2000]}\n\n"
            if plan:
                act_user += f"AGREED APPROACH\n{json.dumps(plan)[:2000]}\n\n"
            act_user += ("Produce the deliverable itself now. Be concrete and complete. "
                         "State any assumption you had to make inline, and mark anything "
                         "you could not verify as an explicit open question.")
            draft, t, c, m = await self._call(
                deps, build_messages(system, act_user), cap,
                int(_env("AGENT_MAX_OUTPUT_TOKENS", "2400")), ctx, "act")
            tokens += t; cost += c; model_used = m or model_used

            # --- 4. CRITIQUE + REVISE ------------------------------------------
            if depth >= 4 and draft.strip():
                await phase(Phase.CRITIQUE)
                crit_user = (f"ACCEPTANCE CRITERIA\n"
                             f"{json.dumps(understanding.get('acceptance_criteria', []))}\n\n"
                             f"DRAFT\n{draft[:6000]}\n\n{CRITIQUE_PROMPT}")
                ctxt, t, c, _ = await self._call(
                    deps, build_messages(system, crit_user), "reasoning", 800, ctx, "critique")
                tokens += t; cost += c
                critique = _safe_json(ctxt) or {}
                if critique.get("verdict") == "revise" and critique.get("issues"):
                    await phase(Phase.REVISE)
                    rev_user = (f"ISSUES TO FIX\n{json.dumps(critique['issues'])[:3000]}\n\n"
                                f"MISSING\n{json.dumps(critique.get('missing', []))[:1000]}\n\n"
                                f"CURRENT DRAFT\n{draft[:6000]}\n\n{REVISE_PROMPT}")
                    revised, t, c, _ = await self._call(
                        deps, build_messages(system, rev_user), cap,
                        int(_env("AGENT_MAX_OUTPUT_TOKENS", "2400")), ctx, "revise")
                    tokens += t; cost += c
                    if revised.strip():
                        draft = revised

        except Exception as e:
            # Offline / provider down: deterministic local output so the DAG still completes.
            offline_reason = redact(str(e))[:160]
            draft = self._offline_draft(ctx, understanding, plan)
            tokens = tokens or max(1, len(draft) // 4)

        await phase(Phase.COMPLETE)
        return AgentResult(
            status="completed",
            structured_output={
                "agent": self.definition.id, "domain": self.definition.domain,
                "node": ctx.node_id, "deliverable": draft,
                "understanding": understanding, "plan": plan,
                "self_review": {"verdict": critique.get("verdict"),
                                "severity": critique.get("severity"),
                                "issues_found": len(critique.get("issues", []))} if critique else {},
                "think_depth": depth, "model": model_used,
                "offline": bool(offline_reason), "offline_reason": offline_reason,
            },
            summary=draft[:4000], usage_tokens=tokens, usage_usd=cost)

    def _offline_draft(self, ctx: AgentContext, understanding: dict, plan: dict) -> str:
        d = self.definition
        return (f"[{d.id} | offline deterministic output]\n"
                f"Role: {d.name} ({d.domain}) — {d.description}\n"
                f"Goal slice: {ctx.goal[:300]}\n"
                f"Planned contribution: {', '.join(d.capabilities[:5])}\n"
                f"Verification strategy: {d.verification_strategy}\n"
                f"NOTE: no model gateway reachable, so this is a structural placeholder, "
                f"not real work product.")


# ---- Router: goal -> {agents, order, tools, model class, concurrency, budget, verification} ----
COST_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass
class RouteStep:
    node_id: str
    agent_id: str
    depends_on: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    capability: str = "general"
    verification: str = "quality"


@dataclass
class RoutePlan:
    steps: list[RouteStep]
    concurrency: int = 4
    budget_tokens: int = 120000
    budget_usd: float = 5.0
    complexity: float = 0.0


# Universal long-horizon lifecycle. Works for software, research, legal, finance,
# science, marketing — the phases are field-agnostic; the agents inside them are not.
PHASES = ["analyze", "research", "design", "implement", "verify", "deliver", "synthesize"]

DOMAIN_PHASES: dict[str, set[str]] = {
    "product_management": {"analyze", "design"},
    "orchestration": {"analyze", "synthesize"},
    "research": {"research"},
    "data_science": {"research", "verify"},
    "analytics": {"research", "verify"},
    "scientific_computing": {"research", "implement"},
    "bioinformatics": {"research", "implement"},
    "healthcare": {"research", "implement"},
    "legal": {"research", "verify"},
    "finance": {"research", "implement"},
    "accounting": {"implement", "verify"},
    "software_architecture": {"design"},
    "ux_design": {"design"},
    "api_design": {"design"},
    "database": {"design", "implement"},
    "backend_engineering": {"implement"},
    "frontend_engineering": {"implement"},
    "mobile_engineering": {"implement"},
    "game_development": {"implement"},
    "embedded_systems": {"implement"},
    "data_engineering": {"implement"},
    "machine_learning": {"implement"},
    "blockchain": {"implement"},
    "creative_writing": {"implement"},
    "media_production": {"implement"},
    "marketing": {"implement"},
    "sales": {"implement"},
    "education": {"implement"},
    "localization": {"implement"},
    "operations": {"implement"},
    "human_resources": {"implement"},
    "customer_support": {"implement"},
    "technical_writing": {"implement", "deliver"},
    "quality_assurance": {"verify"},
    "security": {"verify"},
    "privacy_compliance": {"verify"},
    "devops": {"deliver"},
    "mlops": {"deliver"},
    "cloud_infrastructure": {"deliver"},
    "site_reliability": {"deliver"},
}

# Signals that a phase is actually wanted for this goal.
PHASE_SIGNALS: dict[str, tuple[str, ...]] = {
    "research": ("research", "investigate", "survey", "compare", "evaluate", "study", "find",
                 "analyse", "analyze", "review", "benchmark", "literature", "market", "explore"),
    "design": ("design", "architect", "plan", "structure", "schema", "model", "spec", "blueprint",
               "wireframe", "layout", "strategy"),
    "implement": ("build", "implement", "write", "create", "code", "develop", "make", "generate",
                  "produce", "draft", "refactor", "migrate", "automate", "fix"),
    "verify": ("test", "verify", "validate", "audit", "review", "check", "secure", "qa",
               "compliance", "correct", "prove"),
    "deliver": ("deploy", "ship", "release", "launch", "publish", "document", "handover",
                "rollout", "package", "distribute"),
}

COMPLEXITY_WORDS = ("production", "end-to-end", "complete", "full", "comprehensive", "entire",
                    "scalable", "enterprise", "multi", "long-term", "roadmap", "platform", "system")


STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "our", "your", "you", "are",
    "was", "has", "have", "can", "will", "would", "should", "make", "made", "get", "got", "any",
    "all", "some", "more", "most", "very", "just", "like", "also", "but", "not", "its", "their",
    "them", "they", "his", "her", "who", "what", "when", "where", "how", "why", "which", "there",
    "then", "than", "about", "over", "under", "out", "off", "one", "two", "new", "old", "own",
    "use", "using", "used", "need", "want", "please", "help", "give", "let", "set", "put",
}

# Domain lexicons: what a goal has to sound like for a domain to be in play.
DOMAIN_KEYWORDS: dict[str, tuple[str, ...]] = {
    "software_architecture": ("architecture", "architect", "system design", "microservice", "monolith", "scalable", "topology", "boundaries", "adr", "tradeoff"),
    "backend_engineering": ("backend", "api", "server", "endpoint", "service", "rest", "auth", "authentication", "webhook", "worker", "queue", "saas", "crud", "fastapi", "django", "node", "express"),
    "frontend_engineering": ("frontend", "ui", "react", "vue", "svelte", "component", "css", "browser", "web", "page", "responsive", "dashboard", "spa", "tailwind"),
    "mobile_engineering": ("mobile", "ios", "android", "app", "swift", "kotlin", "flutter", "react native", "phone", "tablet"),
    "game_development": ("game", "gameplay", "unity", "unreal", "player", "level", "npc", "multiplayer", "sprite", "shader"),
    "embedded_systems": ("embedded", "firmware", "microcontroller", "arduino", "esp32", "rtos", "sensor", "hardware", "iot", "driver"),
    "data_engineering": ("data pipeline", "etl", "ingestion", "warehouse", "airflow", "spark", "streaming", "kafka", "batch", "lakehouse", "dbt"),
    "data_science": ("statistics", "statistical", "regression", "correlation", "hypothesis", "distribution", "dataset", "eda", "cohort", "forecast", "experiment"),
    "machine_learning": ("ml model", "machine learning", "recommendation", "recommender", "recsys", "predictive", "prediction", "classifier", "classification", "train a model", "predictive model", "computer vision", "nlp", "neural", "training", "llm", "embedding", "rag", "finetune", "fine-tune", "classifier", "prompt", "inference", "transformer"),
    "mlops": ("mlops", "model deployment", "drift", "serving", "feature store", "retraining", "model registry"),
    "devops": ("ci", "cd", "ci/cd", "jenkins", "github actions", "docker", "build", "release", "deploy", "automation", "devops"),
    "cloud_infrastructure": ("cloud", "aws", "azure", "gcp", "kubernetes", "terraform", "vpc", "infrastructure", "cdn", "serverless", "k8s"),
    "site_reliability": ("reliability", "uptime", "incident", "slo", "sla", "oncall", "outage", "monitoring", "alerting", "postmortem", "latency"),
    "security": ("security", "secure", "vulnerability", "exploit", "threat", "penetration", "xss", "csrf", "injection", "encryption", "hardening", "attack", "breach"),
    "privacy_compliance": ("privacy", "gdpr", "hipaa", "soc2", "soc 2", "pci", "compliance", "consent", "retention", "dpia", "personal data", "regulation"),
    "quality_assurance": ("test", "testing", "qa", "pytest", "unit test", "coverage", "flaky", "regression", "e2e", "assertion", "bug"),
    "database": ("database", "sql", "postgres", "mysql", "schema", "query", "index", "migration", "mongodb", "table", "join", "normalise", "normalize"),
    "api_design": ("api design", "openapi", "swagger", "graphql", "grpc", "contract", "versioning", "pagination", "sdk", "rate limit"),
    "product_management": ("product", "requirement", "roadmap", "feature", "user story", "backlog", "prioritise", "prioritize", "mvp", "scope", "stakeholder"),
    "ux_design": ("ux", "user experience", "wireframe", "usability", "onboarding", "flow", "prototype", "interaction", "accessibility", "design system"),
    "technical_writing": ("documentation", "docs", "readme", "tutorial", "guide", "manual", "changelog", "reference", "write up", "explain"),
    "research": ("research", "investigate", "survey", "literature", "paper", "arxiv", "study", "evidence", "source", "citation", "state of the art", "compare", "landscape"),
    "scientific_computing": ("simulation", "numerical", "physics", "chemistry", "differential", "solver", "matrix", "finite element", "monte carlo", "hpc", "climate"),
    "bioinformatics": ("genome", "genomic", "dna", "rna", "sequencing", "protein", "variant", "bioinformatics", "microbiome", "phylogen"),
    "healthcare": ("clinical", "patient", "medical", "health", "diagnosis", "treatment", "hospital", "fhir", "icd", "trial", "physician"),
    "legal": ("legal", "contract", "clause", "law", "litigation", "liability", "intellectual property", "licence", "license", "terms of service", "nda", "attorney", "statute"),
    "finance": ("financial", "finance", "valuation", "revenue", "dcf", "investment", "cashflow", "cash flow", "runway", "budget", "margin", "forecast", "pricing", "portfolio", "unit economics"),
    "accounting": ("accounting", "ledger", "bookkeeping", "reconcile", "reconciliation", "payroll", "tax", "invoice", "financial audit", "balance sheet", "depreciation"),
    "marketing": ("marketing", "campaign", "seo", "brand", "copy", "content", "advertis", "social media", "newsletter", "funnel", "growth", "positioning", "landing page"),
    "sales": ("sales", "prospect", "sales lead", "outreach", "crm", "sales pipeline", "proposal", "rfp", "quota", "negotiat", "cold email", "closing"),
    "customer_support": ("support ticket", "customer support", "helpdesk", "ticket", "escalation", "knowledge base", "faq", "churn", "csat"),
    "human_resources": ("hiring", "recruit", "candidate", "interview", "employee", "onboarding plan", "compensation", "performance review", "hr", "job description"),
    "operations": ("operations", "process", "sop", "workflow", "logistics", "inventory", "supply", "procurement", "vendor", "scheduling", "throughput"),
    "analytics": ("analytics", "metric", "kpi", "dashboard", "report", "funnel", "attribution", "tracking", "insight", "bi"),
    "creative_writing": ("story", "novel", "fiction", "character", "plot", "screenplay", "poem", "poetry", "essay", "narrative", "script", "dialogue", "fantasy", "chapter"),
    "media_production": ("video", "podcast", "audio", "film", "footage", "subtitle", "storyboard", "edit", "youtube", "livestream", "voiceover"),
    "education": ("teach", "learn", "curriculum", "lesson", "course", "student", "exam", "quiz", "tutor", "syllabus", "explain concept", "training material"),
    "blockchain": ("blockchain", "smart contract", "solidity", "ethereum", "token", "defi", "wallet", "onchain", "on-chain", "nft", "crypto"),
    "localization": ("translate", "translation", "localis", "localiz", "multilingual", "locale", "language support", "rtl", "i18n"),
    "orchestration": ("plan", "orchestrat", "coordinate", "decompose", "delegate", "workflow of agents", "verify", "critique"),
}

_DOMAIN_KW_INDEX: dict[str, list[str]] = {d: list(k) for d, k in DOMAIN_KEYWORDS.items()}


# A live domain implies its neighbours: you cannot build an app with only a backend.
DOMAIN_COMPANIONS: dict[str, tuple[str, ...]] = {
    "backend_engineering": ("database", "api_design", "quality_assurance", "security", "frontend_engineering"),
    "frontend_engineering": ("ux_design", "quality_assurance", "backend_engineering"),
    "mobile_engineering": ("ux_design", "quality_assurance", "backend_engineering"),
    "machine_learning": ("data_engineering", "mlops", "data_science"),
    "mlops": ("machine_learning", "devops", "site_reliability"),
    "data_engineering": ("database", "data_science", "quality_assurance"),
    "devops": ("cloud_infrastructure", "site_reliability", "security"),
    "cloud_infrastructure": ("devops", "security", "site_reliability"),
    "blockchain": ("security", "quality_assurance"),
    "game_development": ("quality_assurance", "ux_design"),
    "embedded_systems": ("quality_assurance", "security"),
    "healthcare": ("privacy_compliance", "research"),
    "legal": ("privacy_compliance", "research"),
    "finance": ("accounting", "analytics"),
    "accounting": ("finance",),
    "marketing": ("analytics", "technical_writing"),
    "creative_writing": ("technical_writing",),
    "localization": ("technical_writing", "quality_assurance"),
    "education": ("technical_writing",),
    "security": ("privacy_compliance", "quality_assurance"),
    "research": ("analytics",),
}


def domain_affinity(goal: str) -> dict[str, float]:
    """Which domains is this goal actually about? Normalised 0..1."""
    gl = (goal or "").lower()
    toks = set(_goal_tokens(goal))
    raw: dict[str, float] = {}
    for dom, kws in _DOMAIN_KW_INDEX.items():
        score = 0.0
        for kw in kws:
            if " " in kw:
                if kw in gl:
                    score += 2.5           # multi-word phrases are strong evidence
            elif kw in toks:
                score += 1.5
            elif len(kw) > 5 and any(t.startswith(kw[:5]) and len(t) > 4 for t in toks):
                score += 0.5               # conservative stem match
        if score:
            raw[dom] = score
    if not raw:
        return {}
    # pull in companion domains at reduced weight so plans are complete, not lopsided
    for dom, v in list(raw.items()):
        if v >= 0.6 * max(raw.values()):
            for comp in DOMAIN_COMPANIONS.get(dom, ()):
                raw[comp] = max(raw.get(comp, 0.0), v * 0.45)
    top = max(raw.values())
    return {d: round(v / top, 4) for d, v in raw.items()}


def _goal_tokens(goal: str) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9]+", (goal or "").lower())
            if len(w) > 2 and w not in STOPWORDS]


def goal_complexity(goal: str) -> float:
    """0..1 — drives how many agents and how much parallelism the plan gets."""
    toks = _goal_tokens(goal)
    score = min(1.0, len(toks) / 40.0) * 0.4
    score += min(1.0, sum(1 for w in COMPLEXITY_WORDS if w in goal.lower()) / 4.0) * 0.4
    score += min(1.0, goal.count(",") / 6.0) * 0.2
    return round(min(1.0, score), 3)


def _candidates(goal: str) -> dict[str, int]:
    """Cheap inverted-index lookup — never scans all 480 definitions."""
    hits: dict[str, int] = defaultdict(int)
    for w in _goal_tokens(goal):
        for aid in TOKEN_INDEX.get(w, ()):
            hits[aid] += 3
    return hits


def _score(defn: AgentDefinition, goal: str, perf: float, raw_hit: int = 0,
           budget_usd: float = 5.0, dom_aff: dict[str, float] | None = None) -> float:
    """Domain affinity first, then role match, cost fit and measured performance."""
    dom_aff = dom_aff or {}
    domain_score = dom_aff.get(defn.domain, 0.0)
    gl = (goal or "").lower()
    cap_hit = sum(1 for c in defn.capabilities if len(c) > 3 and c.lower() in gl)
    # stem overlap catches translate/translator, deploy/deployment, test/testing
    gstems = {t[:5] for t in _goal_tokens(goal)}
    astems = {t[:5] for t in AGENT_TOKENS.get(defn.id, ())}
    stem_hits = len(gstems & astems)
    role_part = defn.id.split(".", 1)[-1]
    rstems = {t[:5] for t in re.findall(r"[a-z0-9]+", f"{role_part} {defn.name}".lower()) if len(t) > 2}
    role_hits = len(gstems & rstems)     # matched the specific role, not just the domain
    role_score = min(1.0, 0.22 * cap_hit + 0.12 * stem_hits + 0.30 * role_hits + 0.04 * min(raw_hit, 4))
    cost_rank = COST_RANK.get(defn.cost_level, 0)
    cost_fit = 1.0 - cost_rank * (0.35 if budget_usd < 1.0 else 0.15)
    risk_penalty = 0.08 * COST_RANK.get(defn.risk_level, 0)
    return round(0.45 * domain_score + 0.35 * role_score
                 + 0.08 * cost_fit + 0.12 * perf - risk_penalty, 5)


def _phase_width(phase: str, complexity: float) -> int:
    base = {"analyze": 2, "research": 3, "design": 3, "implement": 5,
            "verify": 3, "deliver": 2, "synthesize": 2}[phase]
    return max(1, int(round(base * (0.7 + complexity))))


BUILD_WORDS = ("build", "create", "develop", "implement", "production", "ship", "launch",
               "end-to-end", "full", "complete", "platform", "application", "system", "product")


def active_phases(goal: str, dom_aff: dict[str, float] | None = None) -> list[str]:
    """A phase is active if the wording asks for it, or a live domain needs it."""
    gl = (goal or "").lower()
    active = {"analyze", "synthesize"}                      # always
    for phase, signals in PHASE_SIGNALS.items():
        if any(sig in gl for sig in signals):
            active.add(phase)
    # domains the goal is about bring their own phases with them
    dom_aff = dom_aff if dom_aff is not None else domain_affinity(goal)
    for dom, v in dom_aff.items():
        if v >= 0.60 and dom != "orchestration":
            active |= DOMAIN_PHASES.get(dom, {"implement"})
    if active <= {"analyze", "synthesize"}:
        active |= {"research", "implement", "verify"}
    if any(w in gl for w in BUILD_WORDS):                    # real build => design + handover
        active |= {"design", "implement", "verify", "deliver"}
    if "implement" in active:
        active.add("verify")                                 # never ship unverified work
    return [p for p in PHASES if p in active]


def route_goal(goal: str, perf_map: dict[str, float] | None = None,
               budget_tokens: int = 120000, budget_usd: float = 5.0,
               max_agents: int = 24) -> RoutePlan:
    """Select agents by capability match across the whole catalogue, in any field."""
    perf_map = perf_map or {}
    complexity = goal_complexity(goal)
    dom_aff = domain_affinity(goal)
    phases = active_phases(goal, dom_aff)
    hits = _candidates(goal)

    # candidate pool = agents in domains the goal is about, plus direct token hits
    live_domains = {d for d, v in dom_aff.items() if v >= 0.30} | {"orchestration"}
    pool: dict[str, int] = {}
    for dom in live_domains:
        for aid in DOMAIN_INDEX.get(dom, ()):
            pool[aid] = hits.get(aid, 0)
    if len(pool) <= len(DOMAIN_INDEX.get("orchestration", ())):
        # no domain read confidently — fall back to raw token hits, then everything
        pool = {aid: h for aid, h in hits.items() if aid in REGISTRY} or {aid: 0 for aid in REGISTRY}

    by_phase: dict[str, list[tuple[float, AgentDefinition]]] = {p: [] for p in phases}
    for aid, raw in pool.items():
        d = REGISTRY[aid]
        sc = _score(d, goal, perf_map.get(aid, 0.5), raw, budget_usd, dom_aff)
        for p in DOMAIN_PHASES.get(d.domain, {"implement"}) & set(phases):
            by_phase[p].append((sc, d))

    # orchestration spine — always present, regardless of keyword match
    spine = {
        "analyze": ["orchestration.goal_decomposer", "product_management.goal_analyzer"],
        "synthesize": ["orchestration.critic", "orchestration.final_verifier"],
    }

    steps: list[RouteStep] = []
    prev_layer: list[str] = []
    idx = 0
    selected: set[str] = set()

    for phase in phases:
        width = _phase_width(phase, complexity)
        chosen: list[AgentDefinition] = []
        for forced in spine.get(phase, []):
            d = resolve_agent(forced)
            if d and d.id not in selected:
                chosen.append(d); selected.add(d.id)
        ranked = sorted(by_phase.get(phase, []), key=lambda t: -t[0])
        for sc, d in ranked:
            if len(chosen) >= width or len(selected) >= max_agents:
                break
            if d.id in selected:
                continue
            chosen.append(d); selected.add(d.id)
        if not chosen:
            continue
        layer: list[str] = []
        for d in chosen:
            nid = f"n{idx}"; idx += 1
            steps.append(RouteStep(
                node_id=nid, agent_id=d.id, depends_on=list(prev_layer), tools=d.tools,
                capability=(d.model_requirements or {}).get("capability", "general"),
                verification=d.verification_strategy))
            layer.append(nid)
        prev_layer = layer

    if not steps:   # never return an empty plan
        d = resolve_agent("orchestration.goal_decomposer") or next(iter(REGISTRY.values()))
        steps = [RouteStep(node_id="n0", agent_id=d.id, depends_on=[], tools=d.tools,
                           capability="general", verification=d.verification_strategy)]

    concurrency = max(2, min(8, int(round(2 + complexity * 6))))
    return RoutePlan(steps=steps, concurrency=concurrency, budget_tokens=budget_tokens,
                     budget_usd=budget_usd, complexity=complexity)


# =====================================================================================
# 5b. Intent routing — not every message deserves a 16-agent task graph
# =====================================================================================
# "hi" must not spawn a DAG. A conversational turn takes one model call and returns in
# well under a second; only genuine work is promoted to the long-horizon orchestrator.

CHAT_MAX_WORDS = int(_env("CHAT_MAX_WORDS", "40"))

GREETING_RE = re.compile(
    r"^(hi|hey|hello|yo|sup|howdy|good (morning|afternoon|evening)|thanks?|thank you|"
    r"ty|ok|okay|cool|nice|great|bye|goodbye|see ya|gm|gn)\b[\s!.,?]*$", re.I)

# Asking *about* something is conversation. Asking *for* something built is a task.
TASK_VERBS = (
    "build", "create", "implement", "develop", "design", "write", "draft", "generate",
    "produce", "refactor", "migrate", "deploy", "audit", "review", "analyse", "analyze",
    "research", "investigate", "compare", "evaluate", "plan", "architect", "optimise",
    "optimize", "debug", "fix", "test", "translate", "summarise", "summarize", "automate",
    "scaffold", "set up", "integrate", "benchmark", "model", "forecast", "reconcile",
)
TASK_NOUNS = (
    "application", "app", "platform", "system", "pipeline", "report", "dashboard",
    "api", "service", "database", "schema", "test suite", "roadmap", "strategy",
    "architecture", "migration", "deployment", "curriculum", "model", "codebase",
    "repository", "documentation", "spec", "proposal", "contract", "analysis",
    "tests", "test", "bug", "bugs", "ci", "pipeline", "website", "site", "script",
    "server", "backend", "frontend", "feature", "module", "component", "config",
)
QUESTION_STARTS = ("what", "who", "when", "where", "why", "how", "which", "is", "are",
                   "was", "were", "do", "does", "did", "can", "could", "should", "would",
                   "will", "explain", "tell me", "define")


def classify_intent(message: str) -> dict:
    """Decide between a fast conversational reply and a full orchestrated task.

    Returns {mode, confidence, reason, complexity}. `mode` is "chat" or "task".
    """
    msg = (message or "").strip()
    if not msg:
        return {"mode": "chat", "confidence": 1.0, "reason": "empty message", "complexity": 0.0}

    low = msg.lower()
    words = re.findall(r"[a-z0-9']+", low)
    n = len(words) or len(msg.split())          # CJK and other scripts tokenise to nothing
    complexity = goal_complexity(msg)

    if GREETING_RE.match(msg):
        return {"mode": "chat", "confidence": 1.0, "reason": "greeting or acknowledgement",
                "complexity": complexity}

    # explicit override wins over every heuristic
    if low.startswith(("/task", "!task")):
        return {"mode": "task", "confidence": 1.0, "reason": "explicit /task prefix",
                "complexity": max(complexity, 0.5)}
    if low.startswith(("/chat", "!chat")):
        return {"mode": "chat", "confidence": 1.0, "reason": "explicit /chat prefix",
                "complexity": complexity}

    has_verb = any(re.search(rf"\b{re.escape(v)}\b", low) for v in TASK_VERBS)
    has_noun = any(nn in low for nn in TASK_NOUNS)
    is_question = (bool(words) and words[0] in QUESTION_STARTS) or msg.rstrip().endswith("?")
    multi_part = msg.count(",") >= 2 or " and " in low or msg.count("\n") >= 2

    starts_imperative = bool(words) and words[0] in TASK_VERBS
    score = 0.0
    if has_verb:
        score += 0.45
    if starts_imperative:
        score += 0.20                       # "fix the tests" is an order, not a question
    if has_noun:
        score += 0.25
    if multi_part:
        score += 0.15
    if n > CHAT_MAX_WORDS:
        score += 0.25
    if complexity >= 0.25:
        score += 0.20
    # A plain question is conversation even when it mentions a task noun:
    # "what is a good database schema?" is a question, "design a database schema" is work.
    if is_question and not has_verb:
        score -= 0.45
    if n <= 6 and not has_verb:
        score -= 0.35

    if score >= 0.5:
        return {"mode": "task", "confidence": round(min(1.0, score), 2),
                "reason": "requests work to be produced", "complexity": complexity}
    return {"mode": "chat", "confidence": round(min(1.0, 1.0 - score), 2),
            "reason": "conversational turn", "complexity": complexity}


FAST_SYSTEM = (
    "You are Maximus, a direct and knowledgeable assistant. Answer the message plainly "
    "and concisely. Do not announce what you are about to do, do not pad the answer, and "
    "do not offer to build anything unless asked. If the request genuinely needs a "
    "multi-step project, say so in one sentence and stop."
)


async def provider_credential(user_id: str, project_id: str = "",
                              provider_override: str | None = None) -> tuple[str | None, str]:
    """Return the user's project-scoped BYOK secret and provider slug.

    Project keys win over user-wide keys. When `provider_override` is set (the user
    picked a specific model in the UI), only a key for that exact provider is
    considered, so a selection is never silently answered by a different provider
    than the one the user chose. The plaintext secret is kept in memory only for the
    duration of the model call and is never returned to the browser.
    """
    if user_id:
        try:
            SF = session_factory()
            async with SF() as db:
                rows = (await db.execute(
                    select(ProviderKey).where(ProviderKey.user_id == user_id,
                                               ProviderKey.is_valid == True)  # noqa: E712
                )).scalars().all()
                rows.sort(key=lambda row: 0 if project_id and row.project_id == project_id else 1)
                for row in rows:
                    if project_id and row.project_id not in (None, project_id):
                        continue
                    provider = await db.get(Provider, row.provider_id)
                    slug = provider.slug if provider else ""
                    if provider_override and slug != provider_override:
                        continue
                    try:
                        secret = decrypt_secret(row.encrypted_blob)
                    except Exception:
                        continue
                    return secret, slug
        except Exception:
            pass
    # A hosted single-service deployment may keep its provider credential in
    # Render's environment instead of creating a database key first.  This is
    # deliberately a fallback: database/project-scoped BYOK keys above still
    # take precedence, and the secret is only returned to the in-process model
    # call, never to the browser or logs.
    provider = (provider_override or _env("DEFAULT_PROVIDER", "") or
                _env("GATEWAY_PROVIDER", "groq")).strip().lower()
    if provider:
        env_names = {
            "openai": ("OPENAI_API_KEY",),
            "anthropic": ("ANTHROPIC_API_KEY",),
            "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
            "groq": ("GROQ_API_KEY", "GATEWAY_API_KEY"),
            "mistral": ("MISTRAL_API_KEY",),
            "deepseek": ("DEEPSEEK_API_KEY",),
            "nvidia": ("NVIDIA_API_KEY",),
            "openrouter": ("OPENROUTER_API_KEY",),
            "together": ("TOGETHER_API_KEY",),
            "cohere": ("COHERE_API_KEY",),
        }.get(provider, (f"{provider.upper()}_API_KEY",))
        for name in env_names:
            secret = _env(name, "").strip()
            if secret:
                return secret, provider
    return None, (provider_override or "")


async def fast_reply(message: str, history: list[dict] | None = None,
                     project_id: str = "", user_id: str = "",
                     model: str | None = None, provider: str | None = None) -> dict:
    """Single-call conversational response. No planning, no DAG, no agents.

    `model`/`provider` come straight from the UI's model picker. When set, they are
    forced through as an explicit model_hint (and a provider-scoped key lookup)
    instead of letting the capability router pick something else.
    """
    t0 = time.monotonic()
    omni = OmniRouteClient()
    messages = build_messages(FAST_SYSTEM, message, history)
    provider_key, provider_slug = await provider_credential(user_id, project_id, provider)
    model_used = model or ""
    try:
        resp = await omni.complete(messages, capability="cheap", max_tokens=700,
                                   model_hint=model or None,
                                   timeout_s=int(_env("CHAT_TIMEOUT_S", "20")),
                                   provider_key=provider_key, provider=provider_slug,
                                   cache_key_extra=f"fastchat:{provider_slug or 'gateway'}:{model or 'auto'}")
        text = (resp.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
        usage = resp.get("usage") or {}
        tokens = int(usage.get("total_tokens") or len(text) // 4)
        cached = bool(resp.get("_cached"))
        model_used = resp.get("model") or model_used
    except ModelUnavailableError:
        text = "The selected model is not available. Please choose another model."
        tokens, cached = 0, False
    except OmniRouteError as e:
        # Keep provider/network details out of the conversation. A working model
        # should produce an answer; if the provider is temporarily unavailable,
        # give the user a concise retry message instead of exposing internals.
        if _looks_like_model_error(str(e)):
            text = "The selected model is not available. Please choose another model."
        else:
            text = "I couldn't generate a response right now. Please try again."
        tokens, cached = 0, False
    except Exception:
        text = "I couldn't generate a response right now. Please try again."
        tokens, cached = 0, False
    return {"reply": text, "tokens": tokens, "cached": cached, "model": model_used,
            "latency_ms": int((time.monotonic() - t0) * 1000)}




# ---- Planner: RoutePlan -> persistent DAG ----
HUMAN_GATE_AGENTS = {"deployment"}  # legacy short ids


def needs_human_gate(agent_id: str) -> bool:
    d = resolve_agent(agent_id)
    if d is not None and d.human_gate:
        return True
    return agent_id in HUMAN_GATE_AGENTS


def plan_to_dag(plan: RoutePlan) -> dict:
    nodes = []
    for s in plan.steps:
        nodes.append({
            "node_id": s.node_id, "agent_id": s.agent_id, "depends_on": s.depends_on,
            "tools": s.tools, "capability": s.capability, "verification": s.verification,
            "status": "pending", "attempts": 0, "max_retries": 3, "timeout_s": 600,
            "needs_approval": needs_human_gate(s.agent_id),
            "complexity": plan.complexity,
            "result": None, "error": None, "started_at": None, "ended_at": None,
        })
    return {"nodes": nodes, "created_at": time.time(), "concurrency": plan.concurrency,
            "budget_tokens": plan.budget_tokens, "budget_usd": plan.budget_usd,
            "deadline_at": time.time() + float(_env("TASK_DEADLINE_S", "86400")),
            "expansions": 0, "max_expansions": int(_env("MAX_DAG_EXPANSIONS", "3")),
            "generation": 0}


def expand_dag(dag: dict, parent: dict, subtasks: list[dict], goal: str) -> int:
    """Let an agent add work it discovered mid-run — the core of long-horizon execution.

    Bounded by max_expansions so a task cannot grow without limit.
    """
    if dag.get("expansions", 0) >= dag.get("max_expansions", 3):
        return 0
    if not subtasks:
        return 0
    existing = {n["node_id"] for n in dag["nodes"]}
    added = 0
    for st in subtasks[:6]:
        agent_id = str(st.get("agent") or "").strip()
        defn = resolve_agent(agent_id)
        if defn is None:
            hits = registry_search(str(st.get("description", ""))[:120], limit=1)
            if not hits:
                continue
            defn = hits[0]
        nid = f"x{dag.get('generation', 0)}_{len(existing) + added}"
        if nid in existing:
            continue
        dag["nodes"].append({
            "node_id": nid, "agent_id": defn.id,
            "depends_on": [parent["node_id"]], "tools": defn.tools,
            "capability": (defn.model_requirements or {}).get("capability", "general"),
            "verification": defn.verification_strategy, "status": "pending",
            "attempts": 0, "max_retries": 2, "timeout_s": 600,
            "needs_approval": needs_human_gate(defn.id),
            "result": None, "error": None, "started_at": None, "ended_at": None,
            "spawned_by": parent["node_id"],
            "subtask": str(st.get("description", ""))[:400],
        })
        added += 1
    if added:
        dag["expansions"] = dag.get("expansions", 0) + 1
        dag["generation"] = dag.get("generation", 0) + 1
    return added


def dag_expired(dag: dict) -> bool:
    dl = dag.get("deadline_at")
    return bool(dl) and time.time() > float(dl)


def ready_nodes(dag: dict) -> list[dict]:
    done = {n["node_id"] for n in dag["nodes"] if n["status"] in ("completed", "approved")}
    return [n for n in dag["nodes"]
            if n["status"] == "pending" and all(d in done for d in n["depends_on"])]


def dag_status(dag: dict) -> str:
    states = {n["status"] for n in dag["nodes"]}
    if states <= {"completed", "approved", "skipped"}:
        return "completed"
    if "failed" in states and not ready_nodes(dag) and not any(n["status"] in ("pending", "running") for n in dag["nodes"]):
        return "failed"
    if any(n["status"] == "awaiting_approval" for n in dag["nodes"]):
        return "awaiting_approval"
    if any(n["status"] == "running" for n in dag["nodes"]):
        return "running"
    return "pending"


# ---- Runtime lifecycle: UNDERSTAND→PLAN→TOOL_CALL→OBSERVE→ACT→VERIFY→COMPLETE ----
LIFECYCLE = ["UNDERSTAND", "PLAN", "TOOL_CALL", "OBSERVE", "ACT", "VERIFY", "COMPLETE"]
CAN_CALL = {
    "goal_analyzer": {"requirements", "researcher", "analyst"},
    "architecture": {"frontend", "backend", "database", "ai_integrator"},
    "backend": {"database", "testing"},
    "critic": {"frontend", "backend", "testing"},
}


def can_delegate(frm: str, to: str) -> bool:
    return to in CAN_CALL.get(frm, set()) or frm in ("goal_analyzer", "architecture", "critic")


@dataclass
class Deps:
    omni: Any
    tools: Any
    memory: Any
    events: Any
    provider_key: str | None = None
    provider_slug: str = ""


async def _emit_safe(deps: Deps, task_id: str, run_id: str | None, typ: str, payload: dict) -> None:
    try:
        clean = {k: (redact(v) if isinstance(v, str) else v) for k, v in payload.items()}
        await deps.events(task_id, run_id, typ, clean)
    except Exception:
        pass


async def run_node(node: dict, task: dict, deps: Deps) -> dict:
    task_id, node_id, agent_id = task["id"], node["node_id"], node["agent_id"]
    run_id = f"{task_id}:{node_id}"
    defn = resolve_agent(agent_id)
    if defn is None:
        node["status"] = "failed"
        node["error"] = f"unknown agent {agent_id}"
        return {"run_id": run_id, "agent_id": agent_id, "node_id": node_id,
                "status": "failed", "error": node["error"], "attempt": 0}

    await _emit_safe(deps, task_id, run_id, "agent_started",
                     {"agent": agent_id, "name": defn.name, "domain": defn.domain, "node": node_id})
    try:
        mem_snips = await deps.memory.recall(task.get("project_id", ""), task.get("goal", ""), limit=5)
    except Exception:
        mem_snips = []

    ctx = AgentContext(goal=task["goal"], project_id=task.get("project_id", ""),
                       task_id=task_id, node_id=node_id, memory_snippets=mem_snips,
                       upstream=task.get("upstream", {}))

    async def emit_phase(phase: str, summary: str) -> None:
        # Safe status only. The model's internal reasoning is never streamed.
        await _emit_safe(deps, task_id, run_id, "thinking",
                         {"agent": agent_id, "phase": phase, "status": summary})

    last_err: Exception | None = None
    for attempt in range(1, int(node.get("max_retries", 3)) + 1):
        node["attempts"] = attempt
        node["status"] = "running"
        t0 = time.time()
        try:
            agent = GenericAgent(defn)
            res = await asyncio.wait_for(agent.run(ctx, deps, node=node, emit_phase=emit_phase),
                                         timeout=float(node.get("timeout_s", 600)))
            latency = int((time.time() - t0) * 1000)
            node["result"] = res.structured_output
            node["status"] = ("awaiting_approval"
                              if node.get("needs_approval") and res.status == "completed"
                              else res.status)
            await _emit_safe(deps, task_id, run_id, "agent_completed",
                             {"agent": agent_id, "node": node_id, "latency_ms": latency,
                              "tokens": res.usage_tokens,
                              "think_depth": res.structured_output.get("think_depth"),
                              "self_review": res.structured_output.get("self_review", {})})
            return {"run_id": run_id, "agent_id": agent_id, "node_id": node_id,
                    "status": node["status"], "output": res.structured_output,
                    "summary": res.summary, "tokens": res.usage_tokens, "cost": res.usage_usd,
                    "model": res.structured_output.get("model", ""),
                    "latency_ms": latency, "attempt": attempt}
        except asyncio.TimeoutError as e:
            last_err = e
            node["error"] = f"node timeout after {node.get('timeout_s', 600)}s"
            await _emit_safe(deps, task_id, run_id, "retrying",
                             {"agent": agent_id, "attempt": attempt, "error": "timeout"})
        except Exception as e:
            last_err = e
            node["error"] = redact(str(e))[:500]
            await _emit_safe(deps, task_id, run_id, "retrying",
                             {"agent": agent_id, "attempt": attempt, "error": redact(str(e))[:200]})
        await asyncio.sleep(min(2 ** attempt, 10) * (0.7 + random.random() * 0.6))
    node["status"] = "failed"
    return {"run_id": run_id, "agent_id": agent_id, "node_id": node_id, "status": "failed",
            "error": redact(str(last_err))[:500], "attempt": node.get("attempts", 1)}


def collect_upstream(dag: dict, node: dict, max_chars: int = 6000) -> dict:
    """Structured JSON handoff between agents — not a blob of concatenated text."""
    out: dict = {}
    by_id = {n["node_id"]: n for n in dag.get("nodes", [])}
    budget = max_chars
    for dep in node.get("depends_on", []):
        up = by_id.get(dep)
        if not up or not up.get("result"):
            continue
        r = up["result"]
        entry = {
            "agent": r.get("agent"), "domain": r.get("domain"),
            "deliverable": (r.get("deliverable") or "")[:max(400, budget // 2)],
            "acceptance_criteria": (r.get("understanding") or {}).get("acceptance_criteria", [])[:6],
            "open_questions": (r.get("understanding") or {}).get("unknowns", [])[:4],
        }
        blob = json.dumps(entry)
        if len(blob) > budget:
            entry["deliverable"] = entry["deliverable"][:max(200, budget // 3)]
        out[dep] = entry
        budget -= min(len(blob), budget)
        if budget <= 200:
            break
    return out

# =====================================================================================
# 9. OMNIROUTE — model/provider routing gateway client (Maximus picks capability class)
# =====================================================================================
class OmniRouteError(Exception):
    pass


class ModelUnavailableError(OmniRouteError):
    """The model explicitly selected by the user cannot be used anymore."""
    pass


class OmniRouteClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None, timeout_s: int | None = None):
        configured_base = (base_url or S.OMNIROUTE_BASE_URL).strip().rstrip("/")
        # Render Blueprint service references expose `host:port`, not a URL.
        # Accept both forms so the value can be wired directly with
        # `fromService.property: hostport`.
        if configured_base and not re.match(r"^https?://", configured_base, re.I):
            configured_base = f"http://{configured_base}"
        self.base = configured_base
        self.api_key = S.OMNIROUTE_API_KEY if api_key is None else api_key
        self.timeout = timeout_s or S.OMNIROUTE_TIMEOUT_S
        self._failures: dict[str, int] = {}
        self._opened: dict[str, float] = {}

    def _headers(self, provider_key: str | None = None, provider_slug: str = "") -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        if provider_key:
            h["X-Provider-Key"] = provider_key  # BYOK, server-side only, never logged
        if provider_slug:
            h["X-Provider-Slug"] = provider_slug
        return h

    def _cb_open(self, key: str) -> bool:
        return time.time() < self._opened.get(key, 0)

    def _cb_fail(self, key: str) -> None:
        self._failures[key] = self._failures.get(key, 0) + 1
        if self._failures[key] >= 3:
            self._opened[key] = time.time() + 60

    def _cb_ok(self, key: str) -> None:
        self._failures[key] = 0

    async def discover_models(self) -> list[dict]:
        r = await http().get(f"{self.base}/models", headers=self._headers(), timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and "data" in data:
            return data["data"]
        return data if isinstance(data, list) else []

    async def health(self) -> dict:
        try:
            r = await http().get(f"{self.base}/health", headers=self._headers(), timeout=10)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        try:
            models = await self.discover_models()
            return {"status": "healthy", "models": len(models)}
        except Exception as e:
            return {"status": "down", "error": str(e)[:200]}

    async def complete(self, messages: list[dict], capability: str = "reasoning",
                       model_hint: str | None = None, provider_key: str | None = None,
                       temperature: float = 0.2, max_tokens: int = 2000,
                       timeout_s: int | None = None,
                       fallback_capabilities: list[str] | None = None,
                       provider: str = "", cache_key_extra: str = "") -> dict:
        """One gated, cached, retried model call.

        Rate limits are respected before the request leaves, not discovered via 429s.
        """
        chain = [capability] + (fallback_capabilities or CAPABILITY_MAP.get(capability, ["general"])[1:])
        seen: set[str] = set()
        chain = [c for c in chain if not (c in seen or seen.add(c))]

        cached = RESPONSE_CACHE.get(messages, capability, max_tokens, cache_key_extra)
        if cached is not None:
            return cached

        # BYOK short-circuit: a user-supplied key calls the provider directly instead of
        # going through OMNIROUTE_BASE_URL, which is a separate gateway process nothing
        # here starts automatically. No key -> unchanged gateway path below.
        if provider_key and provider:
            t0 = time.monotonic()
            explicit_model = bool(model_hint)
            model = model_hint or ""
            if explicit_model and is_deprecated_provider_model(provider, model_hint):
                raise ModelUnavailableError(
                    f"model '{model_hint}' is no longer available"
                )
            try:
                model = model_hint or await resolve_model_for_provider(provider, provider_key, capability)
                if not model:
                    raise OmniRouteError(f"no usable model found for provider '{provider}'")
                model = normalize_provider_model(provider, model)
                data = await direct_provider_complete(provider, provider_key, messages, model,
                                                       temperature=temperature, max_tokens=max_tokens,
                                                       timeout_s=timeout_s or self.timeout)
                data["_latency_ms"] = int((time.monotonic() - t0) * 1000)
                data["_cost_usd"] = data.get("_cost_usd", 0.0)
                data["model"] = model
                RESPONSE_CACHE.put(messages, capability, max_tokens, cache_key_extra, data)
                return data
            except OmniRouteError as e:
                if _looks_like_model_error(str(e)):
                    if explicit_model:
                        raise ModelUnavailableError(
                            f"model '{model_hint}' is not available"
                        ) from e
                    # Cached catalogues can contain models removed by the
                    # provider. Refresh once and retry with a live model.
                    try:
                        fresh_model = await resolve_live_model_for_provider(
                            provider, provider_key, capability, exclude={model}
                        )
                    except Exception:
                        fresh_model = None
                    if fresh_model and fresh_model != model:
                        try:
                            data = await direct_provider_complete(
                                provider, provider_key, messages, fresh_model,
                                temperature=temperature, max_tokens=max_tokens,
                                timeout_s=timeout_s or self.timeout,
                            )
                            data["_latency_ms"] = int((time.monotonic() - t0) * 1000)
                            data["_cost_usd"] = data.get("_cost_usd", 0.0)
                            data["model"] = fresh_model
                            RESPONSE_CACHE.put(messages, capability, max_tokens, cache_key_extra, data)
                            return data
                        except OmniRouteError:
                            pass
                raise
            except Exception as e:
                raise OmniRouteError(f"direct provider call failed: {redact(str(e))[:200]}")

        gate = gate_for(provider or _env("DEFAULT_PROVIDER", "_default"))
        est = estimate_tokens(messages, max_tokens)
        last: Exception | None = None

        for cap in chain:
            if self._cb_open(cap):
                continue
            for attempt in range(1, int(_env("MODEL_MAX_RETRIES", "3")) + 1):
                try:
                    await gate.acquire(est)
                    async with gate.sem:
                        t0 = time.monotonic()
                        r = await http().post(
                            f"{self.base}/v1/chat/completions",
                            headers=self._headers(provider_key, provider),
                            json={"messages": messages, "capability": cap, "model": model_hint,
                                  "temperature": temperature, "max_tokens": max_tokens},
                            timeout=timeout_s or self.timeout)
                    if r.status_code == 429:
                        delay = gate.on_rate_limited(_retry_after(r))
                        await asyncio.sleep(delay)
                        continue
                    if r.status_code >= 500:
                        gate.on_error()
                        raise OmniRouteError(f"gateway {r.status_code}")
                    _raise_gateway_error(r)
                    data = r.json()
                    actual = int((data.get("usage") or {}).get("total_tokens") or est)
                    await gate.settle(est, actual)
                    gate.on_success()
                    self._cb_ok(cap)
                    data["_latency_ms"] = int((time.monotonic() - t0) * 1000)
                    data["_cost_usd"] = data.get("_cost_usd", 0.0)
                    RESPONSE_CACHE.put(messages, capability, max_tokens, cache_key_extra, data)
                    return data
                except AppError:
                    raise                                     # quota/limit errors are terminal
                except Exception as e:
                    last = e
                    gate.on_error()
                    await gate.settle(est, 0)
                    backoff = min(8.0, 0.25 * (2 ** attempt)) * (0.7 + random.random() * 0.6)
                    await asyncio.sleep(backoff)              # jitter: don't synchronise retries
            self._cb_fail(cap)
        raise OmniRouteError(f"all capabilities failed: {redact(str(last))[:200]}")


def _retry_after(r) -> float | None:
    for h in ("retry-after", "x-ratelimit-reset-requests", "x-ratelimit-reset-tokens"):
        v = r.headers.get(h)
        if not v:
            continue
        try:
            return max(0.0, float(re.sub(r"[^0-9.]", "", v) or 0))
        except Exception:
            continue
    return None


def _raise_gateway_error(r: "httpx.Response") -> None:
    if r.status_code < 400:
        return
    try:
        body = r.json()
        error = body.get("error") if isinstance(body, dict) else None
        detail = error.get("message") if isinstance(error, dict) else None
        detail = detail or (str(body)[:400] if body else "")
    except Exception:
        detail = (r.text or "")[:400]
    raise OmniRouteError(
        f"gateway returned HTTP {r.status_code}: {redact(detail) or '(no detail)'}"
    )


class ResponseCache:
    """Exact-prompt cache. Identical sub-prompts recur constantly across a 480-agent
    DAG (same goal, same understand/plan scaffolding), and a cache hit is free."""

    def __init__(self, max_items: int = 2048, ttl_s: float = 900.0):
        self.max_items, self.ttl_s = max_items, ttl_s
        self._d: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self.hits = self.misses = 0

    @staticmethod
    def _key(messages, capability, max_tokens, extra) -> str:
        blob = json.dumps([messages, capability, max_tokens, extra], sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def get(self, messages, capability, max_tokens, extra) -> dict | None:
        if not CACHE_ENABLED:
            return None
        k = self._key(messages, capability, max_tokens, extra)
        hit = self._d.get(k)
        if hit and time.time() - hit[0] < self.ttl_s:
            self._d.move_to_end(k)
            self.hits += 1
            out = dict(hit[1])
            out["_cached"] = True
            return out
        if hit:
            self._d.pop(k, None)
        self.misses += 1
        return None

    def put(self, messages, capability, max_tokens, extra, value: dict) -> None:
        if not CACHE_ENABLED:
            return
        k = self._key(messages, capability, max_tokens, extra)
        self._d[k] = (time.time(), value)
        self._d.move_to_end(k)
        while len(self._d) > self.max_items:
            self._d.popitem(last=False)

    def stats(self) -> dict:
        total = self.hits + self.misses
        return {"hits": self.hits, "misses": self.misses, "size": len(self._d),
                "hit_rate": round(self.hits / total, 3) if total else 0.0}


CACHE_ENABLED = _env("RESPONSE_CACHE", "true").lower() in ("1", "true", "yes")
RESPONSE_CACHE = ResponseCache(int(_env("RESPONSE_CACHE_ITEMS", "2048")),
                               float(_env("RESPONSE_CACHE_TTL_S", "900")))


CAPABILITY_MAP = {
    "reasoning": ["reasoning", "general", "long-context"],
    "code": ["code", "reasoning", "general"],
    "vision": ["vision", "general"],
    "longctx": ["long-context", "general"],
    "cheap": ["general", "cheap"],
    "general": ["general"],
}

DEFAULT_PROVIDERS = [
    ("openai", "OpenAI", "https://api.openai.com"),
    ("anthropic", "Anthropic", "https://api.anthropic.com"),
    ("gemini", "Google Gemini", "https://generativelanguage.googleapis.com"),
    ("nvidia", "NVIDIA NIM", "https://integrate.api.nvidia.com"),
    ("deepseek", "DeepSeek", "https://api.deepseek.com"),
    ("mistral", "Mistral", "https://api.mistral.ai"),
    ("groq", "Groq", "https://api.groq.com"),
    ("openrouter", "OpenRouter", "https://openrouter.ai/api"),
]

# Groq retired these IDs on 2026-08-16. Keep old saved model selections usable
# after a deployment/database refresh instead of sending a known-invalid ID.
PROVIDER_MODEL_ALIASES: dict[str, dict[str, str]] = {
    "groq": {
        "llama-3.1-8b-instant": "openai/gpt-oss-20b",
        "llama-3.3-70b-versatile": "openai/gpt-oss-120b",
    },
}

# Used only if a provider's model-list endpoint is temporarily incomplete.
# These are chat-capable production IDs, unlike audio/moderation entries that
# some providers include in the same catalogue.
PROVIDER_CHAT_FALLBACKS = {
    "groq": "openai/gpt-oss-20b",
}


def is_deprecated_provider_model(provider: str, model: str | None) -> bool:
    return bool(model and model in PROVIDER_MODEL_ALIASES.get((provider or "").lower(), {}))


def _looks_like_model_error(message: str) -> bool:
    value = (message or "").lower()
    return "model" in value and any(word in value for word in (
        "not found", "not available", "deprecated", "decommission", "does not exist",
        "unsupported", "invalid",
    ))


def normalize_provider_model(provider: str, model: str) -> str:
    return PROVIDER_MODEL_ALIASES.get((provider or "").lower(), {}).get(model, model)


def provider_chat_fallback(provider: str, exclude: set[str] | None = None) -> str | None:
    model = PROVIDER_CHAT_FALLBACKS.get((provider or "").lower())
    return model if model and model not in (exclude or set()) else None


def is_chat_model_record(model: dict) -> bool:
    non_chat = {"embedding", "rerank", "audio", "image", "moderation"}
    return not any(tag in non_chat for tag in (model.get("capability_tags") or []))


# =====================================================================================
# 7b. Shared HTTP + direct provider model discovery (BYOK -> catalogue, automatically)
# =====================================================================================
_HTTP: httpx.AsyncClient | None = None


def http() -> httpx.AsyncClient:
    """One pooled client for the whole process.

    Opening a fresh AsyncClient per request costs a DNS lookup plus a TLS handshake
    every single time — typically 80-250ms of pure latency on each model call.
    """
    global _HTTP
    if _HTTP is None or _HTTP.is_closed:
        _HTTP = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=float(S.OMNIROUTE_TIMEOUT_S), write=10.0, pool=5.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=40,
                                keepalive_expiry=60.0),
            follow_redirects=True,
            headers={"User-Agent": f"{S.APP_NAME}/1.0"},
        )
    return _HTTP


async def close_http() -> None:
    global _HTTP
    if _HTTP is not None and not _HTTP.is_closed:
        await _HTTP.aclose()
    _HTTP = None


# provider -> (models path, auth style, response key)
PROVIDER_DISCOVERY: dict[str, dict] = {
    "openai":     dict(path="/v1/models", auth="bearer", key="data"),
    "anthropic":  dict(path="/v1/models", auth="x-api-key", key="data"),
    "gemini":     dict(path="/v1beta/models", auth="query", key="models"),
    "groq":       dict(path="/openai/v1/models", auth="bearer", key="data"),
    "mistral":    dict(path="/v1/models", auth="bearer", key="data"),
    "deepseek":   dict(path="/models", auth="bearer", key="data"),
    "nvidia":     dict(path="/v1/models", auth="bearer", key="data"),
    "openrouter": dict(path="/v1/models", auth="bearer", key="data"),
    "together":   dict(path="/v1/models", auth="bearer", key="data"),
    "cohere":     dict(path="/v1/models", auth="bearer", key="models"),
    "_default":   dict(path="/v1/models", auth="bearer", key="data"),
}

# substring -> capability tag. Ordered: first match wins for the primary tag.
CAPABILITY_HINTS: tuple[tuple[str, str], ...] = (
    ("embed", "embedding"), ("rerank", "rerank"), ("whisper", "audio"), ("tts", "audio"),
    ("dall-e", "image"), ("imagen", "image"), ("flux", "image"), ("stable-diffusion", "image"),
    ("prompt-guard", "moderation"), ("promptguard", "moderation"),
    ("llama-guard", "moderation"), ("guard-4", "moderation"), ("safeguard", "moderation"),
    ("coder", "code"), ("code", "code"), ("devstral", "code"), ("codestral", "code"),
    ("vision", "vision"), ("-vl", "vision"), ("pixtral", "vision"), ("llava", "vision"),
    ("reasoner", "reasoning"), ("thinking", "reasoning"), ("-r1", "reasoning"),
    ("o1", "reasoning"), ("o3", "reasoning"), ("o4", "reasoning"), ("opus", "reasoning"),
    ("sonnet", "reasoning"), ("gpt-4", "reasoning"), ("gpt-5", "reasoning"),
    ("pro", "reasoning"), ("large", "reasoning"), ("70b", "reasoning"), ("405b", "reasoning"),
    ("mini", "cheap"), ("flash", "cheap"), ("haiku", "cheap"), ("small", "cheap"),
    ("8b", "cheap"), ("7b", "cheap"), ("nano", "cheap"), ("lite", "cheap"),
)


def infer_capabilities(model_id: str, context_window: int = 0) -> list[str]:
    mid = (model_id or "").lower()
    tags: list[str] = []
    for needle, tag in CAPABILITY_HINTS:
        if needle in mid and tag not in tags:
            tags.append(tag)
    if not tags:
        tags = ["general"]
    if tags[0] in ("embedding", "rerank", "audio", "image", "moderation"):
        return tags                       # not a chat model, no general tag
    if "general" not in tags:
        tags.append("general")
    if context_window >= 200000 and "long-context" not in tags:
        tags.append("long-context")
    return tags


def _tier_for(tags: list[str], cost_in: float) -> str:
    if "cheap" in tags or (cost_in and cost_in < 0.0005):
        return "cheap"
    if "reasoning" in tags or (cost_in and cost_in >= 0.003):
        return "premium"
    return "standard"


def _normalise_models(provider: str, payload: Any) -> list[dict]:
    """Every provider returns a slightly different shape. Flatten them all."""
    spec = PROVIDER_DISCOVERY.get(provider, PROVIDER_DISCOVERY["_default"])
    if isinstance(payload, dict):
        rows = payload.get(spec["key"]) or payload.get("data") or payload.get("models") or []
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    out: list[dict] = []
    for r in rows:
        if isinstance(r, str):
            r = {"id": r}
        if not isinstance(r, dict):
            continue
        mid = r.get("id") or r.get("name") or r.get("model") or ""
        if not mid:
            continue
        if provider == "gemini" and mid.startswith("models/"):
            mid = mid.split("/", 1)[1]
        ctx = int(r.get("context_length") or r.get("context_window")
                  or r.get("inputTokenLimit") or r.get("max_input_tokens") or 0)
        pricing = r.get("pricing") or {}
        try:
            cin = float(pricing.get("prompt", 0) or 0) * 1000
            cout = float(pricing.get("completion", 0) or 0) * 1000
        except (TypeError, ValueError):
            cin = cout = 0.0
        # Gemini exposes which methods a model supports; skip non-chat ones
        methods = r.get("supportedGenerationMethods")
        if methods and not any("generateContent" in m or "chat" in m.lower() for m in methods):
            continue
        tags = infer_capabilities(mid, ctx)
        out.append({
            "model_id": mid, "provider": provider, "capability_tags": tags,
            "context_window": ctx or 128000, "cost_in_per_1k": round(cin, 6),
            "cost_out_per_1k": round(cout, 6), "tier": _tier_for(tags, cin),
            "display_name": r.get("display_name") or r.get("name") or mid,
        })
    # stable, de-duplicated
    seen, uniq = set(), []
    for m in sorted(out, key=lambda x: x["model_id"]):
        if m["model_id"] not in seen:
            seen.add(m["model_id"])
            uniq.append(m)
    return uniq


async def discover_models_for_key(provider: str, api_key: str, base_url: str = "",
                                  timeout_s: float = 15.0) -> dict:
    """Call the provider's own model-listing endpoint with the user's key.

    Returns {ok, models, error}. The key is used in headers only — never logged,
    never echoed back, never written to the event stream.
    """
    provider = (provider or "").lower()
    spec = PROVIDER_DISCOVERY.get(provider, PROVIDER_DISCOVERY["_default"])
    base = (base_url or dict((p[0], p[2]) for p in DEFAULT_PROVIDERS).get(provider, "")).rstrip("/")
    if not base:
        return {"ok": False, "models": [], "error": f"no base url known for provider '{provider}'"}

    url = base + spec["path"]
    headers: dict[str, str] = {"Accept": "application/json"}
    params: dict[str, str] = {}
    if spec["auth"] == "bearer":
        headers["Authorization"] = f"Bearer {api_key}"
    elif spec["auth"] == "x-api-key":
        headers["x-api-key"] = api_key
        headers["anthropic-version"] = _env("ANTHROPIC_VERSION", "2023-06-01")
    elif spec["auth"] == "query":
        params["key"] = api_key

    try:
        assert_url_allowed(url)                       # SSRF guard applies to BYOK too
        r = await http().get(url, headers=headers, params=params, timeout=timeout_s)
    except Exception as e:
        return {"ok": False, "models": [], "error": redact(str(e))[:200]}

    if r.status_code in (401, 403):
        return {"ok": False, "models": [], "error": "provider rejected the key (invalid or insufficient scope)"}
    if r.status_code == 429:
        return {"ok": False, "models": [], "error": "provider rate-limited the discovery call; try again shortly"}
    if r.status_code >= 400:
        return {"ok": False, "models": [], "error": f"provider returned HTTP {r.status_code}"}
    try:
        models = _normalise_models(provider, r.json())
    except Exception as e:
        return {"ok": False, "models": [], "error": f"unparseable model list: {redact(str(e))[:120]}"}
    return {"ok": True, "models": models, "error": ""}


# provider -> chat-completions path, derived from the discovery path (same host, the
# "list models" tail swapped for "create a completion"). Every provider below speaks
# the OpenAI chat-completions request/response shape natively.
_OPENAI_SHAPED = ("openai", "groq", "mistral", "deepseek", "nvidia", "openrouter", "together")


def _raise_provider_error(r: "httpx.Response") -> None:
    """Raise an error containing the provider's actual response detail.

    httpx's default HTTPStatusError only includes the status line and URL, which
    hides the useful reason from Groq (for example, a retired model ID).
    """
    if r.status_code < 400:
        return
    try:
        body = r.json()
        error = body.get("error") if isinstance(body, dict) else None
        detail = error.get("message") if isinstance(error, dict) else None
        detail = detail or (str(body)[:400] if body else "")
    except Exception:
        detail = (r.text or "")[:400]
    raise OmniRouteError(
        f"provider returned HTTP {r.status_code}: {redact(detail) or '(no detail)'}"
    )


async def direct_provider_complete(provider: str, api_key: str, messages: list[dict], model: str,
                                   temperature: float = 0.2, max_tokens: int = 2000,
                                   timeout_s: float = 30.0) -> dict:
    """Call a provider's own chat endpoint directly with the user's BYOK key.

    This is what actually fulfils the BYOK promise ("Maximus calls that provider's
    own model endpoint") for real conversational replies -- discovery already did
    this to validate the key; completion needs to do the same thing, not go through
    OMNIROUTE, which is a separate gateway process that most local runs never start.
    Always returns an OpenAI-shaped {"choices":[{"message":{"content": ...}}], "usage": {...}}
    dict so every caller downstream can stay unchanged.
    """
    provider = (provider or "").lower()
    model = normalize_provider_model(provider, model)
    base = dict((p[0], p[2]) for p in DEFAULT_PROVIDERS).get(provider, "")
    if not base:
        raise OmniRouteError(f"no direct endpoint known for provider '{provider}'")

    if provider == "anthropic":
        system = "\n\n".join(m.get("content", "") for m in messages if m.get("role") == "system")
        convo = [{"role": m["role"], "content": m.get("content", "")}
                 for m in messages if m.get("role") in ("user", "assistant")] or [{"role": "user", "content": ""}]
        url = base + "/v1/messages"
        assert_url_allowed(url)
        headers = {"x-api-key": api_key, "anthropic-version": _env("ANTHROPIC_VERSION", "2023-06-01"),
                   "Content-Type": "application/json"}
        payload: dict[str, Any] = {"model": model, "max_tokens": max_tokens,
                                    "temperature": temperature, "messages": convo}
        if system:
            payload["system"] = system
        r = await http().post(url, headers=headers, json=payload, timeout=timeout_s)
        _raise_provider_error(r)
        data = r.json()
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        usage = data.get("usage") or {}
        return {"choices": [{"message": {"role": "assistant", "content": text}}],
                "usage": {"total_tokens": int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))}}

    if provider == "gemini":
        system = "\n\n".join(m.get("content", "") for m in messages if m.get("role") == "system")
        contents = [{"role": "model" if m.get("role") == "assistant" else "user",
                     "parts": [{"text": m.get("content", "")}]}
                    for m in messages if m.get("role") in ("user", "assistant")] \
            or [{"role": "user", "parts": [{"text": ""}]}]
        url = f"{base}/v1beta/models/{model}:generateContent"
        assert_url_allowed(url)
        payload = {"contents": contents,
                   "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens}}
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        r = await http().post(url, params={"key": api_key}, json=payload, timeout=timeout_s)
        _raise_provider_error(r)
        data = r.json()
        candidates = data.get("candidates") or [{}]
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts)
        usage_meta = data.get("usageMetadata") or {}
        return {"choices": [{"message": {"role": "assistant", "content": text}}],
                "usage": {"total_tokens": int(usage_meta.get("totalTokenCount", 0))}}

    if provider in _OPENAI_SHAPED:
        spec = PROVIDER_DISCOVERY.get(provider, PROVIDER_DISCOVERY["_default"])
        path = spec["path"]
        if path.endswith("models"):
            path = path[: -len("models")] + "chat/completions"
        url = base + path
        assert_url_allowed(url)
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {"model": model, "messages": messages, "temperature": temperature}
        # Groq now documents max_completion_tokens as the supported field and
        # uses it for the GPT-OSS replacements; keep other OpenAI-compatible
        # providers on their existing field for compatibility.
        payload["max_completion_tokens" if provider == "groq" else "max_tokens"] = max_tokens
        r = await http().post(url, headers=headers, json=payload, timeout=timeout_s)
        _raise_provider_error(r)
        return r.json()

    raise OmniRouteError(f"no direct chat-completions support for provider '{provider}'")


async def resolve_model_for_provider(provider: str, api_key: str, capability: str) -> str | None:
    """Pick a real model id for a direct call: prefer the already-discovered catalogue,
    fall back to a live discovery call so a freshly-added key works immediately."""
    models: list[dict] = []
    try:
        SF = session_factory()
        async with SF() as db:
            prov = (await db.execute(select(Provider).where(Provider.slug == provider))).scalars().first()
            if prov:
                rows = (await db.execute(
                    select(Model).where(Model.provider_id == prov.id, Model.enabled == True)  # noqa: E712
                )).scalars().all()
                models = [{"model_id": r.model_id, "capability_tags": r.capability_tags or [],
                           "cost_in_per_1k": r.cost_in_per_1k, "context_window": r.context_window,
                           "tier": r.tier} for r in rows]
    except Exception:
        models = []
    if not models:
        disc = await discover_models_for_key(provider, api_key)
        if disc.get("ok"):
            models = disc.get("models") or []
    models = [m for m in models if is_chat_model_record(m)]
    picked = pick_model(models, capability)
    if picked and not is_deprecated_provider_model(provider, picked["model_id"]):
        return picked["model_id"]

    # A persisted catalogue can outlive a provider's model. Refresh only when
    # the cached choice is retired, so normal requests do not pay a discovery
    # round trip while stale deployments recover automatically.
    disc = await discover_models_for_key(provider, api_key)
    if not disc.get("ok"):
        return (normalize_provider_model(provider, picked["model_id"]) if picked
                else provider_chat_fallback(provider))
    live_models = [m for m in (disc.get("models") or [])
                   if is_chat_model_record(m)
                   and not is_deprecated_provider_model(provider, m.get("model_id"))]
    picked = pick_model(live_models, capability)
    return picked["model_id"] if picked else provider_chat_fallback(provider)


async def resolve_live_model_for_provider(provider: str, api_key: str, capability: str,
                                          exclude: set[str] | None = None) -> str | None:
    """Select a current provider model after a cached model was rejected."""
    disc = await discover_models_for_key(provider, api_key)
    if not disc.get("ok"):
        return None
    excluded = exclude or set()
    live_models = [m for m in (disc.get("models") or [])
                   if m.get("model_id") not in excluded
                   and is_chat_model_record(m)
                   and not is_deprecated_provider_model(provider, m.get("model_id"))]
    picked = pick_model(live_models, capability)
    return picked["model_id"] if picked else provider_chat_fallback(provider, excluded)


async def persist_models(db: AsyncSession, provider_slug: str, models: list[dict]) -> int:
    """Upsert discovered models so routing can see them immediately."""
    prov = (await db.execute(select(Provider).where(Provider.slug == provider_slug))).scalars().first()
    if not prov:
        return 0
    existing = {m.model_id: m for m in
                (await db.execute(select(Model).where(Model.provider_id == prov.id))).scalars().all()}
    n = 0
    for m in models:
        row = existing.get(m["model_id"])
        if row:
            row.capability_tags = m["capability_tags"]
            row.context_window = m["context_window"]
            row.cost_in_per_1k = m["cost_in_per_1k"]
            row.cost_out_per_1k = m["cost_out_per_1k"]
            row.tier = m["tier"]
            row.enabled = True
        else:
            db.add(Model(provider_id=prov.id, model_id=m["model_id"],
                         capability_tags=m["capability_tags"], context_window=m["context_window"],
                         cost_in_per_1k=m["cost_in_per_1k"], cost_out_per_1k=m["cost_out_per_1k"],
                         tier=m["tier"], enabled=True))
        n += 1
    prov.status = "healthy"
    await db.commit()
    return n


def pick_model(models: list[dict], capability: str, budget_usd: float = 5.0) -> dict | None:
    """Choose the cheapest model that actually satisfies the requested capability."""
    if not models:
        return None
    wanted = CAPABILITY_MAP.get(capability, [capability, "general"])
    for cap in wanted:
        pool = [m for m in models if cap in (m.get("capability_tags") or [])]
        if not pool:
            continue
        # cheap-first routing; escalation is an explicit decision, not a default
        pool.sort(key=lambda m: (m.get("cost_in_per_1k", 0.0), -m.get("context_window", 0)))
        if budget_usd < 1.0:
            return pool[0]
        premium = [m for m in pool if m.get("tier") == "premium"]
        return (premium or pool)[0]
    return models[0]


async def seed_providers(db: AsyncSession) -> None:
    have = set((await db.execute(select(Provider.slug))).scalars().all())
    for slug, name, url in DEFAULT_PROVIDERS:
        if slug not in have:
            db.add(Provider(slug=slug, display_name=name, base_url=url, openai_compatible=True, status="unknown"))
    await db.commit()


async def sync_models(db: AsyncSession, discovered: list[dict]) -> int:
    prov_map = {p.slug: p.id for p in (await db.execute(select(Provider))).scalars().all()}
    n = 0
    for m in discovered:
        slug = str(m.get("provider", "openrouter"))
        if slug not in prov_map:
            p = Provider(slug=slug, display_name=slug.title(), base_url="", openai_compatible=True)
            db.add(p)
            await db.flush()
            prov_map[slug] = p.id
        mid = str(m.get("id", m.get("model", "unknown")))
        q = await db.execute(select(Model).where(Model.provider_id == prov_map[slug], Model.model_id == mid))
        if q.scalars().first() is None:
            db.add(Model(provider_id=prov_map[slug], model_id=mid,
                         capability_tags=m.get("capabilities", m.get("tags", ["general"])),
                         context_window=int(m.get("context", 128000)),
                         cost_in_per_1k=float(m.get("cost_in", 0)), cost_out_per_1k=float(m.get("cost_out", 0)),
                         tier=str(m.get("tier", "standard"))))
            n += 1
    await db.commit()
    return n


def estimate_cost(tokens_in: int, tokens_out: int, c_in: float, c_out: float) -> float:
    return tokens_in / 1000 * c_in + tokens_out / 1000 * c_out

# =====================================================================================
# 10. MEMORY — conversation/working/episodic/semantic/task/project/agent
# =====================================================================================
_WS: dict[str, dict] = {}


def embed(text: str, dim: int = 128) -> list[float]:
    vec = [0.0] * dim
    for tok in re.findall(r"\w+", (text or "").lower()):
        vec[int(hashlib.sha256(tok.encode()).hexdigest(), 16) % dim] += 1.0
    n = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / n for v in vec]


def _cos(a: list[float], b: list[float]) -> float:
    if not a or not b:
        return 0.0
    return sum(x * y for x, y in zip(a, b))


class MemoryManager:
    async def store(self, content: str, kind: str = "semantic", project_id: str | None = None,
                    task_id: str | None = None, agent_id: str | None = None,
                    user_id: str | None = None) -> str:
        SF = session_factory()
        async with SF() as db:
            m = Memory(project_id=project_id, task_id=task_id, agent_id=agent_id, user_id=user_id,
                       kind=kind, content=content[:8000], embedding=embed(content), summary=content[:280])
            db.add(m)
            await db.commit()
            return m.id

    async def recall(self, project_id: str, query: str, limit: int = 5) -> list[str]:
        SF = session_factory()
        q = embed(query)
        async with SF() as db:
            rows = (await db.execute(select(Memory).where(Memory.project_id == project_id).limit(200))).scalars().all()
            return [m.content for m in sorted(rows, key=lambda m: _cos(q, m.embedding or []), reverse=True)[:limit]]

    def working_set(self, task_id: str, key: str, value: str) -> None:
        _WS.setdefault(task_id, {})[key] = value

    def working_get(self, task_id: str) -> dict:
        return _WS.get(task_id, {})

    async def summarize_task(self, task_id: str, texts: list[str]) -> str:
        sents = re.split(r"(?<=[.!?])\s+", " ".join(texts)[:4000])
        return " ".join(sents[:5])

    def compress_context(self, snippets: list[str], max_chars: int = 6000) -> str:
        out, total = [], 0
        for s in snippets:
            if total + len(s) > max_chars:
                break
            out.append(s)
            total += len(s)
        return "\n---\n".join(out)


MEMORY = MemoryManager()

# =====================================================================================
# 11. TOOLS — universal interface, permission scopes enforced on every call
# =====================================================================================
@dataclass
class ToolResult:
    ok: bool
    output: Any = None
    error: str = ""


@dataclass
class Tool:
    name: str
    description: str
    scopes: list[str] = field(default_factory=list)
    schema: dict = field(default_factory=dict)

    async def run(self, args: dict, ctx: dict) -> ToolResult:
        raise NotImplementedError


class FilesystemTool(Tool):
    def __init__(self):
        super().__init__("filesystem", "Read/write project files (jailed)", ["fs:read", "fs:write"])

    async def run(self, args: dict, ctx: dict) -> ToolResult:
        root = data_dir() / "projects" / ctx.get("project_id", "default")
        root.mkdir(parents=True, exist_ok=True)
        try:
            op = args.get("op", "read")
            if op == "read":
                p = assert_path_inside(root, args.get("path", ""))
                return ToolResult(True, sanitize_tool_output(p.read_text(encoding="utf-8", errors="replace")))
            if op == "write":
                p = assert_path_inside(root, args.get("path", ""))
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(args.get("content", ""), encoding="utf-8")
                return ToolResult(True, {"path": str(p)})
            if op == "list":
                return ToolResult(True, [x.name for x in root.iterdir()])
            return ToolResult(False, error=f"unknown op {op}")
        except Exception as e:
            return ToolResult(False, error=str(e)[:500])


class FetchTool(Tool):
    def __init__(self):
        super().__init__("fetch", "HTTP GET with SSRF protection", ["net:fetch"])

    async def run(self, args: dict, ctx: dict) -> ToolResult:
        try:
            url = assert_url_allowed(args.get("url", ""))
            r = await http().get(url, headers=UA, timeout=20)
            return ToolResult(True, sanitize_tool_output(r.text[:15000]))
        except Exception as e:
            return ToolResult(False, error=str(e)[:500])


class SQLiteTool(Tool):
    def __init__(self):
        super().__init__("sqlite", "Query local sqlite files (SELECT only)", ["db:query"])

    async def run(self, args: dict, ctx: dict) -> ToolResult:
        try:
            dbp = assert_path_inside(data_dir(), args.get("db", "projects/default/app.db"))
            sql = args.get("sql", "SELECT 1").strip()
            if not sql.lower().startswith("select"):
                return ToolResult(False, error="only SELECT allowed without db:write scope")
            con = sqlite3.connect(str(dbp))
            rows = con.execute(sql).fetchmany(100)
            con.close()
            return ToolResult(True, rows)
        except Exception as e:
            return ToolResult(False, error=str(e)[:500])


class TerminalTool(Tool):
    def __init__(self):
        super().__init__("terminal", "Shell via sandbox (approval-gated)", ["exec:shell"])

    async def run(self, args: dict, ctx: dict) -> ToolResult:
        return ToolResult(False, error="use sandbox exec endpoint (approval required)")


# =====================================================================================
# 9b. Free tools — everything below works with no API key and no paid account
# =====================================================================================
FREE_ENDPOINTS = {
    "wikipedia": "https://{lang}.wikipedia.org/w/api.php",
    "wikidata": "https://www.wikidata.org/w/api.php",
    "arxiv": "https://export.arxiv.org/api/query",
    "open_meteo": "https://api.open-meteo.com/v1/forecast",
    "geocode": "https://geocoding-api.open-meteo.com/v1/search",
    "nominatim": "https://nominatim.openstreetmap.org/search",
    "duckduckgo": "https://html.duckduckgo.com/html/",
    "ddg_answer": "https://api.duckduckgo.com/",
    "searxng": _env("SEARXNG_URL", "").rstrip("/"),
    "hn": "https://hn.algolia.com/api/v1/search",
    "crossref": "https://api.crossref.org/works",
    "openlibrary": "https://openlibrary.org/search.json",
}

UA = {"User-Agent": f"{S.APP_NAME}/1.0 (self-hosted; open-source agent platform)"}


def _strip_html(html: str, limit: int = 4000) -> str:
    html = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html)
    html = re.sub(r"(?s)<[^>]+>", " ", html)
    html = (html.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
                .replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " "))
    return re.sub(r"\s+", " ", html).strip()[:limit]


class WebSearchTool(Tool):
    """Free web search. Uses a self-hosted SearXNG when configured, otherwise
    DuckDuckGo's public HTML endpoint. No API key, no paid tier, no tracking."""

    def __init__(self):
        super().__init__("web_search", "Free web search (SearXNG or DuckDuckGo)", ["net:fetch"],
                         {"query": "str", "max_results": "int"})

    async def run(self, args: dict, ctx: dict) -> ToolResult:
        q = str(args.get("query", "")).strip()
        if not q:
            return ToolResult(False, error="query is required")
        k = int(args.get("max_results", 6))
        try:
            if FREE_ENDPOINTS["searxng"]:
                r = await http().get(f"{FREE_ENDPOINTS['searxng']}/search",
                                     params={"q": q, "format": "json"}, headers=UA, timeout=20)
                r.raise_for_status()
                rows = r.json().get("results", [])[:k]
                out = [{"title": x.get("title"), "url": x.get("url"),
                        "snippet": (x.get("content") or "")[:300]} for x in rows]
                return ToolResult(True, {"engine": "searxng", "results": out})

            r = await http().post(FREE_ENDPOINTS["duckduckgo"], data={"q": q},
                                  headers=UA, timeout=20)
            r.raise_for_status()
            out = []
            for m in re.finditer(
                    r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>'
                    r'(?:.*?class="result__snippet"[^>]*>(.*?)</a>)?', r.text, re.S):
                url, title, snip = m.group(1), _strip_html(m.group(2), 200), _strip_html(m.group(3) or "", 300)
                if url.startswith("//duckduckgo.com/l/?uddg="):
                    url = urllib.parse.unquote(url.split("uddg=")[1].split("&")[0])
                out.append({"title": title, "url": url, "snippet": snip})
                if len(out) >= k:
                    break
            if not out:
                a = await http().get(FREE_ENDPOINTS["ddg_answer"],
                                     params={"q": q, "format": "json", "no_html": 1},
                                     headers=UA, timeout=15)
                j = a.json()
                if j.get("AbstractText"):
                    out = [{"title": j.get("Heading", q), "url": j.get("AbstractURL", ""),
                            "snippet": j["AbstractText"][:400]}]
            return ToolResult(True, {"engine": "duckduckgo", "results": out})
        except Exception as e:
            return ToolResult(False, error=redact(str(e))[:300])


class WikipediaTool(Tool):
    def __init__(self):
        super().__init__("wikipedia", "Wikipedia search and article extracts (free)", ["net:fetch"],
                         {"query": "str", "lang": "str"})

    async def run(self, args: dict, ctx: dict) -> ToolResult:
        q = str(args.get("query", "")).strip()
        lang = re.sub(r"[^a-z]", "", str(args.get("lang", "en")).lower()) or "en"
        if not q:
            return ToolResult(False, error="query is required")
        base = FREE_ENDPOINTS["wikipedia"].format(lang=lang)
        try:
            r = await http().get(base, headers=UA, timeout=20, params={
                "action": "query", "format": "json", "prop": "extracts", "generator": "search",
                "gsrsearch": q, "gsrlimit": 3, "exintro": 1, "explaintext": 1})
            r.raise_for_status()
            pages = (r.json().get("query") or {}).get("pages", {})
            out = [{"title": p.get("title"),
                    "extract": (p.get("extract") or "")[:2000],
                    "url": f"https://{lang}.wikipedia.org/?curid={p.get('pageid')}"}
                   for p in pages.values()]
            return ToolResult(True, {"results": out})
        except Exception as e:
            return ToolResult(False, error=redact(str(e))[:300])


class ArxivTool(Tool):
    def __init__(self):
        super().__init__("arxiv", "arXiv paper search (free)", ["net:fetch"],
                         {"query": "str", "max_results": "int"})

    async def run(self, args: dict, ctx: dict) -> ToolResult:
        q = str(args.get("query", "")).strip()
        if not q:
            return ToolResult(False, error="query is required")
        try:
            r = await http().get(FREE_ENDPOINTS["arxiv"], headers=UA, timeout=25, params={
                "search_query": f"all:{q}", "start": 0,
                "max_results": min(int(args.get("max_results", 5)), 20)})
            r.raise_for_status()
            out = []
            for entry in re.findall(r"(?s)<entry>(.*?)</entry>", r.text):
                def pick(tag):
                    m = re.search(rf"(?s)<{tag}>(.*?)</{tag}>", entry)
                    return _strip_html(m.group(1), 1200) if m else ""
                out.append({"title": pick("title"), "summary": pick("summary")[:800],
                            "published": pick("published"), "url": pick("id")})
            return ToolResult(True, {"results": out})
        except Exception as e:
            return ToolResult(False, error=redact(str(e))[:300])


class WeatherTool(Tool):
    def __init__(self):
        super().__init__("open_meteo", "Weather forecast via Open-Meteo (free, no key)",
                         ["net:fetch"], {"location": "str"})

    async def run(self, args: dict, ctx: dict) -> ToolResult:
        loc = str(args.get("location", "")).strip()
        lat, lon = args.get("latitude"), args.get("longitude")
        try:
            if lat is None or lon is None:
                if not loc:
                    return ToolResult(False, error="location or latitude/longitude required")
                g = await http().get(FREE_ENDPOINTS["geocode"], headers=UA, timeout=15,
                                     params={"name": loc, "count": 1})
                g.raise_for_status()
                res = (g.json().get("results") or [])
                if not res:
                    return ToolResult(False, error=f"could not geocode '{loc}'")
                lat, lon, loc = res[0]["latitude"], res[0]["longitude"], res[0]["name"]
            r = await http().get(FREE_ENDPOINTS["open_meteo"], headers=UA, timeout=15, params={
                "latitude": lat, "longitude": lon,
                "current": "temperature_2m,relative_humidity_2m,wind_speed_10m,weather_code",
                "daily": "temperature_2m_max,temperature_2m_min,precipitation_sum",
                "forecast_days": 3, "timezone": "auto"})
            r.raise_for_status()
            j = r.json()
            return ToolResult(True, {"location": loc, "latitude": lat, "longitude": lon,
                                     "current": j.get("current"), "daily": j.get("daily")})
        except Exception as e:
            return ToolResult(False, error=redact(str(e))[:300])


class GeocodeTool(Tool):
    def __init__(self):
        super().__init__("osm_geocode", "OpenStreetMap/Nominatim geocoding (free)", ["net:fetch"],
                         {"query": "str"})

    async def run(self, args: dict, ctx: dict) -> ToolResult:
        q = str(args.get("query", "")).strip()
        if not q:
            return ToolResult(False, error="query is required")
        try:
            r = await http().get(FREE_ENDPOINTS["nominatim"], headers=UA, timeout=20,
                                 params={"q": q, "format": "jsonv2", "limit": 5})
            r.raise_for_status()
            out = [{"name": x.get("display_name"), "lat": x.get("lat"), "lon": x.get("lon"),
                    "type": x.get("type")} for x in r.json()]
            return ToolResult(True, {"results": out})
        except Exception as e:
            return ToolResult(False, error=redact(str(e))[:300])


class ScholarTool(Tool):
    def __init__(self):
        super().__init__("crossref", "Academic metadata via Crossref (free)", ["net:fetch"],
                         {"query": "str"})

    async def run(self, args: dict, ctx: dict) -> ToolResult:
        q = str(args.get("query", "")).strip()
        try:
            r = await http().get(FREE_ENDPOINTS["crossref"], headers=UA, timeout=20,
                                 params={"query": q, "rows": 5})
            r.raise_for_status()
            items = (r.json().get("message") or {}).get("items", [])
            out = [{"title": (i.get("title") or [""])[0], "year":
                    ((i.get("issued") or {}).get("date-parts") or [[None]])[0][0],
                    "doi": i.get("DOI"), "type": i.get("type"),
                    "container": (i.get("container-title") or [""])[0]} for i in items]
            return ToolResult(True, {"results": out})
        except Exception as e:
            return ToolResult(False, error=redact(str(e))[:300])


class HackerNewsTool(Tool):
    def __init__(self):
        super().__init__("hackernews", "Hacker News search via Algolia (free)", ["net:fetch"],
                         {"query": "str"})

    async def run(self, args: dict, ctx: dict) -> ToolResult:
        try:
            r = await http().get(FREE_ENDPOINTS["hn"], headers=UA, timeout=20,
                                 params={"query": str(args.get("query", "")), "hitsPerPage": 8})
            r.raise_for_status()
            out = [{"title": h.get("title"), "url": h.get("url"), "points": h.get("points"),
                    "comments": h.get("num_comments"),
                    "hn_url": f"https://news.ycombinator.com/item?id={h.get('objectID')}"}
                   for h in r.json().get("hits", []) if h.get("title")]
            return ToolResult(True, {"results": out})
        except Exception as e:
            return ToolResult(False, error=redact(str(e))[:300])


class ToolManager:
    def __init__(self):
        self._tools: dict[str, Tool] = {}
        for t in (FilesystemTool(), FetchTool(), SQLiteTool(), TerminalTool(),
                  WebSearchTool(), WikipediaTool(), ArxivTool(), WeatherTool(),
                  GeocodeTool(), ScholarTool(), HackerNewsTool()):
            self._tools[t.name] = t

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        return self._tools[name]

    def list(self) -> list[Tool]:
        return list(self._tools.values())

    async def call(self, name: str, args: dict, ctx: dict, granted: list[str]) -> ToolResult:
        tool = self.get(name)
        missing = [s for s in tool.scopes if s not in granted]
        if missing:
            return ToolResult(False, error=f"permission denied, missing scopes: {missing}")
        return await tool.run(args, ctx)


TOOLS = ToolManager()

# =====================================================================================
# 12. MCP — server registry (custom + well-known defaults, disabled until enabled)
# =====================================================================================
DEFAULT_MCP_SERVERS = [
    ("filesystem", "stdio", "mcp-server-filesystem", ["fs:read", "fs:write"]),
    ("fetch", "stdio", "mcp-server-fetch", ["net:fetch"]),
    ("git", "stdio", "mcp-server-git", ["vcs:read", "vcs:write"]),
    ("github", "stdio", "mcp-server-github", ["vcs:read", "issues:write"]),
    ("sqlite", "stdio", "mcp-server-sqlite", ["db:query"]),
    ("memory", "stdio", "mcp-server-memory", ["memory:read", "memory:write"]),
    ("wikipedia", "http", "https://mcp.wikimedia.org", ["net:fetch", "kb:read"]),
    ("arxiv", "http", "https://mcp.arxiv.org", ["net:fetch", "kb:read"]),
    ("open-meteo", "http", "https://api.open-meteo.com", ["net:fetch", "geo:weather"]),
    ("nominatim", "http", "https://nominatim.openstreetmap.org", ["net:fetch", "geo:read"]),
    ("playwright", "stdio", "mcp-server-playwright", ["browser:control"]),
]


async def seed_mcp_servers(project_id: str | None = None) -> int:
    SF = session_factory()
    async with SF() as db:
        have = set((await db.execute(select(MCPServer.name))).scalars().all())
        n = 0
        for name, transport, cmd, scopes in DEFAULT_MCP_SERVERS:
            if name not in have:
                db.add(MCPServer(project_id=project_id, name=name, transport=transport,
                                 url_or_cmd=cmd, allowed_scopes=scopes, enabled=False))
                n += 1
        await db.commit()
        return n


async def list_servers() -> list[dict]:
    SF = session_factory()
    async with SF() as db:
        rows = (await db.execute(select(MCPServer))).scalars().all()
        return [{"id": r.id, "name": r.name, "transport": r.transport, "url_or_cmd": r.url_or_cmd,
                 "allowed_scopes": r.allowed_scopes, "enabled": r.enabled} for r in rows]

# =====================================================================================
# 13. SANDBOX — local (default) + mock + docker/e2b stubs. Approval always required.
# =====================================================================================
class ExecResult(dict):
    pass


# =====================================================================================
# 10. Local runtime — the user's own machine is the isolation boundary
# =====================================================================================
# No E2B. No Docker. No cloud. Code runs here, in a jailed working directory, with
# the network cut off and hard resource ceilings. Isolation is layered, and the layers
# that are actually active are reported honestly via /v1/sandboxes/capabilities.
try:
    import resource
except ImportError:  # Windows does not expose POSIX resource limits.
    resource = None
import signal

NET_KILL_ENV = {
    "http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
    "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9",
    "ALL_PROXY": "socks5://127.0.0.1:9", "all_proxy": "socks5://127.0.0.1:9",
    "no_proxy": "", "NO_PROXY": "",
    # stop package managers from phoning home even if a net namespace is unavailable
    "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "NPM_CONFIG_OFFLINE": "true", "NPM_CONFIG_REGISTRY": "http://127.0.0.1:9",
    "GIT_TERMINAL_PROMPT": "0", "MAXIMUS_SANDBOX": "1",
}


def _probe(script: str, timeout: float = 8.0) -> bool:
    try:
        p = subprocess.run([UNSHARE_BIN, "-rmn", "--fork", "--pid", "/bin/sh", "-c", script],
                           capture_output=True, timeout=timeout)
        return p.returncode == 0 and b"PROBE_OK" in p.stdout
    except Exception:
        return False


def _detect_isolation() -> str:
    """Pick the strongest isolation this machine can actually provide. No guessing."""
    if sys.platform != "linux" or shutil.which("unshare") is None:
        return "none"
    probe_dir = Path(tempfile.mkdtemp(prefix="maximus-probe-"))
    try:
        for d in ("usr", "bin", "lib", "lib64", "etc", "proc", "tmp", "dev", "work"):
            (probe_dir / d).mkdir(parents=True, exist_ok=True)
        script = _jail_script(probe_dir, probe_dir / "work", ["/bin/sh", "-c", "echo PROBE_OK"])
        if _probe(script):
            return "chroot_ns"           # filesystem + network + pid isolation
    except Exception:
        pass
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)
    try:
        p = subprocess.run([UNSHARE_BIN, "-rn", "true"], capture_output=True, timeout=5)
        if p.returncode == 0:
            return "netns"               # network only; host filesystem still visible
    except Exception:
        pass
    return "none"


def _bin(name: str, *fallbacks: str) -> str:
    p = shutil.which(name)
    if p:
        return p
    for f in fallbacks:
        if Path(f).exists():
            return f
    return name


# absolute paths: the sandbox runs with a scrubbed PATH that excludes sbin
CHROOT_BIN = _bin("chroot", "/usr/sbin/chroot", "/sbin/chroot")
MOUNT_BIN = _bin("mount", "/usr/bin/mount", "/bin/mount")
UNSHARE_BIN = _bin("unshare", "/usr/bin/unshare", "/bin/unshare")

RO_BINDS = ("usr", "bin", "sbin", "lib", "lib64", "lib32")
DEV_NODES = ("null", "zero", "full", "urandom", "random", "tty")


def _jail_script(jail: Path, work: Path, argv: list[str]) -> str:
    """Build the mount + chroot script. Read-only system, writable /work only."""
    j = shlex.quote(str(jail))
    w = shlex.quote(str(work))
    inner = " ".join(shlex.quote(a) for a in argv)
    m = shlex.quote(MOUNT_BIN)
    lines = ["set -e"]
    for d in RO_BINDS:
        lines.append(f'if [ -d /{d} ]; then mkdir -p {j}/{d}; {m} --bind /{d} {j}/{d}; '
                     f'{m} -o remount,ro,bind {j}/{d}; fi')
    lines.append(f'mkdir -p {j}/proc {j}/tmp {j}/dev {j}/etc {j}/work')
    lines.append(f'{m} -t proc proc {j}/proc 2>/dev/null || true')
    lines.append(f'{m} -t tmpfs -o size=64m,mode=1777 tmpfs {j}/tmp')
    for f in DEV_NODES:
        lines.append(f'if [ -e /dev/{f} ]; then touch {j}/dev/{f} 2>/dev/null || true; '
                     f'{m} --bind /dev/{f} {j}/dev/{f} 2>/dev/null || true; fi')
    lines.append(f'{m} --bind {w} {j}/work')
    # a minimal passwd so tools that look up the current uid do not fail
    lines.append(f'printf "sandbox:x:65534:65534:sandbox:/work:/bin/sh\n" > {j}/etc/passwd 2>/dev/null || true')
    lines.append(f'exec {shlex.quote(CHROOT_BIN)} {j} /bin/sh -c "cd /work && exec {inner}"')
    return "\n".join(lines)


ISOLATION_MODE: str = _detect_isolation()
STRICT_ISOLATION = _env("STRICT_ISOLATION", "true").lower() in ("1", "true", "yes")


def isolation_report() -> dict:
    mode = ISOLATION_MODE
    layers = {
        "workspace_jail": True,
        "filesystem_jail": mode == "chroot_ns",
        "network_namespace": mode in ("chroot_ns", "netns"),
        "pid_namespace": mode == "chroot_ns",
        "readonly_system": mode == "chroot_ns",
        "proxy_blackhole": True,
        "env_scrubbed": True,
        "resource_limits": sys.platform != "win32",
        "process_group_kill": sys.platform != "win32",
        "explicit_approval_required": True,
    }
    notes = {
        "chroot_ns": ("Full local jail: the process runs in its own mount, network and PID "
                      "namespaces, chrooted to a read-only system with only its workspace "
                      "writable. It cannot see host files and has no route off the machine."),
        "netns": ("Network is namespace-isolated, but a filesystem jail could not be built, so "
                  "host files remain readable. Install util-linux and enable unprivileged user "
                  "namespaces for the full jail."),
        "none": ("No kernel isolation available on this platform. Egress is blocked best-effort "
                 "via proxy blackhole and a scrubbed environment, which determined code can "
                 "bypass. Leave STRICT_ISOLATION=true to refuse execution instead."),
    }
    return {
        "adapter": "local", "mode": mode, "layers": layers,
        "network_egress": "blocked (kernel namespace)" if mode in ("chroot_ns", "netns")
                          else "blocked (best-effort)",
        "filesystem": "jailed to workspace" if mode == "chroot_ns" else "host filesystem visible",
        "strict_mode": STRICT_ISOLATION,
        "hard_guarantee": mode == "chroot_ns",
        "remote_execution": "never — all execution is local to this machine",
        "note": notes[mode],
    }


class ExecLimits:
    cpu_seconds = int(_env("SANDBOX_CPU_SECONDS", "30"))
    memory_mb = int(_env("SANDBOX_MEMORY_MB", "512"))
    file_size_mb = int(_env("SANDBOX_FILE_SIZE_MB", "32"))
    max_processes = int(_env("SANDBOX_MAX_PROCESSES", "64"))
    max_open_files = int(_env("SANDBOX_MAX_OPEN_FILES", "256"))
    wall_seconds = int(_env("SANDBOX_WALL_SECONDS", "60"))
    max_output = int(_env("SANDBOX_MAX_OUTPUT", "20000"))


def _apply_rlimits() -> None:  # runs in the child, after fork, before exec
    if resource is None:
        return
    try:
        os.setsid()
    except Exception:
        pass
    lim = ExecLimits
    for what, soft in (
        (resource.RLIMIT_CPU, lim.cpu_seconds),
        (resource.RLIMIT_AS, lim.memory_mb * 1024 * 1024),
        (resource.RLIMIT_FSIZE, lim.file_size_mb * 1024 * 1024),
        (resource.RLIMIT_NPROC, lim.max_processes),
        (resource.RLIMIT_NOFILE, lim.max_open_files),
        (resource.RLIMIT_CORE, 0),
    ):
        try:
            resource.setrlimit(what, (soft, soft))
        except (ValueError, OSError):
            pass


def _clean_env(workdir: Path) -> dict[str, str]:
    """Nothing from the host environment leaks in — especially not API keys."""
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(workdir),
        "TMPDIR": str(workdir / ".tmp"),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONNOUSERSITE": "1",
    }
    env.update(NET_KILL_ENV)
    return env


class LocalRuntime:
    """The only execution backend. Runs on this machine, isolated, never remote."""

    name = "local"

    def __init__(self) -> None:
        self.root = Path(S.ALLOWED_SANDBOX_ROOT)
        self.root.mkdir(parents=True, exist_ok=True)
        self.boxes: dict[str, Path] = {}

    def _workdir(self, box_id: str) -> Path:
        p = self.boxes.get(box_id)
        if p is None:
            p = assert_path_inside(self.root, box_id)
        p.mkdir(parents=True, exist_ok=True)
        (p / ".tmp").mkdir(exist_ok=True)
        return p

    async def create(self, task_id: str) -> str:
        bid = f"{(task_id or 'adhoc')[:40]}-{uuid.uuid4().hex[:8]}"
        p = self.root / bid
        p.mkdir(parents=True, exist_ok=True)
        (p / ".tmp").mkdir(exist_ok=True)
        self.boxes[bid] = p
        return bid

    async def exec(self, box_id: str, language: str, code: str, command: str,
                   approve: bool) -> ExecResult:
        # Generated or downloaded code never runs on its own.
        if not approve:
            return ExecResult({"ok": False, "error": "explicit approval required (approve_generated_code=true)",
                               "isolation": isolation_report()["network_egress"]})
        if STRICT_ISOLATION and ISOLATION_MODE != "chroot_ns":
            return ExecResult({"ok": False,
                               "error": "strict isolation is on but this machine cannot provide a full "
                                        "local jail (needs unshare + unprivileged user namespaces). "
                                        "Refusing to execute. Set STRICT_ISOLATION=false to accept the "
                                        "weaker guarantee described in /v1/sandboxes/capabilities.",
                               "isolation": isolation_report()})
        try:
            box = self._workdir(box_id)
        except Exception as e:
            return ExecResult({"ok": False, "error": f"invalid workspace: {redact(str(e))[:160]}"})

        if language == "shell":
            try:
                assert_command_allowed(command)
            except Exception as e:
                return ExecResult({"ok": False, "error": str(e)[:200]})
            argv = ["/bin/sh", "-c", command]
        elif language == "python":
            (box / "main.py").write_text(code, encoding="utf-8")
            argv = ["/usr/bin/python3" if ISOLATION_MODE == "chroot_ns" else (sys.executable or "python3"),
                    "-I", "-S", "main.py"]
        elif language in ("javascript", "node"):
            if shutil.which("node") is None:
                return ExecResult({"ok": False, "error": "node is not installed on this machine"})
            (box / "main.js").write_text(code, encoding="utf-8")
            argv = ["node", "main.js"]
        else:
            return ExecResult({"ok": False, "error": f"unsupported language {language}"})

        if ISOLATION_MODE == "chroot_ns":
            jail = box / ".jail"
            jail.mkdir(parents=True, exist_ok=True)
            argv = [UNSHARE_BIN, "-rmn", "--fork", "--pid", "/bin/sh", "-c",
                    _jail_script(jail, box, argv)]
        elif ISOLATION_MODE == "netns":
            argv = [UNSHARE_BIN, "-rn"] + argv
        t0 = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, cwd=str(box), env=_clean_env(box),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                preexec_fn=_apply_rlimits if sys.platform != "win32" else None,
            )
        except Exception as e:
            return ExecResult({"ok": False, "error": f"spawn failed: {redact(str(e))[:200]}"})

        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=ExecLimits.wall_seconds)
        except asyncio.TimeoutError:
            self._kill_tree(proc)
            return ExecResult({"ok": False, "error": f"timeout after {ExecLimits.wall_seconds}s",
                               "elapsed_ms": int((time.monotonic() - t0) * 1000)})
        text = sanitize_tool_output(out.decode(errors="replace"), ExecLimits.max_output)
        return ExecResult({
            "ok": proc.returncode == 0, "exit": proc.returncode,
            "output": text, "elapsed_ms": int((time.monotonic() - t0) * 1000),
            "isolation_mode": ISOLATION_MODE,
        })

    @staticmethod
    def _kill_tree(proc) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    async def destroy(self, box_id: str) -> None:
        p = self.boxes.pop(box_id, None) or (self.root / box_id)
        try:
            target = assert_path_inside(self.root, str(p))
        except Exception:
            return
        if target.exists():
            shutil.rmtree(str(target), ignore_errors=True)


_RUNTIME = LocalRuntime()


def get_sandbox() -> LocalRuntime:
    """There is exactly one execution backend, and it is local."""
    return _RUNTIME


# =====================================================================================
# 14. VERIFICATION — factual/code/test/security/quality/completion + critic repair loop
# =====================================================================================
def verify_factual(output: str) -> dict:
    issues = []
    if re.search(r"(?i)\b(always|never|guaranteed|100%)\b", output or ""):
        issues.append("absolute claim without citation")
    return {"pass": not issues, "issues": issues}


def verify_code(output: str) -> dict:
    issues = []
    if "TODO" in (output or ""):
        issues.append("contains TODO markers")
    if re.search(r"(?i)(rm -rf /|eval\(.*input|password\s*=\s*['\"][^'\"]+)", output or ""):
        issues.append("suspicious/dangerous code pattern")
    return {"pass": not issues, "issues": issues}


def verify_tests(test_report: dict | None) -> dict:
    if not test_report:
        return {"pass": True, "issues": [], "note": "no test report attached"}
    failed = test_report.get("failed", 0)
    return {"pass": failed == 0, "issues": [] if failed == 0 else [f"{failed} tests failed"]}


def verify_security(output: str) -> dict:
    issues = []
    if re.search(r"(?i)(sk-[A-Za-z0-9]|api[_-]?key\s*[:=])", output or ""):
        issues.append("possible secret leak in output")
    return {"pass": not issues, "issues": issues}


def verify_quality(output: str) -> dict:
    if len(output or "") < 50:
        return {"pass": False, "issues": ["output too short"]}
    return {"pass": True, "issues": []}


STRATEGIES = {
    "factual": [verify_factual, verify_quality, verify_security],
    "code": [verify_code, verify_security, verify_quality],
    "tests": [verify_tests, verify_quality],
    "security": [verify_security, verify_code],
    "quality": [verify_quality, verify_security],
    "completion": [verify_quality],
}


def run_verification(strategy: str, output: str, test_report: dict | None = None) -> dict:
    checks = STRATEGIES.get(strategy, STRATEGIES["quality"])
    results = []
    for fn in checks:
        try:
            r = fn(test_report) if fn is verify_tests else fn(output)
        except Exception as e:
            r = {"pass": False, "issues": [str(e)[:200]]}
        results.append({"check": fn.__name__, **r})
    passed = all(r["pass"] for r in results)
    return {"strategy": strategy, "pass": passed, "checks": results,
            "verdict": "accept" if passed else "reject-repair"}

# =====================================================================================
# 15. WORKER — local SQLite-backed queue + asyncio DAG orchestration (no Redis)
# =====================================================================================
_emit_listeners: dict[str, list[asyncio.Queue]] = {}


async def emit(task_id: str, run_id: str | None, typ: str, payload: dict) -> None:
    SF = session_factory()
    try:
        async with SF() as db:
            db.add(TaskEvent(task_id=task_id, run_id=None, type=typ,
                             payload={k: (redact(v) if isinstance(v, str) else v) for k, v in payload.items()}))
            await db.commit()
    except Exception as e:
        log.warning("emit persist failed: %s", e)
    for q in _emit_listeners.get(task_id, []):
        await q.put({"type": typ, "run_id": run_id, "payload": payload, "at": time.time()})


def subscribe(task_id: str) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue()
    _emit_listeners.setdefault(task_id, []).append(q)
    return q


def unsubscribe(task_id: str, q: asyncio.Queue) -> None:
    if q in _emit_listeners.get(task_id, []):
        _emit_listeners[task_id].remove(q)


async def _perf_map() -> dict[str, float]:
    SF = session_factory()
    async with SF() as db:
        rows = (await db.execute(select(Agent))).scalars().all()
        return {r.slug: (r.performance_score or 0.5) for r in rows}


async def execute_task(task_id: str) -> None:
    SF = session_factory()
    async with SF() as db:
        task = await db.get(Task, task_id)
        if not task or task.status in ("cancelled", "completed"):
            return
        task.status = "running"
        await db.commit()
        goal, project_id, user_id = task.goal, task.project_id, task.user_id
        budget_tokens, budget_usd = task.budget_tokens, task.budget_usd
        dag = dict(task.dag or {})

    await emit(task_id, None, "planning", {"goal": goal[:300]})

    if not dag.get("nodes"):
        plan = route_goal(goal, await _perf_map(), budget_tokens, budget_usd)
        dag = plan_to_dag(plan)
        async with SF() as db:
            task = await db.get(Task, task_id)
            assert task is not None
            task.dag = dag
            await db.commit()
        for st in plan.steps:
            await emit(task_id, None, "agent_selected", {"agent": st.agent_id, "node": st.node_id})
            await emit(task_id, None, "task_created", {"node": st.node_id, "depends_on": st.depends_on})

    omni = OmniRouteClient()
    provider_key, provider_slug = await provider_credential(user_id, project_id)
    deps = Deps(omni=omni, tools=TOOLS, memory=MEMORY, events=emit,
                provider_key=provider_key, provider_slug=provider_slug)
    sem = asyncio.Semaphore(dag.get("concurrency", 4) or 4)
    used = {"tokens": 0, "usd": 0.0}

    async def _run_one(node: dict) -> None:
        async with sem:
            if used["tokens"] >= dag.get("budget_tokens", S.MAX_TOKENS_PER_TASK) or \
               used["usd"] >= dag.get("budget_usd", S.MAX_COST_USD_PER_TASK):
                node["status"] = "failed"
                node["error"] = "budget exhausted"
                return
            res = await run_node(node, {"id": task_id, "goal": goal, "project_id": project_id,
                                        "upstream": collect_upstream(dag, node)}, deps)
            used["tokens"] += res.get("tokens", 0)
            used["usd"] += res.get("cost", 0.0)
            await emit(task_id, res.get("run_id"), "verification_started",
                       {"node": node["node_id"], "strategy": node.get("verification", "quality")})
            v = run_verification(node.get("verification", "quality"), res.get("summary", ""))
            if not v["pass"] and node.get("attempts", 1) <= 1:
                await emit(task_id, res.get("run_id"), "verification_failed", v)
                res = await run_node(node, {"id": task_id,
                                            "goal": goal + "\n[REPAIR] " + str(v["checks"])[:500],
                                            "project_id": project_id,
                                            "upstream": collect_upstream(dag, node)}, deps)
                v = run_verification(node.get("verification", "quality"), res.get("summary", ""))
            SF2 = session_factory()
            async with SF2() as db2:
                aq = await db2.execute(select(Agent).where(Agent.slug == node["agent_id"]))
                ag = aq.scalars().first()
                db2.add(AgentRun(task_id=task_id, agent_id=ag.id if ag else node["agent_id"],
                                 model_used=res.get("model", S.OMNIROUTE_DEFAULT_CAPABILITY),
                                 tokens_in=res.get("tokens", 0), tokens_out=0, cost_usd=res.get("cost", 0.0),
                                 latency_ms=res.get("latency_ms", 0), status=res.get("status", "completed"),
                                 attempt=res.get("attempt", 1), output_json=res.get("output", {}),
                                 verification_json=v))
                db2.add(Usage(project_id=project_id, model=res.get("model", ""),
                              tokens_in=res.get("tokens", 0), tokens_out=0,
                              cost_usd=res.get("cost", 0.0), task_id=task_id))
                t = await db2.get(Task, task_id)
                if t:
                    d = copy.deepcopy(t.dag or dag)
                    for n in d.get("nodes", []):
                        if n["node_id"] == node["node_id"]:
                            n.update(node)
                    subtasks = ((res.get("output") or {}).get("plan") or {}).get("subtasks") or []
                    if subtasks and node.get("status") in ("completed", "approved"):
                        added = expand_dag(d, node, subtasks, goal)
                        if added:
                            await emit(task_id, res.get("run_id"), "task_created",
                                       {"spawned_by": node["node_id"], "new_nodes": added,
                                        "reason": "agent identified follow-up work"})
                    t.dag = d
                    t.checkpoint = {"used_tokens": used["tokens"], "used_usd": used["usd"], "at": time.time()}
                await db2.commit()
                if ag:  # controlled self-improvement: performance scores only
                    row = await db2.get(Agent, ag.id)
                    if row:
                        ok = 1.0 if (res.get("status") in ("completed", "approved") and v["pass"]) else 0.0
                        row.performance_score = round(0.9 * (row.performance_score or 0.5) + 0.1 * ok, 4)
                        await db2.commit()

    while True:
        SF3 = session_factory()
        async with SF3() as db:
            t = await db.get(Task, task_id)
            if not t:
                return
            if t.status == "cancelled":
                await emit(task_id, None, "task_completed", {"status": "cancelled"})
                return
            dag = copy.deepcopy(t.dag or dag)
        if dag_expired(dag):
            async with session_factory()() as db:
                t = await db.get(Task, task_id)
                if t:
                    t.status = "expired"
                    t.dag = copy.deepcopy(dag)
                    await db.commit()
            await emit(task_id, None, "task_completed",
                       {"status": "expired", "reason": "wall-clock deadline reached"})
            return
        batch = ready_nodes(dag)
        st = dag_status(dag)
        if st in ("completed", "failed") or not batch:
            SF4 = session_factory()
            async with SF4() as db:
                t = await db.get(Task, task_id)
                assert t is not None
                if st == "completed":
                    t.status = "completed"
                elif not batch and st not in ("completed",):
                    t.status = "awaiting_approval" if st == "awaiting_approval" else "dead"
                else:
                    t.status = st
                t.dag = copy.deepcopy(dag)
                await db.commit()
                final = t.status
            await emit(task_id, None, "task_completed", {"status": final})
            try:
                await MEMORY.store(f"Task {task_id}: {goal[:200]} -> {final}. tokens={used['tokens']}",
                                   kind="episodic", project_id=project_id, task_id=task_id)
            except Exception:
                pass
            return
        await asyncio.gather(*[_run_one(n) for n in batch])
        SF5 = session_factory()
        async with SF5() as db:
            t = await db.get(Task, task_id)
            dag = copy.deepcopy((t.dag if t else {}) or dag)


async def recover_incomplete() -> int:
    SF = session_factory()
    async with SF() as db:
        rows = (await db.execute(select(Task).where(Task.status == "running"))).scalars().all()
        for t in rows:
            t.status = "queued"
        await db.commit()
        return len(rows)


async def worker_loop(poll_s: float = 1.0) -> None:
    while True:
        SF = session_factory()
        async with SF() as db:
            q = await db.execute(select(Task).where(Task.status == "queued").limit(1))
            task = q.scalars().first()
            if task:
                task.status = "running"
                await db.commit()
                tid = task.id
            else:
                tid = None
        if tid:
            try:
                await execute_task(tid)
            except Exception as e:
                SF2 = session_factory()
                async with SF2() as db2:
                    t = await db2.get(Task, tid)
                    if t:
                        t.status = "failed"
                        await db2.commit()
                await emit(tid, None, "task_completed", {"status": "failed", "error": str(e)[:300]})
        else:
            await asyncio.sleep(poll_s)

# =====================================================================================
# 16. API — /v1/* routes + app
# =====================================================================================
_bearer = HTTPBearer(auto_error=False)


async def current_user(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> User:
    if not creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    try:
        payload = decode_token(creds.credentials)
        if payload.get("type") != "access":
            raise ValueError("not an access token")
        uid = payload["sub"]
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    SF = session_factory()
    async with SF() as db:
        user = await db.get(User, uid)
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="user not found/inactive")
        return user


async def _audit(user_id: str | None, action: str, resource: str = "", result: str = "ok", meta: dict | None = None):
    try:
        SF = session_factory()
        async with SF() as db:
            db.add(AuditLog(user_id=user_id, action=action, resource=resource, result=result, meta=meta or {}))
            await db.commit()
    except Exception:
        pass


auth_r = APIRouter(prefix="/auth", tags=["auth"])
chat_r = APIRouter(prefix="/chat", tags=["chat"])
tasks_r = APIRouter(prefix="/tasks", tags=["tasks"])
projects_r = APIRouter(prefix="/projects", tags=["projects"])
agents_r = APIRouter(prefix="/agents", tags=["agents"])
models_r = APIRouter(prefix="/models", tags=["models"])
providers_r = APIRouter(prefix="/providers", tags=["providers"])
keys_r = APIRouter(prefix="/keys", tags=["keys"])
tools_r = APIRouter(prefix="/tools", tags=["tools"])
mcp_r = APIRouter(prefix="/mcp", tags=["mcp"])
memory_r = APIRouter(prefix="/memory", tags=["memory"])
sandbox_r = APIRouter(prefix="/sandboxes", tags=["sandboxes"])
artifacts_r = APIRouter(prefix="/artifacts", tags=["artifacts"])
runs_r = APIRouter(prefix="/runs", tags=["runs"])
events_r = APIRouter(prefix="/events", tags=["events"])


@auth_r.post("/register", response_model=TokenOut)
async def register(body: RegisterIn):
    SF = session_factory()
    async with SF() as db:
        if (await db.execute(select(User).where(User.email == body.email))).scalars().first():
            raise HTTPException(400, "email already registered")
        n = (await db.execute(select(User))).scalars().all()
        user = User(email=body.email, password_hash=hash_password(body.password),
                    role="admin" if not n else "user")
        db.add(user)
        await db.commit()
        await _audit(user.id, "auth.register", body.email)
        return TokenOut(access_token=create_access_token(user.id), refresh_token=create_refresh_token(user.id))


@auth_r.post("/login", response_model=TokenOut)
async def login(body: LoginIn):
    SF = session_factory()
    async with SF() as db:
        user = (await db.execute(select(User).where(User.email == body.email))).scalars().first()
        if not user or not verify_password(body.password, user.password_hash):
            raise HTTPException(401, "invalid credentials")
        await _audit(user.id, "auth.login", body.email)
        return TokenOut(access_token=create_access_token(user.id), refresh_token=create_refresh_token(user.id))


@auth_r.get("/me")
async def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "role": user.role}


@projects_r.post("")
async def create_project(body: ProjectIn, user: User = Depends(current_user)):
    SF = session_factory()
    async with SF() as db:
        p = Project(owner_id=user.id, name=body.name, goals=body.goals, settings=body.settings)
        db.add(p)
        await db.commit()
        await seed_mcp_servers(p.id)
        return {"id": p.id, "name": p.name}


@projects_r.get("")
async def list_projects(user: User = Depends(current_user)):
    SF = session_factory()
    async with SF() as db:
        rows = (await db.execute(select(Project).where(Project.owner_id == user.id))).scalars().all()
        return [{"id": r.id, "name": r.name, "goals": r.goals} for r in rows]


@tasks_r.post("")
async def create_task(body: TaskCreate, user: User = Depends(current_user)):
    try:
        limiter.check(f"tasks:{user.id}")
    except RuntimeError:
        raise HTTPException(429, "rate limit exceeded")
    SF = session_factory()
    async with SF() as db:
        proj = await db.get(Project, body.project_id)
        if not proj or proj.owner_id != user.id:
            raise HTTPException(404, "project not found")
        if body.idempotency_key and (await db.execute(
                select(Task).where(Task.idempotency_key == body.idempotency_key))).scalars().first():
            raise HTTPException(409, "duplicate idempotency key")
        t = Task(project_id=body.project_id, user_id=user.id, goal=body.goal, status="queued",
                 priority=body.priority, budget_tokens=min(body.budget_tokens, S.MAX_TOKENS_PER_TASK),
                 budget_usd=min(body.budget_usd, S.MAX_COST_USD_PER_TASK),
                 idempotency_key=body.idempotency_key or str(uuid.uuid4()))
        db.add(t)
        await db.commit()
        tid = t.id
    asyncio.create_task(execute_task(tid))
    await emit(tid, None, "task_created", {"goal": redact(body.goal)[:300]})
    return {"id": tid, "status": "queued"}


@tasks_r.get("/{task_id}")
async def get_task(task_id: str, user: User = Depends(current_user)):
    SF = session_factory()
    async with SF() as db:
        t = await db.get(Task, task_id)
        if not t or t.user_id != user.id:
            raise HTTPException(404, "task not found")
        return {"id": t.id, "status": t.status, "goal": t.goal, "dag": t.dag, "checkpoint": t.checkpoint}


@tasks_r.get("")
async def list_tasks(user: User = Depends(current_user)):
    SF = session_factory()
    async with SF() as db:
        rows = (await db.execute(select(Task).where(Task.user_id == user.id).limit(100))).scalars().all()
        return [{"id": r.id, "status": r.status, "goal": r.goal[:200]} for r in rows]


@tasks_r.post("/{task_id}/cancel")
async def cancel_task(task_id: str, user: User = Depends(current_user)):
    SF = session_factory()
    async with SF() as db:
        t = await db.get(Task, task_id)
        if not t or t.user_id != user.id:
            raise HTTPException(404, "task not found")
        t.status = "cancelled"
        await db.commit()
    await emit(task_id, None, "task_completed", {"status": "cancelled"})
    return {"ok": True}


@tasks_r.post("/{task_id}/resume")
async def resume_task(task_id: str, user: User = Depends(current_user)):
    SF = session_factory()
    async with SF() as db:
        t = await db.get(Task, task_id)
        if not t or t.user_id != user.id:
            raise HTTPException(404, "task not found")
        dag = copy.deepcopy(t.dag or {})
        for n in dag.get("nodes", []):
            if n.get("status") == "failed":
                n["status"] = "pending"
                n["error"] = None
        t.dag = copy.deepcopy(dag)
        t.status = "queued"
        await db.commit()
    asyncio.create_task(execute_task(task_id))
    return {"ok": True}


@tasks_r.post("/{task_id}/approve")
async def approve_task(task_id: str, node_id: str = "", user: User = Depends(current_user)):
    """Clear human approval gates so a gated DAG can continue."""
    SF = session_factory()
    async with SF() as db:
        t = await db.get(Task, task_id)
        if not t or t.user_id != user.id:
            raise HTTPException(404, "task not found")
        dag = copy.deepcopy(t.dag or {})
        cleared = []
        for n in dag.get("nodes", []):
            if n.get("status") == "awaiting_approval" and (not node_id or n["node_id"] == node_id):
                n["status"] = "approved"
                cleared.append(n["node_id"])
        if not cleared:
            raise HTTPException(400, "no nodes awaiting approval")
        t.dag = copy.deepcopy(dag)
        t.status = "queued"
        await db.commit()
    await _audit(user.id, "task.approve", task_id, meta={"nodes": cleared})
    asyncio.create_task(execute_task(task_id))
    return {"ok": True, "approved": cleared}


@tasks_r.get("/{task_id}/events")
async def task_events(task_id: str, user: User = Depends(current_user)):
    SF = session_factory()
    async with SF() as db:
        t = await db.get(Task, task_id)
        if not t or t.user_id != user.id:
            raise HTTPException(404, "task not found")
        rows = (await db.execute(select(TaskEvent).where(TaskEvent.task_id == task_id).limit(500))).scalars().all()
        return [{"type": r.type, "payload": r.payload, "at": r.created_at.isoformat()} for r in rows]


async def _check_task_owner(task_id: str, user: User) -> Task:
    SF = session_factory()
    async with SF() as db:
        t = await db.get(Task, task_id)
        if not t or t.user_id != user.id:
            raise HTTPException(404, "task not found")
        return t


@runs_r.get("/{task_id}/stream")
async def stream_events(task_id: str, token: str = "",
                        creds: HTTPAuthorizationCredentials | None = Depends(_bearer)):
    """Server-sent events for a run.

    EventSource cannot set an Authorization header, so a ?token= query parameter is
    accepted here as well. It is validated exactly like a bearer token.
    """
    raw = token or (creds.credentials if creds else "")
    if not raw:
        raise HTTPException(401, "missing token")
    try:
        payload = decode_token(raw)
    except Exception:
        raise HTTPException(401, "invalid token")
    SF = session_factory()
    async with SF() as db:
        user = await db.get(User, payload.get("sub", ""))
    if not user:
        raise HTTPException(401, "unknown user")
    await _check_task_owner(task_id, user)

    async def gen():
        q = subscribe(task_id)
        try:
            # replay what already happened so a late subscriber sees the whole run
            async with session_factory()() as db2:
                rows = (await db2.execute(
                    select(TaskEvent).where(TaskEvent.task_id == task_id)
                    .order_by(TaskEvent.created_at).limit(500))).scalars().all()
            for r in rows:
                ev = {"type": r.type, "run_id": r.run_id, "payload": r.payload or {},
                      "at": r.created_at.timestamp() if r.created_at else time.time(),
                      "replay": True}
                yield f"event: {r.type}\ndata: {json.dumps(ev, default=str)}\n\n"
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=20)
                    yield f"event: {ev['type']}\ndata: {json.dumps(ev, default=str)}\n\n"
                    if ev["type"] == "task_completed":
                        break
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            unsubscribe(task_id, q)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


@agents_r.get("")
async def list_agents(q: str = ""):
    defs = registry_search(q) if q else list(REGISTRY.values())
    SF = session_factory()
    async with SF() as db:
        rows = (await db.execute(select(Agent))).scalars().all()
        perf = {r.slug: r.performance_score for r in rows}
    return [{"id": d.id, "name": d.name, "description": d.description, "capabilities": d.capabilities,
             "tools": d.tools, "cost_level": d.cost_level, "risk_level": d.risk_level,
             "verification": d.verification_strategy, "performance": perf.get(d.id, 0.5)} for d in defs]


@agents_r.get("/stats")
async def agent_stats():
    by_domain: dict[str, int] = defaultdict(int)
    for d in REGISTRY.values():
        by_domain[d.domain] += 1
    return {"total": len(REGISTRY), "domains": len(by_domain),
            "by_domain": dict(sorted(by_domain.items())),
            "human_gated": sum(1 for d in REGISTRY.values() if d.human_gate),
            "aliases": len(ALIASES), "catalogue": str(AGENT_CATALOGUE_PATH)}


@agents_r.post("/reload")
async def reload_agents(user: User = Depends(current_user)):
    """Hot-reload the catalogue — add agents without restarting."""
    n = load_catalogue()
    await _audit(user.id, "agents.reload", "", "ok", {"loaded": n})
    return {"loaded": n, "total": len(REGISTRY)}


@agents_r.get("/{agent_id}")
async def get_agent(agent_id: str):
    if agent_id not in REGISTRY:
        raise HTTPException(404, "agent not found")
    return REGISTRY[agent_id].model_dump()


@models_r.get("")
async def list_models():
    SF = session_factory()
    async with SF() as db:
        rows = (await db.execute(select(Model).limit(200))).scalars().all()
        out = []
        for r in rows:
            prov = await db.get(Provider, r.provider_id)
            # `provider` must be the human-readable slug ("openai", "groq", ...), not the
            # internal provider row id, since the client sends it straight back on /v1/chat
            # to pick which stored key to use for a selected model.
            out.append({"provider": prov.slug if prov else r.provider_id, "model": r.model_id,
                       "tags": r.capability_tags, "tier": r.tier, "enabled": r.enabled})
        return out


@models_r.post("/discover")
async def discover_models(user: User = Depends(current_user)):
    try:
        found = await OmniRouteClient().discover_models()
    except Exception as e:
        raise HTTPException(502, f"omniroute unreachable: {e}")
    SF = session_factory()
    async with SF() as db:
        await seed_providers(db)
        n = await sync_models(db, found)
    return {"synced": n}


@providers_r.get("")
async def list_providers():
    SF = session_factory()
    async with SF() as db:
        await seed_providers(db)
        rows = (await db.execute(select(Provider))).scalars().all()
        return [{"slug": r.slug, "name": r.display_name, "status": r.status} for r in rows]


@providers_r.get("/health")
async def providers_health():
    return await OmniRouteClient().health()


@keys_r.post("")
async def add_key(body: KeyCreate, user: User = Depends(current_user)):
    SF = session_factory()
    async with SF() as db:
        await seed_providers(db)
        prov = (await db.execute(select(Provider).where(Provider.slug == body.provider_slug))).scalars().first()
        if not prov:
            raise HTTPException(404, "provider not found")
        if len(body.api_key) < 8:
            raise HTTPException(400, "api key looks malformed")
        # Validate against the provider and pull its model catalogue in one go.
        disc = await discover_models_for_key(prov.slug, body.api_key, prov.base_url or "")
        is_valid = bool(disc["ok"])
        row = ProviderKey(user_id=user.id, project_id=body.project_id, provider_id=prov.id,
                          encrypted_blob=encrypt_secret(body.api_key),
                          fingerprint=fingerprint(body.api_key), is_valid=is_valid)
        db.add(row)
        await db.commit()
        saved = 0
        if is_valid:
            saved = await persist_models(db, prov.slug, disc["models"])
        await _audit(user.id, "keys.add", prov.slug, "ok" if is_valid else "invalid",
                     {"models_discovered": saved})
        return {"id": row.id, "provider": prov.slug, "fingerprint": row.fingerprint,
                "is_valid": is_valid, "models_discovered": saved,
                "error": disc["error"] or None}


@keys_r.get("")
async def list_keys(user: User = Depends(current_user)):
    SF = session_factory()
    async with SF() as db:
        rows = (await db.execute(select(ProviderKey).where(ProviderKey.user_id == user.id))).scalars().all()
        out = []
        for r in rows:
            prov = await db.get(Provider, r.provider_id)
            out.append({"id": r.id, "provider": prov.slug if prov else r.provider_id,
                        "fingerprint": r.fingerprint, "is_valid": r.is_valid, "project_id": r.project_id})
        return out


@keys_r.delete("/{key_id}")
async def delete_key(key_id: str, user: User = Depends(current_user)):
    SF = session_factory()
    async with SF() as db:
        r = await db.get(ProviderKey, key_id)
        if not r or r.user_id != user.id:
            raise HTTPException(404, "key not found")
        await db.delete(r)
        await db.commit()
        return {"ok": True}


@chat_r.post("")
async def chat(body: ChatIn, user: User = Depends(current_user)):
    """Conversational turn. Routes to a single fast call unless real work is requested."""
    SF = session_factory()
    async with SF() as db:
        proj = await db.get(Project, body.project_id)
        if not proj or proj.owner_id != user.id:
            raise HTTPException(404, "project not found")

    intent = classify_intent(body.message)
    force = (body.mode or "auto").lower()
    if force in ("chat", "task"):
        intent = {**intent, "mode": force, "reason": f"forced by client ({force})"}

    if intent["mode"] == "chat":
        await quota_for(user.id).acquire(estimate_tokens(body.message, 700))
        hist = body.history or []
        res = await fast_reply(body.message, hist, body.project_id, user.id, body.model, body.provider)
        await _audit(user.id, "chat.fast", body.project_id, "ok",
                     {"latency_ms": res["latency_ms"], "cached": res["cached"], "model": res.get("model")})
        return {"mode": "chat", "intent": intent, "reply": res["reply"],
                "latency_ms": res["latency_ms"], "cached": res["cached"],
                "tokens": res["tokens"], "task_id": None, "model": res.get("model")}

    # real work -> hand to the orchestrator, return immediately, stream the rest
    async with SF() as db:
        t = Task(project_id=body.project_id, user_id=user.id, goal=body.message,
                 status="queued", idempotency_key=str(uuid.uuid4()))
        db.add(t)
        await db.commit()
        tid = t.id
    plan = route_goal(body.message)
    await _audit(user.id, "chat.task", tid, "ok", {"agents": len(plan.steps)})
    return {"mode": "task", "intent": intent, "task_id": tid, "status": "queued",
            "planned_agents": [st.agent_id for st in plan.steps],
            "reply": (f"That needs real work, so I have started a task with "
                      f"{len(plan.steps)} specialist agents. Stream it at "
                      f"/v1/runs/{tid}/stream.")}


@chat_r.post("/classify")
async def classify(body: ChatIn, user: User = Depends(current_user)):
    """Inspect routing without spending anything."""
    return classify_intent(body.message)


@tools_r.get("")
async def list_tools():
    return [{"name": t.name, "description": t.description, "scopes": t.scopes} for t in TOOLS.list()]


@tools_r.post("/{name}/invoke")
async def invoke_tool(name: str, args: dict, user: User = Depends(current_user)):
    granted = ["fs:read", "fs:write", "net:fetch", "db:query", "memory:read", "memory:write"]
    try:
        res = await TOOLS.call(name, args, {"project_id": "default"}, granted)
    except KeyError:
        raise HTTPException(404, "tool not found")
    await _audit(user.id, "tools.invoke", name, "ok" if res.ok else "fail")
    return {"ok": res.ok, "output": res.output, "error": res.error}


@mcp_r.get("/servers")
async def mcp_servers(user: User = Depends(current_user)):
    return await list_servers()


@mcp_r.post("/servers")
async def mcp_add(body: MCPServerIn, user: User = Depends(current_user)):
    SF = session_factory()
    async with SF() as db:
        r = MCPServer(project_id=body.project_id, name=body.name, transport=body.transport,
                      url_or_cmd=body.url_or_cmd, allowed_scopes=body.allowed_scopes, enabled=False)
        db.add(r)
        await db.commit()
        return {"id": r.id, "name": r.name}


@memory_r.post("")
async def mem_store(body: MemoryStore, user: User = Depends(current_user)):
    mid = await MEMORY.store(body.content, kind=body.kind, project_id=body.project_id,
                             task_id=body.task_id, user_id=user.id)
    return {"id": mid}


@memory_r.get("/search")
async def mem_search(project_id: str, q: str, user: User = Depends(current_user)):
    return {"results": await MEMORY.recall(project_id, q)}


@sandbox_r.post("")
async def sandbox_create(task_id: str = "", user: User = Depends(current_user)):
    box = get_sandbox()
    bid = await box.create(task_id or "adhoc")
    SF = session_factory()
    async with SF() as db:
        db.add(SandboxRow(task_id=task_id or None, adapter=box.name, status="created"))
        await db.commit()
    return {"sandbox_id": bid, "adapter": box.name}


@sandbox_r.post("/exec")
async def sandbox_exec(body: SandboxExec, user: User = Depends(current_user)):
    res = await get_sandbox().exec(body.sandbox_id, body.language, body.code,
                                   body.command, body.approve_generated_code)
    await _audit(user.id, "sandbox.exec", body.sandbox_id, "ok" if res.get("ok") else "fail")
    return dict(res)


@artifacts_r.get("")
async def list_artifacts(project_id: str, user: User = Depends(current_user)):
    SF = session_factory()
    async with SF() as db:
        rows = (await db.execute(select(Artifact).where(Artifact.project_id == project_id).limit(100))).scalars().all()
        return [{"id": r.id, "kind": r.kind, "uri": r.uri, "approved": r.approved} for r in rows]


@sandbox_r.get("/capabilities")
async def sandbox_capabilities():
    """Exactly which isolation layers are live on this machine — no marketing claims."""
    rep = isolation_report()
    rep["limits"] = {
        "cpu_seconds": ExecLimits.cpu_seconds, "memory_mb": ExecLimits.memory_mb,
        "wall_seconds": ExecLimits.wall_seconds, "max_processes": ExecLimits.max_processes,
        "file_size_mb": ExecLimits.file_size_mb, "max_output_chars": ExecLimits.max_output,
    }
    return rep


@providers_r.get("/limits")
async def provider_limits():
    """Live rate-limit state per provider, including adaptive throttling."""
    return {"defaults": FREE_TIER_DEFAULTS,
            "live": {p: g.snapshot() for p, g in GATES.items()},
            "note": ("Defaults are starting points for known free tiers and will drift as "
                     "providers change them. Override with PROVIDER_LIMITS_JSON. Every gate "
                     "also shrinks itself automatically on a 429 and recovers on success.")}


@models_r.post("/refresh")
async def refresh_models(provider_slug: str = "", user: User = Depends(current_user)):
    """Re-discover models using the user's stored keys."""
    SF = session_factory()
    out: dict[str, Any] = {}
    async with SF() as db:
        q = select(ProviderKey).where(ProviderKey.user_id == user.id)
        keys = (await db.execute(q)).scalars().all()
        for k in keys:
            prov = await db.get(Provider, k.provider_id)
            if not prov or (provider_slug and prov.slug != provider_slug):
                continue
            try:
                plain = decrypt_secret(k.encrypted_blob)
            except Exception:
                out[prov.slug] = {"ok": False, "error": "key could not be decrypted"}
                continue
            disc = await discover_models_for_key(prov.slug, plain, prov.base_url or "")
            del plain
            if disc["ok"]:
                n = await persist_models(db, prov.slug, disc["models"])
                out[prov.slug] = {"ok": True, "models": n}
            else:
                out[prov.slug] = {"ok": False, "error": disc["error"]}
    await _audit(user.id, "models.refresh", provider_slug or "all")
    return out


@asynccontextmanager
async def lifespan(app: FastAPI):
    data_dir()
    await init_db()
    SF = session_factory()
    async with SF() as db:
        await seed_providers(db)
        have = {row[0] for row in (await db.execute(select(Agent.slug))).all()}
        rows = [dict(id=_uid(), slug=d.id, name=d.name, description=d.description,
                     capabilities=d.capabilities, tools=d.tools,
                     model_requirements=d.model_requirements, cost_level=d.cost_level,
                     risk_level=d.risk_level, permissions=d.permissions,
                     system_prompt=d.system_instructions,
                     verification_strategy=d.verification_strategy, version=d.version,
                     enabled=True, performance_score=0.5)
                for d in REGISTRY.values() if d.id not in have]
        if rows:
            await db.execute(Agent.__table__.insert(), rows)   # one statement, not 480
        await db.commit()
    await recover_incomplete()
    log.info("Maximus ready: %d agents across %d domains | isolation=%s",
             len(REGISTRY), len({d.domain for d in REGISTRY.values()}), ISOLATION_MODE)
    try:
        yield
    finally:
        await close_http()


def create_app() -> FastAPI:
    app = FastAPI(title="Maximus AI", version="1.0.0",
                  description="Autonomous multi-agent OS — local-first. OmniRoute = model gateway.",
                  lifespan=lifespan)
    app.add_middleware(CORSMiddleware,
                       allow_origins=_env("CORS_ORIGINS", "*").split(","),
                       allow_methods=["*"], allow_headers=["*"])

    # Original lookup (unchanged): an index.html dropped next to app.py wins if present.
    # Added: fall back to the frontend/index.html that ships in this repo, so `python app.py`
    # serves the UI without an extra manual copy step, and so a single Render web service can
    # serve both the API and the UI together if that's how it's deployed.
    index = BASE_DIR / "index.html"
    if not index.exists() and (BASE_DIR / "frontend" / "index.html").exists():
        index = BASE_DIR / "frontend" / "index.html"

    @app.get("/", include_in_schema=False)
    async def root(request: Request):
        # Browsers get the control room; API clients get JSON from the same path.
        if index.exists() and "text/html" in request.headers.get("accept", ""):
            return FileResponse(str(index), media_type="text/html")
        return JSONResponse({
            "app": S.APP_NAME, "agents": len(REGISTRY),
            "domains": len({d.domain for d in REGISTRY.values()}),
            "ui": "/app" if index.exists() else None, "docs": "/docs",
            "isolation": ISOLATION_MODE,
            "principle": "MAXIMUS=orchestration, OMNIROUTE=models, MCP=tools, "
                         "SANDBOX=local execution, MEMORY=context"})

    @app.get("/app", include_in_schema=False)
    async def ui():
        if not index.exists():
            raise HTTPException(404, "index.html is not next to app.py")
        return FileResponse(str(index), media_type="text/html")

    @app.get("/health")
    async def health():
        return {"status": "ok", "app": S.APP_NAME}

    @app.get("/ready")
    async def ready():
        try:
            SF = session_factory()
            async with SF() as db:
                await db.execute(select(Agent).limit(1))
            db_ok = True
        except Exception:
            db_ok = False
        return {"ready": db_ok, "agents": len(REGISTRY)}

    for _r in (auth_r, chat_r, tasks_r, projects_r, agents_r, models_r, providers_r,
               keys_r, tools_r, mcp_r, memory_r, sandbox_r, artifacts_r, runs_r, events_r):
        app.include_router(_r, prefix="/v1")

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=S.API_HOST, port=S.API_PORT, reload=False)
