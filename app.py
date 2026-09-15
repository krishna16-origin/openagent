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
import base64
import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import shutil
import sqlite3
import tempfile
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
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


class S:
    APP_NAME = _env("APP_NAME", "MaximusAI")
    SECRET_KEY = _env("SECRET_KEY", "dev-only-change-me-min-32-chars-1234567890")
    JWT_ALGORITHM = _env("JWT_ALGORITHM", "HS256")
    JWT_ACCESS_MINUTES = int(_env("JWT_ACCESS_MINUTES", "15"))
    JWT_REFRESH_DAYS = int(_env("JWT_REFRESH_DAYS", "30"))
    DATABASE_URL = _env("DATABASE_URL", f"sqlite+aiosqlite:///{(BASE_DIR / 'data' / 'maximus.db').as_posix()}")
    DATA_DIR = _env("DATA_DIR", str(BASE_DIR / "data"))
    SECRETS_MASTER_KEY = _env("SECRETS_MASTER_KEY", "")
    OMNIROUTE_BASE_URL = _env("OMNIROUTE_BASE_URL", "http://127.0.0.1:9000").rstrip("/")
    OMNIROUTE_API_KEY = _env("OMNIROUTE_API_KEY", "")
    OMNIROUTE_TIMEOUT_S = int(_env("OMNIROUTE_TIMEOUT_S", "60"))
    OMNIROUTE_DEFAULT_CAPABILITY = _env("OMNIROUTE_DEFAULT_CAPABILITY", "reasoning")
    SANDBOX_ADAPTER = _env("SANDBOX_ADAPTER", "local")
    E2B_API_KEY = _env("E2B_API_KEY", "")
    ALLOWED_SANDBOX_ROOT = _env("ALLOWED_SANDBOX_ROOT", str(BASE_DIR / "data" / "sandboxes"))
    MAX_TOKENS_PER_TASK = int(_env("MAX_TOKENS_PER_TASK", "120000"))
    MAX_COST_USD_PER_TASK = float(_env("MAX_COST_USD_PER_TASK", "5.0"))
    MAX_RETRIES = int(_env("MAX_RETRIES", "3"))
    RATE_LIMIT_PER_MIN = int(_env("RATE_LIMIT_PER_MIN", "60"))
    API_HOST = _env("API_HOST", "127.0.0.1")
    API_PORT = int(_env("API_PORT", "8000"))


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


def assert_url_allowed(url: str, allow_private: bool = False) -> str:
    u = urlparse(url)
    if u.scheme not in ("http", "https"):
        raise ValueError(f"blocked scheme: {u.scheme}")
    host = (u.hostname or "").lower()
    if host in _BLOCKED_HOSTS and not allow_private:
        raise ValueError(f"blocked host (SSRF): {host}")
    try:
        ip = ipaddress.ip_address(host)
        if (ip.is_private or ip.is_loopback or ip.is_link_local) and not allow_private:
            raise ValueError(f"blocked private IP: {host}")
    except ValueError:
        pass
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


def get_engine():
    global _engine, _Session
    if _engine is None:
        url = S.DATABASE_URL
        if url.startswith("sqlite+aiosqlite://"):
            f = url.split("sqlite+aiosqlite://", 1)[1].split("?")[0]
            Path(f).parent.mkdir(parents=True, exist_ok=True)
        _engine = create_async_engine(url, echo=False, future=True)
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
    project_id: str
    message: str


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
    description: str = ""
    capabilities: list[str] = []
    tools: list[str] = []
    model_requirements: dict = {}
    cost_level: str = "low"
    risk_level: str = "low"
    permissions: list[str] = []
    system_instructions: str = ""
    verification_strategy: str = "quality"
    version: str = "1.0"


@dataclass
class AgentContext:
    goal: str
    project_id: str
    task_id: str
    node_id: str = "root"
    memory_snippets: list[str] = field(default_factory=list)
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

REGISTRY: dict[str, AgentDefinition] = {d["id"]: AgentDefinition(**d) for d in AGENT_DEFS}


def registry_search(q: str) -> list[AgentDefinition]:
    q = q.lower()
    return [d for d in REGISTRY.values()
            if q in d.id or q in d.name.lower() or any(q in c.lower() for c in d.capabilities)]


class GenericAgent:
    """One runtime class driven by the definition. No per-agent services."""

    def __init__(self, definition: AgentDefinition):
        self.definition = definition

    async def run(self, ctx: AgentContext, deps) -> AgentResult:
        system = self.definition.system_instructions or f"You are {self.definition.name}. {self.definition.description}"
        mem = "\n".join(ctx.memory_snippets[:5])
        messages = build_messages(system, f"{ctx.goal}\n\n<context>\n{mem}\n</context>")
        cap = (self.definition.model_requirements or {}).get("capability", "general")
        try:
            resp = await deps.omni.complete(messages, capability=cap, max_tokens=2000, timeout_s=15)
            text = resp["choices"][0]["message"]["content"]
            usage = resp.get("usage", {})
            tokens = int(usage.get("total_tokens", len(text) // 4))
        except Exception as e:  # offline fallback: deterministic local output
            text = f"[{self.definition.id}] local-plan for: {ctx.goal[:300]} (omniroute unavailable: {str(e)[:120]})"
            tokens = max(1, len(text) // 4)
        return AgentResult(status="completed",
                           structured_output={"agent": self.definition.id, "node": ctx.node_id, "output": text},
                           summary=text[:2000], usage_tokens=tokens, usage_usd=0.0)


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


def _score(defn: AgentDefinition, goal: str, perf: float) -> float:
    gl = goal.lower()
    cap_hit = sum(1 for c in defn.capabilities if c.lower() in gl)
    cap_score = min(1.0, 0.3 + 0.35 * cap_hit)
    cost_fit = 1.0 - COST_RANK.get(defn.cost_level, 0) * 0.2
    kw = 1.0 if any(k in gl for k in ("build", "saas", "app", "code", "deploy", "test", "research", "analy")) else 0.5
    return 0.4 * cap_score + 0.15 * cost_fit + 0.15 * (0.5 + perf / 2) + 0.3 * kw


SAAS_PIPE = ["goal_analyzer", "requirements", "architecture", "ui", "frontend", "backend",
             "database", "ai_integrator", "security", "testing", "devops", "deployment",
             "critic", "final_verifier"]
RESEARCH_PIPE = ["goal_analyzer", "researcher", "analyst", "critic", "final_verifier"]
DEFAULT_PIPE = ["goal_analyzer", "researcher", "analyst", "backend", "testing", "critic", "final_verifier"]


def route_goal(goal: str, perf_map: dict[str, float] | None = None,
               budget_tokens: int = 120000, budget_usd: float = 5.0) -> RoutePlan:
    perf_map = perf_map or {}
    gl = goal.lower()
    if any(k in gl for k in ("saas", "application", "platform", "frontend", "backend", "deploy")):
        pipe = SAAS_PIPE
    elif any(k in gl for k in ("research", "analy", "report", "paper", "survey")):
        pipe = RESEARCH_PIPE
    else:
        ranked = sorted(REGISTRY.values(), key=lambda d: _score(d, goal, perf_map.get(d.id, 0.5)), reverse=True)
        pipe = [d.id for d in ranked[:6]] or DEFAULT_PIPE
    pipe = [a for a in pipe if a in REGISTRY] or list(REGISTRY)[:3]
    steps: list[RouteStep] = []
    prev: str | None = None
    anchor: str | None = None
    parallel = {"frontend", "backend", "database", "ai_integrator", "ui"}
    for i, aid in enumerate(pipe):
        d = REGISTRY[aid]
        deps: list[str] = []
        if aid in parallel and anchor:
            deps = [anchor]
        elif prev:
            deps = [prev]
        if aid == "architecture":
            anchor = f"n{i}"
        steps.append(RouteStep(node_id=f"n{i}", agent_id=aid, depends_on=deps, tools=d.tools,
                               capability=(d.model_requirements or {}).get("capability", "general"),
                               verification=d.verification_strategy))
        if aid not in parallel:
            prev = f"n{i}"
    return RoutePlan(steps=steps, concurrency=4, budget_tokens=budget_tokens, budget_usd=budget_usd)


# ---- Planner: RoutePlan -> persistent DAG ----
HUMAN_GATE_AGENTS = {"deployment", "security", "devops"}


def plan_to_dag(plan: RoutePlan) -> dict:
    nodes = []
    for s in plan.steps:
        nodes.append({
            "node_id": s.node_id, "agent_id": s.agent_id, "depends_on": s.depends_on,
            "tools": s.tools, "capability": s.capability, "verification": s.verification,
            "status": "pending", "attempts": 0, "max_retries": 3, "timeout_s": 600,
            "needs_approval": s.agent_id in HUMAN_GATE_AGENTS,
            "result": None, "error": None, "started_at": None, "ended_at": None,
        })
    return {"nodes": nodes, "created_at": time.time(), "concurrency": plan.concurrency,
            "budget_tokens": plan.budget_tokens, "budget_usd": plan.budget_usd}


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


async def _emit_safe(deps: Deps, task_id: str, run_id: str | None, typ: str, payload: dict) -> None:
    try:
        clean = {k: (redact(v) if isinstance(v, str) else v) for k, v in payload.items()}
        await deps.events(task_id, run_id, typ, clean)
    except Exception:
        pass


async def run_node(node: dict, task: dict, deps: Deps) -> dict:
    task_id, node_id, agent_id = task["id"], node["node_id"], node["agent_id"]
    run_id = f"{task_id}:{node_id}"
    await _emit_safe(deps, task_id, run_id, "agent_started", {"agent": agent_id, "node": node_id})
    try:
        mem_snips = await deps.memory.recall(task.get("project_id", ""), task.get("goal", ""), limit=5)
    except Exception:
        mem_snips = []
    ctx = AgentContext(goal=task["goal"], project_id=task.get("project_id", ""),
                       task_id=task_id, node_id=node_id, memory_snippets=mem_snips)
    last_err: Exception | None = None
    for attempt in range(1, int(node.get("max_retries", 3)) + 1):
        node["attempts"] = attempt
        node["status"] = "running"
        t0 = time.time()
        try:
            await _emit_safe(deps, task_id, run_id, "thinking", {"agent": agent_id, "phase": "UNDERSTAND"})
            agent = GenericAgent(REGISTRY[agent_id])
            await _emit_safe(deps, task_id, run_id, "thinking", {"agent": agent_id, "phase": "ACT"})
            res = await asyncio.wait_for(agent.run(ctx, deps), timeout=float(node.get("timeout_s", 600)))
            latency = int((time.time() - t0) * 1000)
            node["result"] = res.structured_output
            node["status"] = "awaiting_approval" if node.get("needs_approval") and res.status == "completed" else res.status
            await _emit_safe(deps, task_id, run_id, "agent_completed",
                             {"agent": agent_id, "node": node_id, "latency_ms": latency, "tokens": res.usage_tokens})
            return {"run_id": run_id, "agent_id": agent_id, "node_id": node_id, "status": node["status"],
                    "output": res.structured_output, "summary": res.summary,
                    "tokens": res.usage_tokens, "cost": res.usage_usd, "latency_ms": latency, "attempt": attempt}
        except Exception as e:
            last_err = e
            node["error"] = str(e)[:500]
            await _emit_safe(deps, task_id, run_id, "retrying",
                             {"agent": agent_id, "attempt": attempt, "error": str(e)[:200]})
            await asyncio.sleep(min(2 ** attempt, 10))
    node["status"] = "failed"
    return {"run_id": run_id, "agent_id": agent_id, "node_id": node_id, "status": "failed",
            "error": str(last_err)[:500], "attempt": node.get("attempts", 1)}

# =====================================================================================
# 9. OMNIROUTE — model/provider routing gateway client (Maximus picks capability class)
# =====================================================================================
class OmniRouteError(Exception):
    pass


class OmniRouteClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None, timeout_s: int | None = None):
        self.base = (base_url or S.OMNIROUTE_BASE_URL).rstrip("/")
        self.api_key = S.OMNIROUTE_API_KEY if api_key is None else api_key
        self.timeout = timeout_s or S.OMNIROUTE_TIMEOUT_S
        self._failures: dict[str, int] = {}
        self._opened: dict[str, float] = {}

    def _headers(self, provider_key: str | None = None) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        if provider_key:
            h["X-Provider-Key"] = provider_key  # BYOK, server-side only, never logged
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
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(f"{self.base}/models", headers=self._headers())
            r.raise_for_status()
            data = r.json()
        if isinstance(data, dict) and "data" in data:
            return data["data"]
        return data if isinstance(data, list) else []

    async def health(self) -> dict:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(f"{self.base}/health", headers=self._headers())
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
                       fallback_capabilities: list[str] | None = None) -> dict:
        chain = [capability] + (fallback_capabilities or ["general"])
        last: Exception | None = None
        for cap in chain:
            if self._cb_open(cap):
                continue
            try:
                async with httpx.AsyncClient(timeout=timeout_s or self.timeout) as c:
                    r = await c.post(f"{self.base}/v1/chat/completions", headers=self._headers(provider_key),
                                     json={"messages": messages, "capability": cap, "model": model_hint,
                                           "temperature": temperature, "max_tokens": max_tokens})
                    r.raise_for_status()
                    self._cb_ok(cap)
                    return r.json()
            except Exception as e:
                last = e
                self._cb_fail(cap)
                await asyncio.sleep(0.2)
        raise OmniRouteError(f"all OmniRoute capabilities failed: {last}")


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
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
                r = await c.get(url)
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


class ToolManager:
    def __init__(self):
        self._tools: dict[str, Tool] = {}
        for t in (FilesystemTool(), FetchTool(), SQLiteTool(), TerminalTool()):
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


class SandboxAdapter:
    name = "base"

    async def create(self, task_id: str) -> str:
        raise NotImplementedError

    async def exec(self, box_id: str, language: str, code: str, command: str, approve: bool) -> ExecResult:
        raise NotImplementedError

    async def destroy(self, box_id: str) -> None:
        raise NotImplementedError


class LocalSandbox(SandboxAdapter):
    name = "local"

    def __init__(self):
        self.root = Path(S.ALLOWED_SANDBOX_ROOT)
        self.root.mkdir(parents=True, exist_ok=True)
        self.boxes: dict[str, Path] = {}

    async def create(self, task_id: str) -> str:
        bid = f"{task_id}-{uuid.uuid4().hex[:8]}"
        p = self.root / bid
        p.mkdir(parents=True, exist_ok=True)
        self.boxes[bid] = p
        return bid

    async def exec(self, box_id: str, language: str, code: str, command: str, approve: bool) -> ExecResult:
        if not approve:
            return ExecResult({"ok": False, "error": "explicit approval required (approve_generated_code=true)"})
        box = self.boxes.get(box_id)
        if box is None:
            box = assert_path_inside(self.root, box_id)
            box.mkdir(parents=True, exist_ok=True)
        if language == "shell":
            assert_command_allowed(command)
            proc = await asyncio.create_subprocess_shell(
                command, cwd=str(box), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        elif language == "python":
            f = Path(box) / "main.py"
            f.write_text(code, encoding="utf-8")
            proc = await asyncio.create_subprocess_exec(
                "python", str(f), cwd=str(box), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        elif language == "javascript":
            if shutil.which("node") is None:
                return ExecResult({"ok": False, "error": "node not installed"})
            f = Path(box) / "main.js"
            f.write_text(code, encoding="utf-8")
            proc = await asyncio.create_subprocess_exec(
                "node", str(f), cwd=str(box), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        else:
            return ExecResult({"ok": False, "error": f"unsupported language {language}"})
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return ExecResult({"ok": proc.returncode == 0, "exit": proc.returncode,
                               "output": out.decode(errors="replace")[:20000]})
        except asyncio.TimeoutError:
            proc.kill()
            return ExecResult({"ok": False, "error": "timeout (120s)"})

    async def destroy(self, box_id: str) -> None:
        p = self.boxes.pop(box_id, None) or (self.root / box_id)
        if Path(str(p)).exists():
            shutil.rmtree(str(p), ignore_errors=True)


class MockSandbox(SandboxAdapter):
    name = "mock"

    async def create(self, task_id: str) -> str:
        return f"mock-{task_id}"

    async def exec(self, box_id: str, language: str, code: str, command: str, approve: bool) -> ExecResult:
        return ExecResult({"ok": True, "exit": 0, "output": f"[mock:{language}] ok", "box": box_id})

    async def destroy(self, box_id: str) -> None:
        return None


class DockerSandbox(SandboxAdapter):
    name = "docker"

    async def create(self, task_id: str) -> str:
        try:
            import docker  # type: ignore
        except ImportError:
            raise RuntimeError("docker package not installed (pip install docker)")
        return f"docker-{task_id}-{uuid.uuid4().hex[:6]}"

    async def exec(self, box_id: str, language: str, code: str, command: str, approve: bool) -> ExecResult:
        if not approve:
            return ExecResult({"ok": False, "error": "explicit approval required"})
        return ExecResult({"ok": False, "error": "docker exec not configured in single-file build (use local adapter)"})

    async def destroy(self, box_id: str) -> None:
        return None


class E2BSandbox(SandboxAdapter):
    name = "e2b"

    async def create(self, task_id: str) -> str:
        if not S.E2B_API_KEY:
            raise RuntimeError("E2B_API_KEY not set")
        return f"e2b-{task_id}"

    async def exec(self, box_id: str, language: str, code: str, command: str, approve: bool) -> ExecResult:
        return ExecResult({"ok": False, "error": "E2B adapter stub — set E2B_API_KEY and implement SDK call"})

    async def destroy(self, box_id: str) -> None:
        return None


def get_sandbox() -> SandboxAdapter:
    kind = S.SANDBOX_ADAPTER.lower()
    if kind == "mock":
        return MockSandbox()
    if kind == "docker":
        return DockerSandbox()
    if kind == "e2b":
        return E2BSandbox()
    return LocalSandbox()

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
        goal, project_id = task.goal, task.project_id
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
    deps = Deps(omni=omni, tools=TOOLS, memory=MEMORY, events=emit)
    sem = asyncio.Semaphore(dag.get("concurrency", 4) or 4)
    used = {"tokens": 0, "usd": 0.0}

    async def _run_one(node: dict) -> None:
        async with sem:
            if used["tokens"] >= dag.get("budget_tokens", S.MAX_TOKENS_PER_TASK) or \
               used["usd"] >= dag.get("budget_usd", S.MAX_COST_USD_PER_TASK):
                node["status"] = "failed"
                node["error"] = "budget exhausted"
                return
            res = await run_node(node, {"id": task_id, "goal": goal, "project_id": project_id}, deps)
            used["tokens"] += res.get("tokens", 0)
            used["usd"] += res.get("cost", 0.0)
            await emit(task_id, res.get("run_id"), "verification_started",
                       {"node": node["node_id"], "strategy": node.get("verification", "quality")})
            v = run_verification(node.get("verification", "quality"), res.get("summary", ""))
            if not v["pass"] and node.get("attempts", 1) <= 1:
                await emit(task_id, res.get("run_id"), "verification_failed", v)
                res = await run_node(node, {"id": task_id,
                                            "goal": goal + "\n[REPAIR] " + str(v["checks"])[:500],
                                            "project_id": project_id}, deps)
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
                    d = dict(t.dag or dag)
                    for n in d.get("nodes", []):
                        if n["node_id"] == node["node_id"]:
                            n.update(node)
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
            dag = dict(t.dag or dag)
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
                t.dag = dag
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
            dag = dict((t.dag if t else {}) or dag)


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
        dag = dict(t.dag or {})
        for n in dag.get("nodes", []):
            if n.get("status") == "failed":
                n["status"] = "pending"
                n["error"] = None
        t.dag = dag
        t.status = "queued"
        await db.commit()
    asyncio.create_task(execute_task(task_id))
    return {"ok": True}


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
@events_r.get("/stream")
async def stream_events(task_id: str, user: User = Depends(current_user)):
    await _check_task_owner(task_id, user)

    async def gen():
        q = subscribe(task_id)
        try:
            yield f"event: planning\ndata: {json.dumps({'task': task_id})}\n\n"
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=25)
                    yield f"event: {ev['type']}\ndata: {json.dumps(ev, default=str)}\n\n"
                    if ev["type"] == "task_completed":
                        break
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            unsubscribe(task_id, q)

    return StreamingResponse(gen(), media_type="text/event-stream")


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
        return [{"provider": r.provider_id, "model": r.model_id, "tags": r.capability_tags,
                 "tier": r.tier, "enabled": r.enabled} for r in rows]


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
        is_valid = len(body.api_key) >= 8
        row = ProviderKey(user_id=user.id, project_id=body.project_id, provider_id=prov.id,
                          encrypted_blob=encrypt_secret(body.api_key),
                          fingerprint=fingerprint(body.api_key), is_valid=is_valid)
        db.add(row)
        await db.commit()
        await _audit(user.id, "keys.add", prov.slug)
        return {"id": row.id, "provider": prov.slug, "fingerprint": row.fingerprint, "is_valid": is_valid}


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
    SF = session_factory()
    async with SF() as db:
        proj = await db.get(Project, body.project_id)
        if not proj or proj.owner_id != user.id:
            raise HTTPException(404, "project not found")
        t = Task(project_id=body.project_id, user_id=user.id, goal=body.message,
                 status="queued", idempotency_key=str(uuid.uuid4()))
        db.add(t)
        await db.commit()
        tid = t.id
    await execute_task(tid)
    SF2 = session_factory()
    async with SF2() as db2:
        t2 = await db2.get(Task, tid)
        nodes = (t2.dag or {}).get("nodes", []) if t2 else []
        outs = [n.get("result", {}).get("output", "") for n in nodes if n.get("result")]
    return {"task_id": tid, "status": t2.status if t2 else "unknown", "outputs": outs[-2:]}


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    data_dir()
    await init_db()
    SF = session_factory()
    async with SF() as db:
        await seed_providers(db)
        have = {r.slug for r in (await db.execute(select(Agent))).scalars().all()}
        for d in REGISTRY.values():
            if d.id not in have:
                db.add(Agent(slug=d.id, name=d.name, description=d.description,
                             capabilities=d.capabilities, tools=d.tools,
                             model_requirements=d.model_requirements, cost_level=d.cost_level,
                             risk_level=d.risk_level, permissions=d.permissions,
                             system_prompt=d.system_instructions,
                             verification_strategy=d.verification_strategy, version=d.version))
        await db.commit()
    await recover_incomplete()
    log.info("Maximus ready: %d agents", len(REGISTRY))
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="Maximus AI", version="1.0.0",
                  description="Autonomous multi-agent OS — single-file local build. OmniRoute = model gateway.",
                  lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    # serve frontend index.html at / if present (Claude-style minimal frontend)
    try:
        from fastapi.staticfiles import StaticFiles as _SF
        from fastapi.responses import FileResponse as _FR
        _idx = BASE_DIR / "index.html"
        if _idx.exists():
            @app.get("/app", include_in_schema=False)
            async def _serve_index():
                return _FR(str(_idx), media_type="text/html")
            # also mount at / when Accept prefers html (keeps / JSON for API clients)
            _orig_root = None
            @app.get("/", include_in_schema=False)
            async def root(request=None):
                try:
                    from fastapi import Request as _Req
                    # if browser request, serve html; otherwise JSON
                    if request is not None:
                        accept = ""
                        try:
                            accept = request.headers.get("accept", "")
                        except Exception:
                            pass
                        if "text/html" in accept:
                            return _FR(str(_idx), media_type="text/html")
                except Exception:
                    pass
                return {"app": S.APP_NAME, "agents": len(REGISTRY), "docs": "/docs",
                        "principle": "MAXIMUS=orchestration, OMNIROUTE=models, MCP=tools, SANDBOX=execution, MEMORY=context"}
        else:
            @app.get("/")
            async def root():
                return {"app": S.APP_NAME, "agents": len(REGISTRY), "docs": "/docs",
                        "principle": "MAXIMUS=orchestration, OMNIROUTE=models, MCP=tools, SANDBOX=execution, MEMORY=context"}
    except Exception:
        @app.get("/")
        async def root():
            return {"app": S.APP_NAME, "agents": len(REGISTRY), "docs": "/docs",
                    "principle": "MAXIMUS=orchestration, OMNIROUTE=models, MCP=tools, SANDBOX=execution, MEMORY=context"}

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

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=S.API_HOST, port=S.API_PORT, reload=False)
