import math
import re
import threading
import time
from dataclasses import dataclass

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.auth import COOKIE_NAME, decode_access_token
from app.config import settings

MAX_TRACKED_KEYS = 10_000
STALE_AFTER_SECONDS = 300


@dataclass(frozen=True)
class Rule:
    name: str
    method: str
    pattern: re.Pattern
    limit: int
    window_seconds: int
    scope: str  # "user_or_ip", "ip" or "global"
    detail: str


RULES = [
    Rule(
        "scan",
        "POST",
        re.compile(r"^/scan$"),
        15,
        60,
        "user_or_ip",
        "too many scans, please wait a moment and try again",
    ),
    Rule(
        "explain",
        "POST",
        re.compile(r"^/explain$"),
        8,
        60,
        "user_or_ip",
        "too many explanation requests, please wait a moment and try again",
    ),
    Rule(
        "explain-all-users",
        "POST",
        re.compile(r"^/explain$"),
        12,
        60,
        "global",
        "the explanation service is busy, please try again in a minute",
    ),
    Rule(
        "attempt",
        "POST",
        re.compile(r"^/exercises/[^/]+/attempt$"),
        20,
        60,
        "user_or_ip",
        "too many submissions, please wait a moment and try again",
    ),
    Rule(
        "login",
        "POST",
        re.compile(r"^/auth/login$"),
        10,
        60,
        "ip",
        "too many login attempts, please wait a minute and try again",
    ),
    Rule(
        "register",
        "POST",
        re.compile(r"^/auth/register$"),
        10,
        60,
        "ip",
        "too many sign-ups from this address, please wait a minute and try again",
    ),
]


class SlidingWindowLimiter:
    """In-memory sliding window. Correct for a single backend process only."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def check(self, key: str, limit: int, window_seconds: int) -> float | None:
        """Record a hit. Return None if allowed, else seconds until a slot frees up."""
        now = self._clock()
        cutoff = now - window_seconds
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if t > cutoff]
            if len(hits) >= limit:
                self._hits[key] = hits
                return max(0.0, hits[0] + window_seconds - now)
            hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > MAX_TRACKED_KEYS:
                self._prune(now)
            return None

    def _prune(self, now: float) -> None:
        stale = [k for k, v in self._hits.items() if not v or v[-1] < now - STALE_AFTER_SECONDS]
        for key in stale:
            del self._hits[key]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()


def client_ip(request: Request) -> str:
    if settings.trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for", "")
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


def actor_key(request: Request, scope: str) -> str:
    if scope == "global":
        return "global"
    if scope == "user_or_ip":
        token = request.cookies.get(COOKIE_NAME)
        user_id = decode_access_token(token) if token else None
        if user_id is not None:
            return f"user:{user_id}"
    return f"ip:{client_ip(request)}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if settings.rate_limit_enabled and request.method != "OPTIONS":
            for rule in RULES:
                if request.method != rule.method or not rule.pattern.match(request.url.path):
                    continue
                key = f"{rule.name}|{actor_key(request, rule.scope)}"
                retry_after = limiter.check(key, rule.limit, rule.window_seconds)
                if retry_after is not None:
                    return JSONResponse(
                        status_code=429,
                        content={"detail": rule.detail},
                        headers={"Retry-After": str(max(1, math.ceil(retry_after)))},
                    )
        return await call_next(request)