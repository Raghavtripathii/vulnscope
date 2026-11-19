import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth import COOKIE_NAME, create_access_token
from app.config import Settings
from app.ratelimit import RateLimitMiddleware, SlidingWindowLimiter, settings


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_allows_up_to_the_limit_then_blocks():
    clock = FakeClock()
    limiter = SlidingWindowLimiter(clock)
    assert all(limiter.check("k", 3, 60) is None for _ in range(3))
    assert limiter.check("k", 3, 60) is not None


def test_retry_after_counts_down_to_the_oldest_hit():
    clock = FakeClock()
    limiter = SlidingWindowLimiter(clock)
    for _ in range(3):
        limiter.check("k", 3, 60)
    clock.now += 20
    assert limiter.check("k", 3, 60) == pytest.approx(40)


def test_slots_free_up_after_the_window():
    clock = FakeClock()
    limiter = SlidingWindowLimiter(clock)
    for _ in range(3):
        limiter.check("k", 3, 60)
    clock.now += 61
    assert limiter.check("k", 3, 60) is None


def test_keys_are_independent():
    limiter = SlidingWindowLimiter(FakeClock())
    for _ in range(3):
        limiter.check("a", 3, 60)
    assert limiter.check("a", 3, 60) is not None
    assert limiter.check("b", 3, 60) is None


def test_reset_clears_everything():
    limiter = SlidingWindowLimiter(FakeClock())
    for _ in range(3):
        limiter.check("a", 3, 60)
    limiter.reset()
    assert limiter.check("a", 3, 60) is None


def make_client(monkeypatch, trust_forwarded=True):
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "trust_forwarded_for", trust_forwarded)
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware)

    @app.post("/scan")
    def scan():
        return {"ok": True}

    @app.get("/scan")
    def scan_get():
        return {"ok": True}

    @app.post("/explain")
    def explain():
        return {"ok": True}

    @app.post("/exercises/{exercise_id}/attempt")
    def attempt(exercise_id: str):
        return {"ok": True}

    @app.post("/auth/login")
    def login():
        return {"ok": True}

    @app.get("/health")
    def health():
        return {"ok": True}

    return TestClient(app)


def test_scan_is_limited_per_address(monkeypatch):
    client = make_client(monkeypatch)
    headers = {"X-Forwarded-For": "1.1.1.1"}
    assert all(client.post("/scan", headers=headers).status_code == 200 for _ in range(15))
    blocked = client.post("/scan", headers=headers)
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) >= 1
    assert "too many scans" in blocked.json()["detail"]


def test_another_address_is_not_affected(monkeypatch):
    client = make_client(monkeypatch)
    for _ in range(16):
        client.post("/scan", headers={"X-Forwarded-For": "1.1.1.1"})
    assert client.post("/scan", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 200


def test_logged_in_users_are_counted_per_user_not_per_address(monkeypatch):
    client = make_client(monkeypatch)
    headers = {"X-Forwarded-For": "1.1.1.1"}
    for _ in range(15):
        client.post("/scan", headers=headers, cookies={COOKIE_NAME: create_access_token(1)})
    blocked = client.post("/scan", headers=headers, cookies={COOKIE_NAME: create_access_token(1)})
    other_user = client.post("/scan", headers=headers, cookies={COOKIE_NAME: create_access_token(2)})
    assert blocked.status_code == 429
    assert other_user.status_code == 200


def test_forwarded_header_is_ignored_unless_trusted(monkeypatch):
    client = make_client(monkeypatch, trust_forwarded=False)
    for i in range(15):
        client.post("/scan", headers={"X-Forwarded-For": f"9.9.9.{i}"})
    spoofed = client.post("/scan", headers={"X-Forwarded-For": "8.8.8.8"})
    assert spoofed.status_code == 429


def test_get_requests_and_health_are_not_limited(monkeypatch):
    client = make_client(monkeypatch)
    assert all(client.get("/scan").status_code == 200 for _ in range(40))
    assert all(client.get("/health").status_code == 200 for _ in range(40))


def test_explain_has_a_global_cap_across_users(monkeypatch):
    client = make_client(monkeypatch)
    statuses = [
        client.post("/explain", cookies={COOKIE_NAME: create_access_token(user)}).status_code
        for user in range(1, 14)
    ]
    assert statuses[:12] == [200] * 12
    assert statuses[12] == 429


def test_one_user_hits_the_per_user_explain_limit_first(monkeypatch):
    client = make_client(monkeypatch)
    cookies = {COOKIE_NAME: create_access_token(1)}
    statuses = [client.post("/explain", cookies=cookies).status_code for _ in range(9)]
    assert statuses[:8] == [200] * 8
    assert statuses[8] == 429


def test_attempts_and_logins_are_limited(monkeypatch):
    client = make_client(monkeypatch)
    cookies = {COOKIE_NAME: create_access_token(1)}
    attempts = [client.post("/exercises/x/attempt", cookies=cookies).status_code for _ in range(21)]
    assert attempts[-1] == 429 and attempts[:20] == [200] * 20
    logins = [client.post("/auth/login").status_code for _ in range(11)]
    assert logins[-1] == 429 and logins[:10] == [200] * 10


def test_can_be_switched_off(monkeypatch):
    client = make_client(monkeypatch)
    monkeypatch.setattr(settings, "rate_limit_enabled", False)
    assert all(client.post("/scan").status_code == 200 for _ in range(40))


def test_production_requires_a_jwt_secret():
    with pytest.raises(ValueError):
        Settings(environment="production", jwt_secret_key="", _env_file=None)


def test_production_rejects_a_short_jwt_secret():
    with pytest.raises(ValueError):
        Settings(environment="production", jwt_secret_key="short", _env_file=None)


def test_production_accepts_a_long_jwt_secret():
    built = Settings(environment="production", jwt_secret_key="x" * 40, _env_file=None)
    assert built.jwt_secret_key == "x" * 40


def test_development_gets_a_random_secret_of_safe_length():
    first = Settings(jwt_secret_key="", _env_file=None)
    second = Settings(jwt_secret_key="", _env_file=None)
    assert len(first.jwt_secret_key) >= 32
    assert first.jwt_secret_key != second.jwt_secret_key