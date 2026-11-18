import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import get_current_user_id
from app.database import Base, get_db
from app.exercises import EXERCISES, get_exercise
from app.models import ExerciseAttempt, User
from app.routers import practice as practice_module
from app.routers.practice import router
from app.scanner import ScanResult

SQLI_FINDING = {
    "detector": "bandit",
    "rule_id": "B608",
    "vulnerability_type": "hardcoded_sql_expressions",
    "severity": "medium",
    "line_number": 5,
    "message": "possible sql injection",
    "code_snippet": "cur.execute(query)",
}

SECRET_FINDING = {
    "detector": "semgrep",
    "rule_id": "vulnscope-hardcoded-secret-python",
    "vulnerability_type": "CWE-798: Use of Hard-coded Credentials",
    "severity": "medium",
    "line_number": 2,
    "message": "secret",
    "code_snippet": 'KEY = "abcdefgh1234"',
}

OK = {"semgrep": "ok", "bandit": "ok"}


@pytest.fixture()
def session_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = factory()
    db.add_all(
        [
            User(id=1, email="a@example.com", hashed_password="x"),
            User(id=2, email="b@example.com", hashed_password="x"),
        ]
    )
    db.commit()
    db.close()
    return factory


def make_client(session_factory, user_id):
    app = FastAPI()
    app.include_router(router)

    def override_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user_id] = lambda: user_id
    return TestClient(app)


def fake_scan(monkeypatch, findings, detectors=None):
    calls = []

    def scan(code, language):
        calls.append((code, language))
        return ScanResult(findings=list(findings), detectors=dict(detectors or OK))

    monkeypatch.setattr(practice_module, "scan_with_status", scan)
    return calls


def attempts_in_db(session_factory):
    db = session_factory()
    try:
        return db.query(ExerciseAttempt).order_by(ExerciseAttempt.id).all()
    finally:
        db.close()


def test_every_exercise_is_well_formed():
    ids = [item.id for item in EXERCISES]
    assert len(ids) == len(set(ids))
    for item in EXERCISES:
        assert item.language in ("python", "javascript")
        assert item.vulnerable_code.strip() and item.reference_fix.strip() and item.hint.strip()
        assert item.vulnerable_code != item.reference_fix


def test_list_returns_all_exercises_without_answers(session_factory):
    response = make_client(session_factory, 1).get("/exercises")
    assert response.status_code == 200
    body = response.json()
    assert len(body) == len(EXERCISES)
    assert all(item["completed"] is False for item in body)
    assert "reference_fix" not in response.text


def test_list_can_filter_by_class(session_factory):
    body = make_client(session_factory, 1).get("/exercises?vulnerability_class=xss").json()
    assert body and all(item["vulnerability_class"] == "xss" for item in body)


def test_list_rejects_unknown_class(session_factory):
    assert make_client(session_factory, 1).get("/exercises?vulnerability_class=other").status_code == 422


def test_detail_shows_task_but_not_the_answer(session_factory):
    response = make_client(session_factory, 1).get("/exercises/sqli-py-login")
    assert response.status_code == 200
    body = response.json()
    assert body["vulnerable_code"] == get_exercise("sqli-py-login").vulnerable_code
    assert body["hint"]
    assert "reference_fix" not in body
    assert get_exercise("sqli-py-login").reference_fix not in response.text


def test_unknown_exercise_is_404(session_factory):
    client = make_client(session_factory, 1)
    assert client.get("/exercises/nope").status_code == 404
    assert client.post("/exercises/nope/attempt", json={"code": "x"}).status_code == 404


def test_anonymous_gets_401_everywhere(session_factory):
    client = make_client(session_factory, None)
    assert client.get("/exercises").status_code == 401
    assert client.get("/exercises/sqli-py-login").status_code == 401
    assert client.post("/exercises/sqli-py-login/attempt", json={"code": "x"}).status_code == 401
    assert client.get("/me/progress").status_code == 401


def test_passing_attempt_reveals_the_reference_fix_and_is_recorded(session_factory, monkeypatch):
    calls = fake_scan(monkeypatch, [])
    response = make_client(session_factory, 1).post("/exercises/sqli-js-delete/attempt", json={"code": "fixed code"})
    assert response.status_code == 200
    body = response.json()
    assert body["passed"] is True
    assert body["remaining"] == []
    assert body["reference_fix"] == get_exercise("sqli-js-delete").reference_fix
    assert calls == [("fixed code", "javascript")]
    saved = attempts_in_db(session_factory)
    assert [(row.user_id, row.exercise_id, row.passed) for row in saved] == [(1, "sqli-js-delete", True)]


def test_failing_attempt_hides_the_answer_and_lists_what_remains(session_factory, monkeypatch):
    fake_scan(monkeypatch, [SQLI_FINDING])
    response = make_client(session_factory, 1).post("/exercises/sqli-py-login/attempt", json={"code": "still bad"})
    body = response.json()
    assert body["passed"] is False
    assert body["reference_fix"] is None
    assert body["remaining"] == [{"line_number": 5, "vulnerability_class": "sql_injection", "label": "SQL injection"}]
    assert get_exercise("sqli-py-login").reference_fix not in response.text
    assert [row.passed for row in attempts_in_db(session_factory)] == [False]


def test_a_different_remaining_issue_does_not_block_passing(session_factory, monkeypatch):
    fake_scan(monkeypatch, [SECRET_FINDING])
    body = make_client(session_factory, 1).post("/exercises/sqli-py-login/attempt", json={"code": "x = 1"}).json()
    assert body["passed"] is True
    assert body["remaining"][0]["vulnerability_class"] == "hardcoded_secret"


def test_unfinished_detectors_are_never_graded_or_recorded(session_factory, monkeypatch):
    fake_scan(monkeypatch, [], detectors={"semgrep": "timeout", "bandit": "ok"})
    response = make_client(session_factory, 1).post("/exercises/sqli-py-login/attempt", json={"code": "x = 1"})
    assert response.status_code == 503
    assert attempts_in_db(session_factory) == []


def test_empty_and_oversized_code_are_rejected(session_factory, monkeypatch):
    fake_scan(monkeypatch, [])
    client = make_client(session_factory, 1)
    assert client.post("/exercises/sqli-py-login/attempt", json={"code": ""}).status_code == 422
    monkeypatch.setattr(practice_module.settings, "max_code_size_bytes", 10)
    assert client.post("/exercises/sqli-py-login/attempt", json={"code": "x" * 11}).status_code == 413
    assert attempts_in_db(session_factory) == []


def test_completed_flag_and_progress_follow_attempts(session_factory, monkeypatch):
    client = make_client(session_factory, 1)
    fake_scan(monkeypatch, [SQLI_FINDING])
    client.post("/exercises/sqli-py-login/attempt", json={"code": "bad"})
    client.post("/exercises/sqli-py-login/attempt", json={"code": "bad again"})
    fake_scan(monkeypatch, [])
    client.post("/exercises/sqli-py-login/attempt", json={"code": "good"})
    client.post("/exercises/xss-js-greeting/attempt", json={"code": "good"})

    listing = {item["id"]: item["completed"] for item in client.get("/exercises").json()}
    assert listing["sqli-py-login"] is True
    assert listing["xss-js-greeting"] is True
    assert listing["sqli-py-search"] is False

    progress = client.get("/me/progress").json()
    assert progress["exercises_total"] == len(EXERCISES)
    assert progress["exercises_completed"] == 2
    by_class = {item["vulnerability_class"]: item for item in progress["by_class"]}
    assert by_class["sql_injection"]["completed"] == 1
    assert by_class["xss"]["completed"] == 1
    assert by_class["hardcoded_secret"]["completed"] == 0
    assert by_class["broken_authentication"]["total"] == 2
    detail = {item["exercise_id"]: item for item in progress["exercises"]}
    assert detail["sqli-py-login"]["attempts"] == 3
    assert detail["sqli-py-login"]["completed"] is True
    assert detail["sqli-py-search"]["attempts"] == 0
    assert detail["sqli-py-search"]["last_attempt_at"] is None


def test_progress_is_private_to_each_user(session_factory, monkeypatch):
    fake_scan(monkeypatch, [])
    make_client(session_factory, 1).post("/exercises/sqli-py-login/attempt", json={"code": "good"})
    other = make_client(session_factory, 2)
    assert other.get("/me/progress").json()["exercises_completed"] == 0
    assert {item["id"]: item["completed"] for item in other.get("/exercises").json()}["sqli-py-login"] is False