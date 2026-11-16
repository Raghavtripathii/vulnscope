import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import get_current_user_id
from app.database import Base, get_db
from app.models import Finding, Scan, User
from app.routers.me import router

SQLI = dict(
    vulnerability_type="CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
    severity="high",
    line_number=3,
    message="sql built from string",
    code_snippet='cur.execute("SELECT " + name)',
)

SECRET = dict(
    vulnerability_type="CWE-798: Use of Hard-coded Credentials",
    severity="high",
    line_number=1,
    message="hardcoded password",
    code_snippet='password = "hunter2hunter2"',
)


def day(number):
    return datetime.datetime(2026, 11, number, 12, 0, 0)


@pytest.fixture()
def session_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture()
def seeded(session_factory):
    db = session_factory()
    db.add_all(
        [
            User(id=1, email="a@example.com", hashed_password="x"),
            User(id=2, email="b@example.com", hashed_password="x"),
            User(id=3, email="c@example.com", hashed_password="x"),
        ]
    )
    db.add_all(
        [
            Scan(id=1, user_id=1, language="python", filename="one.py", created_at=day(1)),
            Scan(id=2, user_id=1, language="python", filename="two.py", created_at=day(2)),
            Scan(id=3, user_id=1, language="javascript", filename=None, created_at=day(3)),
            Scan(id=4, user_id=2, language="python", filename="other.py", created_at=day(4)),
            Scan(id=5, user_id=None, language="python", filename="anon.py", created_at=day(5)),
        ]
    )
    db.flush()
    db.add_all(
        [
            Finding(scan_id=1, detector="semgrep", rule_id="python.sqli", **SQLI),
            Finding(scan_id=1, detector="bandit", rule_id="B608", **SQLI),
            Finding(scan_id=1, detector="semgrep", rule_id="vulnscope-hardcoded-secret-python", **SECRET),
            Finding(scan_id=2, detector="bandit", rule_id="B608", **SQLI),
            Finding(scan_id=4, detector="bandit", rule_id="B608", **SQLI),
            Finding(scan_id=5, detector="bandit", rule_id="B608", **SQLI),
        ]
    )
    db.commit()
    db.close()
    return session_factory


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


def test_history_lists_newest_first_with_counts(seeded):
    body = make_client(seeded, 1).get("/me/scans").json()
    assert [item["scan_id"] for item in body] == [3, 2, 1]
    assert body[0]["issue_count"] == 0
    assert body[0]["issues_by_class"] == {}
    assert body[1]["issues_by_class"] == {"sql_injection": 1}
    assert body[2]["issue_count"] == 2
    assert body[2]["issues_by_class"] == {"sql_injection": 1, "hardcoded_secret": 1}
    assert body[2]["filename"] == "one.py"


def test_history_only_shows_own_scans(seeded):
    ids = [item["scan_id"] for item in make_client(seeded, 2).get("/me/scans").json()]
    assert ids == [4]


def test_history_limit_is_applied_and_validated(seeded):
    client = make_client(seeded, 1)
    assert [item["scan_id"] for item in client.get("/me/scans?limit=1").json()] == [3]
    assert client.get("/me/scans?limit=0").status_code == 422
    assert client.get("/me/scans?limit=201").status_code == 422


def test_stats_totals_and_repeated_mistakes(seeded):
    body = make_client(seeded, 1).get("/me/stats").json()
    assert body["scans_count"] == 3
    assert body["issues_total"] == 3
    assert body["issues_by_class"] == {"sql_injection": 2, "hardcoded_secret": 1}
    repeated = body["repeated_mistakes"]
    assert [item["vulnerability_class"] for item in repeated] == ["sql_injection"]
    assert repeated[0]["label"] == "SQL injection"
    assert repeated[0]["scans_affected"] == 2
    assert repeated[0]["issues_total"] == 2
    assert repeated[0]["last_seen"].startswith("2026-11-02")


def test_one_scan_with_many_issues_is_not_a_repeat(seeded):
    body = make_client(seeded, 2).get("/me/stats").json()
    assert body["issues_total"] == 1
    assert body["repeated_mistakes"] == []


def test_new_user_gets_empty_results(seeded):
    client = make_client(seeded, 3)
    assert client.get("/me/scans").json() == []
    assert client.get("/me/stats").json() == {
        "scans_count": 0,
        "issues_total": 0,
        "issues_by_class": {},
        "repeated_mistakes": [],
    }


def test_anonymous_gets_401(seeded):
    client = make_client(seeded, None)
    assert client.get("/me/scans").status_code == 401
    assert client.get("/me/stats").status_code == 401