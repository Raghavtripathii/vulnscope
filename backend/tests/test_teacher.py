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
from app.routers import teacher as teacher_module
from app.routers.teacher import router

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

XSS = dict(
    vulnerability_type="CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    severity="high",
    line_number=2,
    message="unsafe html sink",
    code_snippet="el.innerHTML = value",
)

TEACHER_ID = 10


def day(number):
    return datetime.datetime(2026, 11, number, 12, 0, 0)


@pytest.fixture()
def session_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture()
def seeded(session_factory, monkeypatch):
    monkeypatch.setattr(teacher_module.settings, "teacher_emails", " Teacher@Example.com , other@example.com ")
    db = session_factory()
    db.add_all(
        [
            User(id=1, email="s1@example.com", hashed_password="x"),
            User(id=2, email="s2@example.com", hashed_password="x"),
            User(id=3, email="s3@example.com", hashed_password="x"),
            User(id=TEACHER_ID, email="teacher@example.com", hashed_password="x"),
        ]
    )
    db.add_all(
        [
            Scan(id=1, user_id=1, language="python", created_at=day(1)),
            Scan(id=2, user_id=1, language="python", created_at=day(2)),
            Scan(id=3, user_id=2, language="python", created_at=day(3)),
            Scan(id=4, user_id=3, language="javascript", created_at=day(4)),
            Scan(id=5, user_id=None, language="python", created_at=day(5)),
        ]
    )
    db.flush()
    db.add_all(
        [
            Finding(scan_id=1, detector="semgrep", rule_id="python.sqli", **SQLI),
            Finding(scan_id=1, detector="bandit", rule_id="B608", **SQLI),
            Finding(scan_id=1, detector="semgrep", rule_id="vulnscope-hardcoded-secret-python", **SECRET),
            Finding(scan_id=2, detector="bandit", rule_id="B608", **SQLI),
            Finding(scan_id=3, detector="bandit", rule_id="B608", **SQLI),
            Finding(scan_id=4, detector="semgrep", rule_id="vulnscope-xss-html-sink", **XSS),
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


def test_teacher_sees_class_wide_stats(seeded):
    response = make_client(seeded, TEACHER_ID).get("/teacher/stats")
    assert response.status_code == 200
    body = response.json()
    assert body["students_count"] == 3
    assert body["scans_count"] == 4
    assert body["issues_total"] == 5
    by_class = {item["vulnerability_class"]: item for item in body["classes"]}
    assert by_class["sql_injection"]["issues_total"] == 3
    assert by_class["sql_injection"]["students_affected"] == 2
    assert by_class["sql_injection"]["students_repeating"] == 1
    assert by_class["sql_injection"]["share_of_students"] == 0.667
    assert by_class["hardcoded_secret"]["students_affected"] == 1
    assert by_class["hardcoded_secret"]["students_repeating"] == 0
    assert by_class["xss"]["issues_total"] == 1


def test_classes_are_sorted_by_how_many_students_struggle(seeded):
    body = make_client(seeded, TEACHER_ID).get("/teacher/stats").json()
    assert [item["vulnerability_class"] for item in body["classes"]] == [
        "sql_injection",
        "hardcoded_secret",
        "xss",
        "broken_authentication",
    ]


def test_core_classes_always_present_even_with_zero(seeded):
    body = make_client(seeded, TEACHER_ID).get("/teacher/stats").json()
    broken = [item for item in body["classes"] if item["vulnerability_class"] == "broken_authentication"][0]
    assert broken["issues_total"] == 0
    assert broken["students_affected"] == 0
    assert broken["share_of_students"] == 0.0


def test_anonymous_scans_are_not_counted(seeded):
    body = make_client(seeded, TEACHER_ID).get("/teacher/stats").json()
    assert body["scans_count"] == 4


def test_no_student_identity_in_the_response(seeded):
    text = make_client(seeded, TEACHER_ID).get("/teacher/stats").text
    assert "@" not in text
    assert "user_id" not in text


def test_students_are_forbidden(seeded):
    assert make_client(seeded, 1).get("/teacher/stats").status_code == 403


def test_anonymous_gets_401(seeded):
    assert make_client(seeded, None).get("/teacher/stats").status_code == 401


def test_nobody_is_a_teacher_when_the_list_is_empty(seeded, monkeypatch):
    monkeypatch.setattr(teacher_module.settings, "teacher_emails", "")
    assert make_client(seeded, TEACHER_ID).get("/teacher/stats").status_code == 403


def test_empty_class_returns_zeros(session_factory, monkeypatch):
    monkeypatch.setattr(teacher_module.settings, "teacher_emails", "teacher@example.com")
    db = session_factory()
    db.add(User(id=TEACHER_ID, email="teacher@example.com", hashed_password="x"))
    db.commit()
    db.close()
    body = make_client(session_factory, TEACHER_ID).get("/teacher/stats").json()
    assert body["students_count"] == 0
    assert body["scans_count"] == 0
    assert body["issues_total"] == 0
    assert all(item["issues_total"] == 0 for item in body["classes"])