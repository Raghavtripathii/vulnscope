import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import get_current_user_id
from app.database import Base, get_db
from app.models import User
from app.routers import teacher as teacher_module
from app.routers.auth import router


@pytest.fixture()
def session_factory(monkeypatch):
    monkeypatch.setattr(teacher_module.settings, "teacher_emails", "Teacher@Example.com")
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = factory()
    db.add_all(
        [
            User(id=1, email="student@example.com", hashed_password="x"),
            User(id=2, email="teacher@example.com", hashed_password="x"),
        ]
    )
    db.commit()
    db.close()
    return factory


def make_client(factory, user_id):
    app = FastAPI()
    app.include_router(router)

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user_id] = lambda: user_id
    return TestClient(app)


def test_me_returns_email_for_a_student(session_factory):
    body = make_client(session_factory, 1).get("/auth/me").json()
    assert body == {"id": 1, "email": "student@example.com", "is_teacher": False}


def test_me_marks_a_teacher_case_insensitively(session_factory):
    body = make_client(session_factory, 2).get("/auth/me").json()
    assert body["is_teacher"] is True


def test_me_requires_login(session_factory):
    assert make_client(session_factory, None).get("/auth/me").status_code == 401


def test_me_does_not_leak_the_password_hash(session_factory):
    assert "hashed_password" not in make_client(session_factory, 1).get("/auth/me").text


def test_me_with_a_deleted_user_is_401(session_factory):
    assert make_client(session_factory, 99).get("/auth/me").status_code == 401