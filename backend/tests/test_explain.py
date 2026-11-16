import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import get_current_user_id
from app.database import Base, get_db
from app.explanations.schema import Explanation
from app.models import Finding, Scan, User
from app.routers import explain as explain_module
from app.routers.explain import get_explanation_service, router


class FakeService:
    def __init__(self):
        self.calls = []

    def explain(self, issue, language):
        self.calls.append((issue, language))
        return Explanation(
            vulnerability_type="SQL injection",
            exploit_scenario="scenario",
            fixed_code_example="fix",
            owasp_mapping=issue.owasp,
            source="static",
        )


@pytest.fixture()
def session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture()
def seeded(session_factory):
    db = session_factory()
    db.add_all([User(id=1, email="a@example.com", hashed_password="x"), User(id=2, email="b@example.com", hashed_password="x")])
    db.add_all(
        [
            Scan(id=10, user_id=1, language="python"),
            Scan(id=11, user_id=2, language="python"),
            Scan(id=12, user_id=None, language="python"),
            Scan(id=13, user_id=1, language="javascript"),
        ]
    )
    db.flush()
    sqli = dict(
        vulnerability_type="CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        severity="high",
        line_number=3,
        message="sql built from string",
        code_snippet='cur.execute("SELECT " + name)',
    )
    db.add_all(
        [
            Finding(scan_id=10, detector="semgrep", rule_id="python.sqli", **sqli),
            Finding(scan_id=10, detector="bandit", rule_id="B608", **sqli),
            Finding(
                scan_id=10,
                detector="semgrep",
                rule_id="vulnscope-hardcoded-secret-python",
                vulnerability_type="CWE-798: Use of Hard-coded Credentials",
                severity="high",
                line_number=1,
                message="hardcoded password",
                code_snippet='password = "hunter2hunter2"',
            ),
            Finding(scan_id=11, detector="bandit", rule_id="B608", **sqli),
            Finding(scan_id=12, detector="bandit", rule_id="B608", **sqli),
            Finding(scan_id=13, detector="semgrep", rule_id="js.sqli", **sqli),
        ]
    )
    db.commit()
    db.close()
    return session_factory


def make_client(session_factory, user_id, service=None):
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
    app.dependency_overrides[get_explanation_service] = lambda: service or FakeService()
    return TestClient(app)


def test_lists_grouped_issues_in_line_order(seeded):
    client = make_client(seeded, 1)
    response = client.get("/scans/10/issues")
    assert response.status_code == 200
    body = response.json()
    assert [item["index"] for item in body] == [0, 1]
    assert [item["line_number"] for item in body] == [1, 3]
    assert body[0]["vulnerability_class"] == "hardcoded_secret"
    assert body[1]["vulnerability_class"] == "sql_injection"
    assert body[1]["label"] == "SQL injection"
    assert body[1]["detectors"] == ["bandit", "semgrep"]


def test_other_users_scan_is_hidden(seeded):
    client = make_client(seeded, 1)
    assert client.get("/scans/11/issues").status_code == 404
    assert client.post("/explain", json={"scan_id": 11, "issue_index": 0}).status_code == 404


def test_anonymous_gets_401(seeded):
    client = make_client(seeded, None)
    assert client.get("/scans/10/issues").status_code == 401
    assert client.post("/explain", json={"scan_id": 10, "issue_index": 0}).status_code == 401


def test_anonymous_owned_scan_is_not_reachable(seeded):
    client = make_client(seeded, 1)
    assert client.get("/scans/12/issues").status_code == 404


def test_unknown_scan_is_404(seeded):
    client = make_client(seeded, 1)
    assert client.get("/scans/999/issues").status_code == 404
    assert client.post("/explain", json={"scan_id": 999, "issue_index": 0}).status_code == 404


def test_explain_uses_stored_issue_and_scan_language(seeded):
    service = FakeService()
    client = make_client(seeded, 1, service)
    response = client.post("/explain", json={"scan_id": 13, "issue_index": 0})
    assert response.status_code == 200
    assert response.json()["source"] == "static"
    issue, language = service.calls[0]
    assert language == "javascript"
    assert issue.vulnerability_class == "sql_injection"
    assert issue.line_number == 3


def test_explain_picks_the_requested_index(seeded):
    service = FakeService()
    client = make_client(seeded, 1, service)
    client.post("/explain", json={"scan_id": 10, "issue_index": 0})
    assert service.calls[0][0].vulnerability_class == "hardcoded_secret"


def test_out_of_range_index_is_404(seeded):
    client = make_client(seeded, 1)
    assert client.post("/explain", json={"scan_id": 10, "issue_index": 2}).status_code == 404


def test_negative_index_is_422(seeded):
    client = make_client(seeded, 1)
    assert client.post("/explain", json={"scan_id": 10, "issue_index": -1}).status_code == 422


def test_build_service_without_key_uses_written_explanations(monkeypatch):
    monkeypatch.setattr(explain_module.settings, "gemini_api_key", type(explain_module.settings.gemini_api_key)(""))
    explain_module.build_service.cache_clear()
    assert explain_module.build_service().llm is None
    explain_module.build_service.cache_clear()


def test_build_service_with_key_enables_the_model(monkeypatch):
    monkeypatch.setattr(explain_module.settings, "gemini_api_key", type(explain_module.settings.gemini_api_key)("fake-key"))
    explain_module.build_service.cache_clear()
    assert explain_module.build_service().llm is not None
    explain_module.build_service.cache_clear()