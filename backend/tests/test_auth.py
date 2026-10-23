import uuid

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_register_and_login():
    email = f"test-{uuid.uuid4().hex[:8]}@example.com"
    password = "correct-horse-battery"

    register_response = client.post(
        "/auth/register",
        json={"email": email, "password": password},
    )
    assert register_response.status_code == 201
    assert register_response.json()["email"] == email
    assert "vulnscope_token" in register_response.cookies

    login_response = client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )
    assert login_response.status_code == 200
    assert "vulnscope_token" in login_response.cookies


def test_login_wrong_password_rejected():
    email = f"test-{uuid.uuid4().hex[:8]}@example.com"
    client.post("/auth/register", json={"email": email, "password": "correct-horse-battery"})

    response = client.post("/auth/login", json={"email": email, "password": "wrong-password"})
    assert response.status_code == 401