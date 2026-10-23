from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_detects_hardcoded_password():
    vulnerable_code = 'password = "supersecret123"\nprint(password)\n'
    response = client.post(
        "/scan",
        json={"code": vulnerable_code, "language": "python", "filename": "test.py"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["language"] == "python"
    assert len(body["findings"]) >= 1


def test_scan_rejects_unsupported_language():
    response = client.post(
        "/scan",
        json={"code": "print(1)", "language": "ruby"},
    )
    assert response.status_code == 422