import subprocess
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import scanner
from app.auth import get_current_user_id
from app.database import Base, get_db
from app.detectors import bandit_detector, eslint_detector, semgrep_detector
from app.detectors.result import DetectorFindings, status_of
from app.routers import scan as scan_module
from app.scanner import DetectorFailure, ScanResult, scan_text, scan_with_status

FINDING = {
    "detector": "semgrep",
    "rule_id": "r1",
    "vulnerability_type": "CWE-89",
    "severity": "high",
    "line_number": 3,
    "message": "m",
    "code_snippet": "x",
}

DETECTORS = [
    (semgrep_detector, "run_semgrep", "{}"),
    (bandit_detector, "run_bandit", "{}"),
    (eslint_detector, "run_eslint", "[]"),
]


def fake_run(stdout="", returncode=0):
    return lambda *args, **kwargs: SimpleNamespace(stdout=stdout, stderr="boom", returncode=returncode)


def raising(error):
    def run(*args, **kwargs):
        raise error

    return run


@pytest.mark.parametrize("module,name,empty_json", DETECTORS)
def test_successful_run_is_ok(monkeypatch, tmp_path, module, name, empty_json):
    monkeypatch.setattr(module.subprocess, "run", fake_run(stdout=empty_json))
    result = getattr(module, name)(tmp_path / "a.py")
    assert result == []
    assert status_of(result) == "ok"


@pytest.mark.parametrize("module,name,empty_json", DETECTORS)
def test_timeout_is_reported(monkeypatch, tmp_path, module, name, empty_json):
    monkeypatch.setattr(module.subprocess, "run", raising(subprocess.TimeoutExpired(cmd="x", timeout=1)))
    result = getattr(module, name)(tmp_path / "a.py")
    assert result == []
    assert status_of(result) == "timeout"


@pytest.mark.parametrize("module,name,empty_json", DETECTORS)
def test_missing_or_blocked_tool_is_unavailable(monkeypatch, tmp_path, module, name, empty_json):
    monkeypatch.setattr(module.subprocess, "run", raising(OSError("blocked")))
    result = getattr(module, name)(tmp_path / "a.py")
    assert result == []
    assert status_of(result) == "unavailable"


@pytest.mark.parametrize("module,name,empty_json", DETECTORS)
def test_empty_output_is_failed(monkeypatch, tmp_path, module, name, empty_json):
    monkeypatch.setattr(module.subprocess, "run", fake_run(stdout="", returncode=2))
    result = getattr(module, name)(tmp_path / "a.py")
    assert status_of(result) == "failed"


@pytest.mark.parametrize("module,name,empty_json", DETECTORS)
def test_invalid_json_is_failed(monkeypatch, tmp_path, module, name, empty_json):
    monkeypatch.setattr(module.subprocess, "run", fake_run(stdout="not json"))
    result = getattr(module, name)(tmp_path / "a.py")
    assert status_of(result) == "failed"


def test_plain_lists_count_as_ok():
    assert status_of([FINDING]) == "ok"


def patch_detectors(monkeypatch, semgrep=None, bandit=None, eslint=None):
    monkeypatch.setattr(scanner, "run_semgrep", lambda path: semgrep if semgrep is not None else DetectorFindings())
    monkeypatch.setattr(scanner, "run_bandit", lambda path: bandit if bandit is not None else DetectorFindings())
    monkeypatch.setattr(scanner, "run_eslint", lambda path: eslint if eslint is not None else DetectorFindings())


def test_python_scan_reports_semgrep_and_bandit(monkeypatch):
    patch_detectors(monkeypatch, semgrep=DetectorFindings([FINDING]))
    result = scan_with_status("x = 1\n", "python")
    assert result.detectors == {"semgrep": "ok", "bandit": "ok"}
    assert result.complete is True
    assert result.findings == [FINDING]


def test_javascript_scan_reports_semgrep_and_eslint(monkeypatch):
    patch_detectors(monkeypatch)
    result = scan_with_status("var a = 1;\n", "javascript")
    assert result.detectors == {"semgrep": "ok", "eslint": "ok"}


def test_one_failed_detector_makes_the_scan_incomplete_but_keeps_other_findings(monkeypatch):
    patch_detectors(
        monkeypatch,
        semgrep=DetectorFindings(status="timeout"),
        bandit=DetectorFindings([dict(FINDING, detector="bandit")]),
    )
    result = scan_with_status("x = 1\n", "python")
    assert result.detectors == {"semgrep": "timeout", "bandit": "ok"}
    assert result.complete is False
    assert len(result.findings) == 1


def test_plain_list_mocks_still_work(monkeypatch):
    monkeypatch.setattr(scanner, "run_semgrep", lambda path: [FINDING])
    monkeypatch.setattr(scanner, "run_bandit", lambda path: [])
    result = scan_with_status("x = 1\n", "python")
    assert result.complete is True
    assert result.findings == [FINDING]


def test_scan_text_returns_findings_when_all_detectors_finish(monkeypatch):
    patch_detectors(monkeypatch, semgrep=DetectorFindings([FINDING]))
    assert scan_text("x = 1\n", "python") == [FINDING]


def test_scan_text_raises_when_a_detector_did_not_finish(monkeypatch):
    patch_detectors(monkeypatch, bandit=DetectorFindings(status="unavailable"))
    with pytest.raises(DetectorFailure) as error:
        scan_text("x = 1\n", "python")
    assert "bandit" in str(error.value)


def test_temp_file_is_removed_even_when_a_detector_crashes(monkeypatch):
    seen = {}

    def crash(path):
        seen["path"] = path
        raise RuntimeError("boom")

    monkeypatch.setattr(scanner, "run_semgrep", crash)
    with pytest.raises(RuntimeError):
        scan_with_status("x = 1\n", "python")
    assert not seen["path"].exists()


def make_scan_client(monkeypatch, result):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(scan_module, "scan_with_status", lambda code, language: result)
    app = FastAPI()
    app.include_router(scan_module.router)
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user_id] = lambda: None
    return TestClient(app)


def test_scan_response_includes_detector_status(monkeypatch):
    result = ScanResult(findings=[FINDING], detectors={"semgrep": "timeout", "bandit": "ok"})
    client = make_scan_client(monkeypatch, result)
    response = client.post("/scan", json={"code": "x = 1", "language": "python"})
    assert response.status_code == 200
    body = response.json()
    assert body["detectors"] == {"semgrep": "timeout", "bandit": "ok"}
    assert body["complete"] is False
    assert len(body["findings"]) == 1


def test_scan_response_marks_complete_scans(monkeypatch):
    result = ScanResult(findings=[], detectors={"semgrep": "ok", "bandit": "ok"})
    client = make_scan_client(monkeypatch, result)
    body = client.post("/scan", json={"code": "x = 1", "language": "python"}).json()
    assert body["complete"] is True
    assert body["findings"] == []