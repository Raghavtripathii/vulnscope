import pytest

from app import scanner


@pytest.fixture
def calls(monkeypatch):
    record = {"semgrep": [], "bandit": [], "eslint": []}

    def fake(name):
        def run(path):
            record[name].append((path, path.read_text(encoding="utf-8")))
            return [{"detector": name}]

        return run

    monkeypatch.setattr(scanner, "run_semgrep", fake("semgrep"))
    monkeypatch.setattr(scanner, "run_bandit", fake("bandit"))
    monkeypatch.setattr(scanner, "run_eslint", fake("eslint"))
    return record


def test_python_runs_semgrep_and_bandit_only(calls):
    findings = scanner.scan_text("x = 1\n", "python")
    assert [f["detector"] for f in findings] == ["semgrep", "bandit"]
    assert calls["eslint"] == []


def test_javascript_runs_semgrep_and_eslint_only(calls):
    findings = scanner.scan_text("let a = 1;\n", "javascript")
    assert [f["detector"] for f in findings] == ["semgrep", "eslint"]
    assert calls["bandit"] == []


def test_code_is_written_with_the_right_extension_and_removed_afterwards(calls):
    scanner.scan_text("let a = 1;\n", "javascript")
    path, content = calls["semgrep"][0]
    assert path.suffix == ".js"
    assert content == "let a = 1;\n"
    assert not path.exists()


def test_non_ascii_code_survives_the_round_trip(calls):
    scanner.scan_text("name = 'é'\n", "python")
    assert calls["semgrep"][0][1] == "name = 'é'\n"


def test_temp_file_is_removed_even_if_a_detector_crashes(monkeypatch, calls):
    seen = {}

    def boom(path):
        seen["path"] = path
        raise RuntimeError("detector crashed")

    monkeypatch.setattr(scanner, "run_semgrep", boom)
    with pytest.raises(RuntimeError):
        scanner.scan_text("x = 1\n", "python")
    assert not seen["path"].exists()