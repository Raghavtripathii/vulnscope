import shutil
import subprocess

import pytest

from app.detectors import semgrep_detector


def semgrep_runs() -> bool:
    if shutil.which("semgrep") is None:
        return False
    try:
        result = subprocess.run(["semgrep", "--version"], capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


pytestmark = pytest.mark.skipif(not semgrep_runs(), reason="semgrep cannot run here")

PYTHON_SQLI_VULNERABLE = [
    'cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n',
    'cur.execute("SELECT * FROM users WHERE name = \'%s\'" % name)\n',
    'cur.execute("SELECT * FROM users WHERE name = \'{}\'".format(name))\n',
    'cur.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n',
]

PYTHON_SQLI_SAFE = [
    'cur.execute("SELECT * FROM users WHERE name = ?", (name,))\n',
    'cur.execute("SELECT * FROM users WHERE name = %s", (name,))\n',
]

JAVASCRIPT_SQLI_VULNERABLE = [
    'db.query("SELECT * FROM users WHERE id = " + req.params.id);\n',
    'db.query(`SELECT * FROM users WHERE name = \'${name}\'`);\n',
]

JAVASCRIPT_SQLI_SAFE = [
    'db.query("SELECT * FROM users WHERE id = ?", [id]);\n',
    'db.query("SELECT * FROM users WHERE id = $1", [id]);\n',
]


@pytest.fixture(autouse=True)
def offline_rules(monkeypatch):
    monkeypatch.setattr(semgrep_detector, "SEMGREP_RULESETS", [str(semgrep_detector.CUSTOM_RULES_FILE)])


def scan(tmp_path, name, code):
    target = tmp_path / name
    target.write_text(code, encoding="utf-8")
    return semgrep_detector.run_semgrep(target)


def has_rule(findings, rule_name):
    return any(f["rule_id"].endswith(rule_name) for f in findings)


def test_python_hardcoded_secret_is_found(tmp_path):
    findings = scan(tmp_path, "config.py", 'api_key = "sk_live_abcdef123456"\n')
    assert has_rule(findings, "vulnscope-hardcoded-secret-python")


def test_javascript_innerhtml_sink_is_found(tmp_path):
    findings = scan(tmp_path, "page.js", "el.innerHTML = userInput;\n")
    assert has_rule(findings, "vulnscope-xss-html-sink")


def test_snippet_comes_from_source_not_login_notice(tmp_path):
    findings = scan(tmp_path, "config.py", 'api_key = "sk_live_abcdef123456"\n')
    assert findings
    assert findings[0]["code_snippet"] == 'api_key = "sk_live_abcdef123456"'
    assert findings[0]["line_number"] == 1


def test_clean_code_has_no_findings(tmp_path):
    assert scan(tmp_path, "clean.py", "total = 1 + 2\nprint(total)\n") == []


@pytest.mark.parametrize("code", PYTHON_SQLI_VULNERABLE)
def test_python_sqli_is_found(tmp_path, code):
    assert has_rule(scan(tmp_path, "query.py", code), "vulnscope-sqli-python")


@pytest.mark.parametrize("code", PYTHON_SQLI_SAFE)
def test_python_parameterized_query_is_not_flagged(tmp_path, code):
    assert not has_rule(scan(tmp_path, "query.py", code), "vulnscope-sqli-python")


@pytest.mark.parametrize("code", JAVASCRIPT_SQLI_VULNERABLE)
def test_javascript_sqli_is_found(tmp_path, code):
    assert has_rule(scan(tmp_path, "query.js", code), "vulnscope-sqli-javascript")


@pytest.mark.parametrize("code", JAVASCRIPT_SQLI_SAFE)
def test_javascript_parameterized_query_is_not_flagged(tmp_path, code):
    assert not has_rule(scan(tmp_path, "query.js", code), "vulnscope-sqli-javascript")