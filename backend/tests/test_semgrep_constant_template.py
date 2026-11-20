import json
import subprocess
from types import SimpleNamespace

from app.detectors import semgrep_detector
from app.detectors.semgrep_detector import is_constant_template_call, run_semgrep

SAFE = '''from flask import render_template_string, request


def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello, {{ name }}</h1>", name=name)
'''

CONCAT = '''from flask import render_template_string, request


def profile():
    bio = request.form["bio"]
    return render_template_string("<p>" + bio + "</p>")
'''

FSTRING = '''from flask import render_template_string


def page(bio):
    return render_template_string(f"<p>{bio}</p>")
'''

FORMAT = '''from flask import render_template_string


def page(bio):
    return render_template_string("<p>{}</p>".format(bio))
'''

VARIABLE = '''from flask import render_template_string


def page(template):
    return render_template_string(template)
'''

MULTILINE = '''from flask import render_template_string


def page(name):
    return render_template_string(
        "<h1>Hello, {{ name }}</h1>",
        name=name,
    )
'''

RULE_ID = "x.python.flask.security.audit.render-template-string.render-template-string"


def write(tmp_path, code):
    path = tmp_path / "snippet.py"
    path.write_text(code, encoding="utf-8")
    return path


def test_plain_string_template_is_treated_as_safe(tmp_path):
    assert is_constant_template_call(write(tmp_path, SAFE), 6) is True


def test_multiline_call_with_plain_string_is_safe(tmp_path):
    assert is_constant_template_call(write(tmp_path, MULTILINE), 6) is True


def test_built_templates_are_not_treated_as_safe(tmp_path):
    for code in (CONCAT, FSTRING, FORMAT, VARIABLE):
        assert is_constant_template_call(write(tmp_path, code), 6 if code is CONCAT else 5) is False


def test_unparseable_file_is_not_treated_as_safe(tmp_path):
    assert is_constant_template_call(write(tmp_path, "def broken(:\n"), 1) is False


def test_other_line_is_not_treated_as_safe(tmp_path):
    assert is_constant_template_call(write(tmp_path, SAFE), 5) is False


def fake_semgrep(monkeypatch, line, rule_id=RULE_ID):
    payload = {
        "results": [
            {
                "check_id": rule_id,
                "start": {"line": line},
                "extra": {"severity": "WARNING", "message": "template", "metadata": {"cwe": ["CWE-96"]}, "lines": "x"},
            }
        ]
    }
    monkeypatch.setattr(
        semgrep_detector.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(stdout=json.dumps(payload), stderr="", returncode=1),
    )


def test_run_semgrep_drops_finding_on_safe_template(tmp_path, monkeypatch):
    fake_semgrep(monkeypatch, 6)
    assert list(run_semgrep(write(tmp_path, SAFE))) == []


def test_run_semgrep_keeps_finding_on_concatenated_template(tmp_path, monkeypatch):
    fake_semgrep(monkeypatch, 6)
    findings = run_semgrep(write(tmp_path, CONCAT))
    assert len(findings) == 1
    assert findings[0]["rule_id"] == RULE_ID


def test_run_semgrep_keeps_other_rules_on_the_same_line(tmp_path, monkeypatch):
    fake_semgrep(monkeypatch, 6, rule_id="x.generic.secrets.hardcoded-credential")
    assert len(run_semgrep(write(tmp_path, SAFE))) == 1