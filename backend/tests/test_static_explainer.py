import shutil
import subprocess

import pytest

from app.detectors import semgrep_detector
from app.explanations.grouping import Issue
from app.explanations.static_explainer import STATIC_EXPLANATIONS, StaticExplainer

LANGUAGES = ["python", "javascript"]
SUFFIX = {"python": ".py", "javascript": ".js"}


def semgrep_runs() -> bool:
    if shutil.which("semgrep") is None:
        return False
    try:
        result = subprocess.run(["semgrep", "--version"], capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def make_issue(vulnerability_class, cwe=None, owasp=None):
    return Issue(
        line_number=3,
        vulnerability_class=vulnerability_class,
        cwe=cwe,
        owasp=owasp,
        severity="high",
        code_snippet=None,
        evidence=[],
    )


@pytest.mark.parametrize("vulnerability_class", list(STATIC_EXPLANATIONS))
@pytest.mark.parametrize("language", LANGUAGES)
def test_every_class_has_text_and_code_for_both_languages(vulnerability_class, language):
    result = StaticExplainer().explain(make_issue(vulnerability_class), language)
    assert result.source == "static"
    assert result.exploit_scenario.strip()
    assert result.fixed_code_example.strip()


def test_owasp_and_label_come_from_the_detector_side():
    issue = make_issue("sql_injection", cwe="CWE-89", owasp="A05:2025 Injection")
    result = StaticExplainer().explain(issue, "python")
    assert result.vulnerability_type == "SQL injection"
    assert result.owasp_mapping == "A05:2025 Injection"


def test_unclassified_issue_gets_the_generic_text_and_keeps_its_cwe():
    issue = make_issue("other", cwe="CWE-96", owasp="A05:2025 Injection")
    result = StaticExplainer().explain(issue, "python")
    assert result.vulnerability_type == "Other security issue (CWE-96)"
    assert result.owasp_mapping == "A05:2025 Injection"
    assert "no ready-made code example" in result.fixed_code_example


def test_unknown_language_falls_back_to_an_available_example():
    result = StaticExplainer().explain(make_issue("xss"), "ruby")
    assert result.fixed_code_example.strip()


@pytest.mark.skipif(not semgrep_runs(), reason="semgrep cannot run here")
@pytest.mark.parametrize("vulnerability_class", list(STATIC_EXPLANATIONS))
@pytest.mark.parametrize("language", LANGUAGES)
def test_fixed_examples_do_not_trigger_our_own_rules(tmp_path, monkeypatch, vulnerability_class, language):
    monkeypatch.setattr(semgrep_detector, "SEMGREP_RULESETS", [str(semgrep_detector.CUSTOM_RULES_FILE)])
    example = STATIC_EXPLANATIONS[vulnerability_class]["fixed_code_example"][language]
    target = tmp_path / f"fixed{SUFFIX[language]}"
    target.write_text(example, encoding="utf-8")
    assert semgrep_detector.run_semgrep(target) == []