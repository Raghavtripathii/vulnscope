from app.explanations.grouping import Issue
from app.explanations.prompt import build_prompt


def make_issue(**overrides):
    base = {
        "line_number": 5,
        "vulnerability_class": "sql_injection",
        "cwe": "CWE-89",
        "owasp": "A05:2025 Injection",
        "severity": "high",
        "code_snippet": 'cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
        "evidence": [
            {
                "detector": "bandit",
                "rule_id": "B608",
                "message": "Possible SQL injection vector through string-based query construction.",
            }
        ],
    }
    base.update(overrides)
    return Issue(**base)


def test_prompt_contains_only_detector_grounded_facts():
    prompt = build_prompt(make_issue(), "python")
    assert "Language: python" in prompt
    assert "Finding class: SQL injection" in prompt
    assert "CWE: CWE-89" in prompt
    assert "OWASP: A05:2025 Injection" in prompt
    assert "Line: 5" in prompt
    assert "bandit B608" in prompt
    assert "ONLY" in prompt


def test_secret_values_never_reach_the_prompt():
    issue = make_issue(
        vulnerability_class="hardcoded_secret",
        cwe="CWE-798",
        owasp="A07:2025 Authentication Failures",
        code_snippet='api_key = "sk_live_abcdef123456"',
    )
    prompt = build_prompt(issue, "python")
    assert "sk_live_abcdef123456" not in prompt
    assert "<REDACTED>" in prompt


def test_long_tokens_are_masked_for_other_classes():
    token = "Z" * 40
    prompt = build_prompt(make_issue(code_snippet=f"call({token})"), "javascript")
    assert token not in prompt


def test_missing_snippet_and_cwe_are_stated_plainly():
    prompt = build_prompt(make_issue(code_snippet=None, cwe=None, owasp=None, line_number=None), "python")
    assert "(no snippet available)" in prompt
    assert "CWE: not reported" in prompt
    assert "OWASP: not reported" in prompt
    assert "Line: unknown" in prompt