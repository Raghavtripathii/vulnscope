import pytest

from app.explanations.gemini_client import ExplainerError, QuotaExceededError
from app.explanations.grouping import Issue
from app.explanations.schema import Explanation
from app.explanations.service import ExplanationService, cache_key

SQLI_FINDING = {
    "detector": "bandit",
    "rule_id": "B608",
    "vulnerability_type": "hardcoded_sql_expressions",
    "severity": "high",
    "line_number": 1,
    "message": "",
    "code_snippet": None,
}
XSS_FINDING = {
    "detector": "semgrep",
    "rule_id": "vulnscope-xss-html-sink",
    "vulnerability_type": "CWE-79: Improper Neutralization of Input During Web Page Generation",
    "severity": "medium",
    "line_number": 1,
    "message": "",
    "code_snippet": None,
}
UNRELATED_FINDING = {
    "detector": "bandit",
    "rule_id": "B404",
    "vulnerability_type": "blacklist",
    "severity": "low",
    "line_number": 1,
    "message": "",
    "code_snippet": None,
}


def make_issue(**overrides):
    base = {
        "line_number": 5,
        "vulnerability_class": "sql_injection",
        "cwe": "CWE-89",
        "owasp": "A05:2025 Injection",
        "severity": "high",
        "code_snippet": 'cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
        "evidence": [{"detector": "bandit", "rule_id": "B608", "message": "Possible SQL injection."}],
    }
    base.update(overrides)
    return Issue(**base)


def llm_explanation(fix="cur.execute('SELECT 1 WHERE a = ?', (a,))"):
    return Explanation(
        vulnerability_type="SQL injection",
        exploit_scenario="An attacker types SQL.",
        fixed_code_example=fix,
        owasp_mapping="A05:2025 Injection",
        source="llm",
    )


class FakeStatic:
    def __init__(self):
        self.calls = 0

    def explain(self, issue, language):
        self.calls += 1
        return Explanation(
            vulnerability_type="SQL injection",
            exploit_scenario="written text",
            fixed_code_example="written fix",
            owasp_mapping=issue.owasp,
            source="static",
        )


class FakeLlm:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = 0

    def explain(self, issue, language):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result.model_copy()


class FakeScan:
    def __init__(self, findings=None, error=None):
        self.findings = findings or []
        self.error = error
        self.calls = []

    def __call__(self, code, language):
        self.calls.append((code, language))
        if self.error is not None:
            raise self.error
        return list(self.findings)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make_service(llm=None, scan=None, **kwargs):
    return ExplanationService(static=FakeStatic(), scan_fn=scan or FakeScan(), llm=llm, **kwargs)


def test_without_a_model_the_written_explanation_is_used_and_nothing_is_scanned():
    scan = FakeScan()
    service = make_service(llm=None, scan=scan)
    result = service.explain(make_issue(), "python")
    assert result.source == "static"
    assert scan.calls == []


def test_a_clean_fix_is_returned_as_llm_and_marked_rescanned():
    scan = FakeScan()
    service = make_service(llm=FakeLlm(llm_explanation()), scan=scan)
    result = service.explain(make_issue(), "python")
    assert result.source == "llm"
    assert result.fix_rescan == "clean"
    assert scan.calls == [("cur.execute('SELECT 1 WHERE a = ?', (a,))", "python")]


def test_the_second_identical_request_is_served_from_the_cache():
    llm = FakeLlm(llm_explanation())
    scan = FakeScan()
    service = make_service(llm=llm, scan=scan)
    first = service.explain(make_issue(), "python")
    second = service.explain(make_issue(), "python")
    assert first == second
    assert llm.calls == 1
    assert len(scan.calls) == 1


def test_a_fix_that_still_has_the_same_problem_is_rejected_and_not_cached():
    llm = FakeLlm(llm_explanation())
    service = make_service(llm=llm, scan=FakeScan([SQLI_FINDING]))
    result = service.explain(make_issue(), "python")
    assert result.source == "static"
    service.explain(make_issue(), "python")
    assert llm.calls == 2


def test_a_fix_that_introduces_another_of_the_four_classes_is_rejected():
    service = make_service(llm=FakeLlm(llm_explanation()), scan=FakeScan([XSS_FINDING]))
    assert service.explain(make_issue(), "python").source == "static"


def test_a_fix_with_only_unrelated_notices_is_accepted():
    service = make_service(llm=FakeLlm(llm_explanation()), scan=FakeScan([UNRELATED_FINDING]))
    assert service.explain(make_issue(), "python").source == "llm"


def test_an_unclassified_issue_rejects_a_fix_that_trips_the_same_rule():
    issue = make_issue(
        vulnerability_class="other",
        cwe=None,
        owasp=None,
        evidence=[{"detector": "bandit", "rule_id": "B404", "message": "x"}],
    )
    service = make_service(llm=FakeLlm(llm_explanation()), scan=FakeScan([UNRELATED_FINDING]))
    assert service.explain(issue, "python").source == "static"


def test_model_errors_fall_back_to_the_written_explanation():
    service = make_service(llm=FakeLlm(error=ExplainerError("bad json")))
    assert service.explain(make_issue(), "python").source == "static"


def test_quota_error_starts_a_cooldown_that_skips_the_model_until_it_ends():
    clock = Clock()
    llm = FakeLlm(error=QuotaExceededError("limit"))
    service = make_service(llm=llm, clock=clock, quota_cooldown_seconds=300.0)
    assert service.explain(make_issue(), "python").source == "static"
    assert llm.calls == 1
    clock.now += 100
    assert service.explain(make_issue(line_number=9, code_snippet="other"), "python").source == "static"
    assert llm.calls == 1
    clock.now += 250
    service.explain(make_issue(line_number=9, code_snippet="other"), "python")
    assert llm.calls == 2


def test_a_crash_while_rescanning_falls_back_instead_of_failing():
    service = make_service(llm=FakeLlm(llm_explanation()), scan=FakeScan(error=RuntimeError("boom")))
    assert service.explain(make_issue(), "python").source == "static"


def test_secret_values_do_not_change_the_cache_key():
    def secret_issue(value):
        return make_issue(
            vulnerability_class="hardcoded_secret",
            cwe="CWE-798",
            owasp="A07:2025 Authentication Failures",
            code_snippet=f'api_key = "{value}"',
        )

    assert cache_key(secret_issue("sk_live_aaaaaaaa"), "python") == cache_key(secret_issue("sk_live_bbbbbbbb"), "python")


def test_different_language_or_class_gives_a_different_cache_key():
    base = cache_key(make_issue(), "python")
    assert cache_key(make_issue(), "javascript") != base
    assert cache_key(make_issue(vulnerability_class="xss", cwe="CWE-79"), "python") != base


def test_the_oldest_entry_is_dropped_when_the_cache_is_full():
    llm = FakeLlm(llm_explanation())
    service = make_service(llm=llm, cache_size=2)
    for index in range(3):
        service.explain(make_issue(code_snippet=f"query_{index}"), "python")
    assert llm.calls == 3
    service.explain(make_issue(code_snippet="query_0"), "python")
    assert llm.calls == 4
    service.explain(make_issue(code_snippet="query_2"), "python")
    assert llm.calls == 4


def test_changing_a_returned_explanation_does_not_change_the_cache():
    service = make_service(llm=FakeLlm(llm_explanation()))
    first = service.explain(make_issue(), "python")
    first.exploit_scenario = "tampered"
    second = service.explain(make_issue(), "python")
    assert second.exploit_scenario == "An attacker types SQL."