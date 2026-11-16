import json

import httpx
import pytest

from app.explanations.gemini_client import (
    ExplainerError,
    GeminiExplainer,
    QuotaExceededError,
    build_gemini_explainer,
)
from app.explanations.grouping import Issue

API_KEY = "test-key-should-never-leak"
MODEL = "gemini-3.5-flash-lite"


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


def reply(text):
    return {"candidates": [{"content": {"parts": [{"text": text}]}}]}


GOOD = json.dumps({"exploit_scenario": "An attacker types SQL.", "fixed_code_example": "cur.execute('...', (name,))"})


def make_explainer(handler):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return GeminiExplainer(api_key=API_KEY, model=MODEL, client=client, retry_delays=(0.0, 0.0), sleep=lambda seconds: None)


def test_successful_call_builds_a_grounded_llm_explanation():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("x-goog-api-key")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=reply(GOOD))

    result = make_explainer(handler).explain(make_issue(), "python")
    assert result.source == "llm"
    assert result.vulnerability_type == "SQL injection"
    assert result.owasp_mapping == "A05:2025 Injection"
    assert result.exploit_scenario == "An attacker types SQL."
    assert MODEL in seen["url"]
    assert API_KEY not in seen["url"]
    assert seen["key"] == API_KEY
    assert seen["body"]["generationConfig"]["responseMimeType"] == "application/json"
    assert "Finding class: SQL injection" in seen["body"]["contents"][0]["parts"][0]["text"]


def test_json_wrapped_in_a_code_fence_is_accepted():
    fenced = "```json\n" + GOOD + "\n```"
    result = make_explainer(lambda request: httpx.Response(200, json=reply(fenced))).explain(make_issue(), "python")
    assert result.exploit_scenario == "An attacker types SQL."


def test_the_model_cannot_change_the_vulnerability_type_or_owasp_category():
    sneaky = json.dumps(
        {
            "exploit_scenario": "x",
            "fixed_code_example": "y",
            "vulnerability_type": "Buffer overflow",
            "owasp_mapping": "A01:2025 Broken Access Control",
        }
    )
    result = make_explainer(lambda request: httpx.Response(200, json=reply(sneaky))).explain(make_issue(), "python")
    assert result.vulnerability_type == "SQL injection"
    assert result.owasp_mapping == "A05:2025 Injection"


def test_rate_limit_is_retried_and_then_succeeds():
    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, json={})
        return httpx.Response(200, json=reply(GOOD))

    result = make_explainer(handler).explain(make_issue(), "python")
    assert result.source == "llm"
    assert len(calls) == 2


def test_persistent_rate_limit_raises_quota_error_after_all_attempts():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(429, json={})

    with pytest.raises(QuotaExceededError):
        make_explainer(handler).explain(make_issue(), "python")
    assert len(calls) == 3


def test_server_errors_are_retried_then_reported():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(503, json={})

    with pytest.raises(ExplainerError):
        make_explainer(handler).explain(make_issue(), "python")
    assert len(calls) == 3


def test_client_errors_are_not_retried_and_hide_the_key():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(400, json={"error": "bad request"})

    with pytest.raises(ExplainerError) as caught:
        make_explainer(handler).explain(make_issue(), "python")
    assert len(calls) == 1
    assert API_KEY not in str(caught.value)


def test_invalid_json_from_the_model_is_an_error():
    with pytest.raises(ExplainerError):
        make_explainer(lambda request: httpx.Response(200, json=reply("not json at all"))).explain(make_issue(), "python")


def test_a_missing_field_is_an_error():
    only_one = json.dumps({"exploit_scenario": "x"})
    with pytest.raises(ExplainerError):
        make_explainer(lambda request: httpx.Response(200, json=reply(only_one))).explain(make_issue(), "python")


def test_unexpected_response_shape_is_an_error():
    with pytest.raises(ExplainerError):
        make_explainer(lambda request: httpx.Response(200, json={"candidates": []})).explain(make_issue(), "python")


def test_timeouts_are_reported_as_explainer_errors():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(ExplainerError):
        make_explainer(handler).explain(make_issue(), "python")


def test_secret_values_in_the_snippet_never_leave_in_the_request():
    sent = {}

    def handler(request):
        sent["text"] = request.content.decode()
        return httpx.Response(200, json=reply(GOOD))

    issue = make_issue(
        vulnerability_class="hardcoded_secret",
        cwe="CWE-798",
        owasp="A07:2025 Authentication Failures",
        code_snippet='api_key = "sk_live_abcdef123456"',
    )
    make_explainer(handler).explain(issue, "python")
    assert "sk_live_abcdef123456" not in sent["text"]


def test_no_key_means_no_explainer():
    assert build_gemini_explainer("", MODEL) is None
    assert build_gemini_explainer("some-key", MODEL) is not None