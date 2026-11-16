import json
import re
import time

import httpx
from pydantic import ValidationError

from app.explanations.grouping import Issue
from app.explanations.prompt import build_prompt
from app.explanations.schema import CLASS_LABELS, Explanation, LlmExplanation

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

RETRY_STATUS = {429, 500, 502, 503, 504}

FENCE = re.compile(r"^```(?:json)?\s*|\s*```$")


class ExplainerError(Exception):
    pass


class QuotaExceededError(ExplainerError):
    pass


def display_type(issue: Issue) -> str:
    label = CLASS_LABELS.get(issue.vulnerability_class, CLASS_LABELS["other"])
    if issue.vulnerability_class == "other" and issue.cwe:
        return f"{label} ({issue.cwe})"
    return label


def extract_text(body: dict) -> str:
    try:
        return body["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError):
        raise ExplainerError("the model response had an unexpected shape")


def parse_llm_json(text: str) -> LlmExplanation:
    cleaned = FENCE.sub("", text.strip())
    try:
        return LlmExplanation.model_validate(json.loads(cleaned))
    except (json.JSONDecodeError, ValidationError):
        raise ExplainerError("the model did not return the two required fields as valid json")


class GeminiExplainer:
    def __init__(
        self,
        api_key: str,
        model: str,
        client: httpx.Client | None = None,
        retry_delays: tuple[float, ...] = (3.0, 8.0),
        sleep=time.sleep,
    ):
        self.api_key = api_key
        self.model = model
        self.client = client or httpx.Client(timeout=30.0)
        self.retry_delays = retry_delays
        self.sleep = sleep

    def request_body(self, issue: Issue, language: str) -> dict:
        return {
            "contents": [{"parts": [{"text": build_prompt(issue, language)}]}],
            "generationConfig": {"responseMimeType": "application/json", "temperature": 0.2},
        }

    def post_with_retries(self, body: dict) -> httpx.Response:
        url = GEMINI_URL.format(model=self.model)
        headers = {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}
        attempts = len(self.retry_delays) + 1
        response = None
        for attempt in range(attempts):
            try:
                response = self.client.post(url, json=body, headers=headers)
            except httpx.TimeoutException:
                raise ExplainerError("the model request timed out")
            except httpx.HTTPError:
                raise ExplainerError("the model request failed")
            if response.status_code not in RETRY_STATUS:
                return response
            if attempt < attempts - 1:
                self.sleep(self.retry_delays[attempt])
        if response is not None and response.status_code == 429:
            raise QuotaExceededError("the model rate limit or daily quota was reached")
        raise ExplainerError(f"the model service kept failing with status {response.status_code}")

    def explain(self, issue: Issue, language: str) -> Explanation:
        response = self.post_with_retries(self.request_body(issue, language))
        if response.status_code != 200:
            raise ExplainerError(f"the model service answered with status {response.status_code}")
        try:
            body = response.json()
        except ValueError:
            raise ExplainerError("the model response was not json")
        llm = parse_llm_json(extract_text(body))
        return Explanation(
            vulnerability_type=display_type(issue),
            exploit_scenario=llm.exploit_scenario,
            fixed_code_example=llm.fixed_code_example,
            owasp_mapping=issue.owasp,
            source="llm",
        )


def build_gemini_explainer(api_key: str, model: str) -> GeminiExplainer | None:
    if not api_key:
        return None
    return GeminiExplainer(api_key=api_key, model=model)