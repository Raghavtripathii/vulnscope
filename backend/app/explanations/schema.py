from typing import Literal, Optional

from pydantic import BaseModel, Field

CLASS_LABELS = {
    "sql_injection": "SQL injection",
    "xss": "Cross-site scripting (XSS)",
    "hardcoded_secret": "Hardcoded secret",
    "broken_authentication": "Broken authentication",
    "other": "Other security issue",
}


class LlmExplanation(BaseModel):
    exploit_scenario: str = Field(..., min_length=1)
    fixed_code_example: str = Field(..., min_length=1)


class Explanation(BaseModel):
    vulnerability_type: str
    exploit_scenario: str
    fixed_code_example: str
    owasp_mapping: Optional[str] = None
    source: Literal["llm", "static"]