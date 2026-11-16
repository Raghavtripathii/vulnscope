from app.explanations.classification import HARDCODED_SECRET
from app.explanations.grouping import Issue
from app.explanations.redaction import redact
from app.explanations.schema import CLASS_LABELS

INSTRUCTIONS = (
    "You are a secure coding tutor for students. "
    "Explain ONLY the finding below, which was reported by automated static analysis tools. "
    "Do not report any other vulnerability. "
    "If the snippet does not give enough information, say what is missing instead of guessing. "
    "Never include or invent real credentials. "
    "Reply with JSON only, with exactly these keys: exploit_scenario, fixed_code_example."
)


def build_prompt(issue: Issue, language: str) -> str:
    mask_strings = issue.vulnerability_class == HARDCODED_SECRET
    snippet = redact(issue.code_snippet, mask_all_strings=mask_strings) or "(no snippet available)"

    lines = [
        INSTRUCTIONS,
        "",
        f"Language: {language}",
        f"Finding class: {CLASS_LABELS.get(issue.vulnerability_class, issue.vulnerability_class)}",
        f"CWE: {issue.cwe or 'not reported'}",
        f"OWASP: {issue.owasp or 'not reported'}",
        f"Line: {issue.line_number if issue.line_number is not None else 'unknown'}",
        "Code:",
        snippet,
        "Evidence from detectors:",
    ]
    for item in issue.evidence:
        message = redact(item.get("message") or "", mask_all_strings=False)
        lines.append(f"- {item.get('detector')} {item.get('rule_id')}: {message}")
    return "\n".join(lines)