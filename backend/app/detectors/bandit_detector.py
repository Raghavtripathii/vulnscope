import json
import subprocess
from pathlib import Path

from app.config import settings

SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def run_bandit(file_path: Path) -> list[dict]:
    try:
        result = subprocess.run(
            ["bandit", "-f", "json", str(file_path)],
            capture_output=True,
            text=True,
            timeout=settings.bandit_timeout_seconds,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    if not result.stdout:
        return []

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for item in payload.get("results", []):
        code = item.get("code")
        findings.append(
            {
                "detector": "bandit",
                "rule_id": item.get("test_id"),
                "vulnerability_type": item.get("test_name", "unknown"),
                "severity": SEVERITY_MAP.get(item.get("issue_severity"), "medium"),
                "line_number": item.get("line_number"),
                "message": item.get("issue_text", ""),
                "code_snippet": code.strip() if code else None,
            }
        )
    return findings