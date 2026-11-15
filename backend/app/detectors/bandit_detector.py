import json
import logging
import subprocess
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)

SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def run_bandit(file_path: Path) -> list[dict]:
    try:
        result = subprocess.run(
            ["bandit", "-f", "json", str(file_path)],
            capture_output=True,
            text=True,
            timeout=settings.bandit_timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        logger.warning("bandit timed out after %s seconds", settings.bandit_timeout_seconds)
        return []
    except OSError as error:
        logger.error("could not start bandit: %s", error)
        return []

    if not result.stdout:
        logger.warning("bandit returned no output, exit code %s, stderr: %s", result.returncode, result.stderr[:300])
        return []

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.warning("bandit output was not valid json")
        return []

    for error in payload.get("errors", []):
        logger.warning("bandit reported an error: %s", error)

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