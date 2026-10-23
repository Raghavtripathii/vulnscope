import json
import subprocess
from pathlib import Path

from app.config import settings

ESLINT_CONFIG_DIR = Path(__file__).resolve().parent / "eslint-config"
ESLINT_CONFIG_FILE = ESLINT_CONFIG_DIR / ".eslintrc.json"

SEVERITY_MAP = {1: "low", 2: "high"}


def run_eslint(file_path: Path) -> list[dict]:
    try:
        result = subprocess.run(
            [
                "npx",
                "--prefix",
                str(ESLINT_CONFIG_DIR),
                "eslint",
                "--no-eslintrc",
                "-c",
                str(ESLINT_CONFIG_FILE),
                "--format",
                "json",
                str(file_path),
            ],
            capture_output=True,
            text=True,
            timeout=settings.eslint_timeout_seconds,
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
    for file_result in payload:
        for msg in file_result.get("messages", []):
            findings.append(
                {
                    "detector": "eslint",
                    "rule_id": msg.get("ruleId"),
                    "vulnerability_type": msg.get("ruleId") or "unknown",
                    "severity": SEVERITY_MAP.get(msg.get("severity"), "medium"),
                    "line_number": msg.get("line"),
                    "message": msg.get("message", ""),
                    "code_snippet": None,
                }
            )
    return findings