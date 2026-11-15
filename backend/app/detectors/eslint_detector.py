import json
import logging
import subprocess
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)

ESLINT_CONFIG_DIR = Path(__file__).resolve().parent / "eslint-config"
ESLINT_CONFIG_FILE = ESLINT_CONFIG_DIR / ".eslintrc.json"

SEVERITY_MAP = {1: "low", 2: "high"}

MAX_SNIPPET_CHARS = 300


def load_source_lines(file_path: Path) -> list[str]:
    try:
        return file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def source_line(source_lines: list[str], line_number: int | None) -> str | None:
    if line_number and 1 <= line_number <= len(source_lines):
        return source_lines[line_number - 1].strip()[:MAX_SNIPPET_CHARS]
    return None


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
    except subprocess.TimeoutExpired:
        logger.warning("eslint timed out after %s seconds", settings.eslint_timeout_seconds)
        return []
    except OSError as error:
        logger.error("could not start eslint: %s", error)
        return []

    if not result.stdout:
        logger.warning("eslint returned no output, exit code %s, stderr: %s", result.returncode, result.stderr[:300])
        return []

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.warning("eslint output was not valid json")
        return []

    source_lines = load_source_lines(file_path)

    findings = []
    for file_result in payload:
        for msg in file_result.get("messages", []):
            if not msg.get("ruleId"):
                logger.warning("eslint could not analyse line %s: %s", msg.get("line"), msg.get("message"))
                continue
            findings.append(
                {
                    "detector": "eslint",
                    "rule_id": msg.get("ruleId"),
                    "vulnerability_type": msg.get("ruleId"),
                    "severity": SEVERITY_MAP.get(msg.get("severity"), "medium"),
                    "line_number": msg.get("line"),
                    "message": msg.get("message", ""),
                    "code_snippet": source_line(source_lines, msg.get("line")),
                }
            )
    return findings