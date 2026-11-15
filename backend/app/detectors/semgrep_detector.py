import json
import logging
import subprocess
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)

CUSTOM_RULES_FILE = Path(__file__).resolve().parent / "semgrep-rules" / "vulnscope.yml"

SEMGREP_RULESETS = ["p/security-audit", "p/owasp-top-ten", "p/secrets", str(CUSTOM_RULES_FILE)]

SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

HIDDEN_LINES_MARKER = "requires login"


def read_source_line(file_path: Path, line_number: int | None) -> str | None:
    if not line_number:
        return None
    try:
        source_lines = file_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    if 1 <= line_number <= len(source_lines):
        return source_lines[line_number - 1].strip()
    return None


def run_semgrep(file_path: Path) -> list[dict]:
    config_args = []
    for ruleset in SEMGREP_RULESETS:
        config_args += ["--config", ruleset]

    try:
        result = subprocess.run(
            ["semgrep", *config_args, "--metrics=off", "--json", "--quiet", str(file_path)],
            capture_output=True,
            text=True,
            timeout=settings.semgrep_timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        logger.warning("semgrep timed out after %s seconds", settings.semgrep_timeout_seconds)
        return []
    except FileNotFoundError:
        logger.error("semgrep executable not found")
        return []

    if not result.stdout:
        logger.warning("semgrep returned no output, exit code %s, stderr: %s", result.returncode, result.stderr[:300])
        return []

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.warning("semgrep output was not valid json")
        return []

    findings = []
    for item in payload.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe") or []
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list]
        vulnerability_type = cwe_list[0] if cwe_list else item.get("check_id", "unknown")
        line_number = item.get("start", {}).get("line")
        lines = extra.get("lines")

        if lines and lines.strip() != HIDDEN_LINES_MARKER:
            snippet = lines.strip()
        else:
            snippet = read_source_line(file_path, line_number)

        findings.append(
            {
                "detector": "semgrep",
                "rule_id": item.get("check_id"),
                "vulnerability_type": vulnerability_type,
                "severity": SEVERITY_MAP.get(extra.get("severity"), "medium"),
                "line_number": line_number,
                "message": extra.get("message", ""),
                "code_snippet": snippet,
            }
        )
    return findings