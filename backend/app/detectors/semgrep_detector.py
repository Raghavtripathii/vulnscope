import json
import subprocess
from pathlib import Path

from app.config import settings

SEMGREP_RULESETS = ["p/security-audit", "p/owasp-top-ten"]

SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def run_semgrep(file_path: Path) -> list[dict]:
    config_args = []
    for ruleset in SEMGREP_RULESETS:
        config_args += ["--config", ruleset]

    try:
        result = subprocess.run(
            ["semgrep", *config_args, "--json", "--quiet", str(file_path)],
            capture_output=True,
            text=True,
            timeout=settings.semgrep_timeout_seconds,
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
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe") or []
        vulnerability_type = cwe_list[0] if cwe_list else item.get("check_id", "unknown")
        lines = extra.get("lines")

        findings.append(
            {
                "detector": "semgrep",
                "rule_id": item.get("check_id"),
                "vulnerability_type": vulnerability_type,
                "severity": SEVERITY_MAP.get(extra.get("severity"), "medium"),
                "line_number": item.get("start", {}).get("line"),
                "message": extra.get("message", ""),
                "code_snippet": lines.strip() if lines else None,
            }
        )
    return findings