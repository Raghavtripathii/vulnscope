import ast
import json
import logging
import os
import subprocess
from pathlib import Path

from app.config import settings
from app.detectors.result import DetectorFindings

logger = logging.getLogger(__name__)

# Semgrep checks for a newer version on every run. That network call can stall a scan
# when the machine is offline or slow, so it is switched off for this process.
os.environ.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")

RULES_DIR = Path(__file__).resolve().parent / "semgrep-rules"
VENDORED_DIR = RULES_DIR / "vendored"
CUSTOM_RULES_FILE = RULES_DIR / "vulnscope.yml"
AUTH_RULES_FILE = RULES_DIR / "vulnscope-auth.yml"

# Registry pack name -> file name of the local copy kept in the repo (see docs/vendoring).
REGISTRY_PACKS = {
    "p/security-audit": "security-audit.yml",
    "p/owasp-top-ten": "owasp-top-ten.yml",
    "p/secrets": "secrets.yml",
}


def build_rulesets(vendored_dir: Path = VENDORED_DIR) -> list[str]:
    """Use the local copy of each registry pack when it exists, else the registry name."""
    rulesets = []
    for pack, filename in REGISTRY_PACKS.items():
        local = vendored_dir / filename
        rulesets.append(str(local) if local.is_file() else pack)
    rulesets += [str(CUSTOM_RULES_FILE), str(AUTH_RULES_FILE)]
    return rulesets


SEMGREP_RULESETS = build_rulesets()

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


# Semgrep's render_template_string rule fires on every call, even when the template is a
# fixed string and user input only reaches it as a context variable (which Jinja escapes).
# That is the standard safe pattern, so a finding on it is dropped. A template built with
# +, f-strings, % or .format() is not a plain string literal and is still reported.
# The rule is matched loosely ("template" in its id) because the exact id comes from the
# vendored pack; the AST check below is what makes the decision.
RENDER_TEMPLATE_RULE_MARKER = "template"


def is_constant_template_call(file_path: Path, line_number: int | None) -> bool:
    """True when the flagged line is render_template_string("<plain string>", ...)."""
    if not line_number:
        return False
    try:
        tree = ast.parse(file_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return False
    found = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (node.lineno <= line_number <= (node.end_lineno or node.lineno)):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name != "render_template_string":
            continue
        found = True
        template = node.args[0] if node.args else next(
            (kw.value for kw in node.keywords if kw.arg == "source"), None
        )
        if not (isinstance(template, ast.Constant) and isinstance(template.value, str)):
            return False
    return found


def run_semgrep(file_path: Path) -> DetectorFindings:
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
        return DetectorFindings(status="timeout")
    except OSError as error:
        logger.error("could not start semgrep: %s", error)
        return DetectorFindings(status="unavailable")

    if not result.stdout:
        logger.warning("semgrep returned no output, exit code %s, stderr: %s", result.returncode, result.stderr[:300])
        return DetectorFindings(status="failed")

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.warning("semgrep output was not valid json")
        return DetectorFindings(status="failed")

    findings = DetectorFindings()
    for item in payload.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe") or []
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list]
        vulnerability_type = cwe_list[0] if cwe_list else item.get("check_id", "unknown")
        line_number = item.get("start", {}).get("line")
        lines = extra.get("lines")

        if RENDER_TEMPLATE_RULE_MARKER in (item.get("check_id") or "").lower() and is_constant_template_call(
            file_path, line_number
        ):
            continue

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