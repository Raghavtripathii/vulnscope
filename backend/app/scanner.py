import tempfile
from pathlib import Path

from app.detectors.bandit_detector import run_bandit
from app.detectors.eslint_detector import run_eslint
from app.detectors.semgrep_detector import run_semgrep

EXTENSION_BY_LANGUAGE = {"python": ".py", "javascript": ".js"}


def scan_text(code: str, language: str) -> list[dict]:
    suffix = EXTENSION_BY_LANGUAGE[language]
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as tmp:
        tmp.write(code)
        tmp_path = Path(tmp.name)

    try:
        findings = run_semgrep(tmp_path)
        if language == "python":
            findings += run_bandit(tmp_path)
        elif language == "javascript":
            findings += run_eslint(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)
    return findings