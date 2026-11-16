import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from app.detectors.bandit_detector import run_bandit
from app.detectors.eslint_detector import run_eslint
from app.detectors.result import status_of
from app.detectors.semgrep_detector import run_semgrep

EXTENSION_BY_LANGUAGE = {"python": ".py", "javascript": ".js"}


class DetectorFailure(Exception):
    pass


@dataclass
class ScanResult:
    findings: list[dict] = field(default_factory=list)
    detectors: dict[str, str] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return all(status == "ok" for status in self.detectors.values())


def scan_with_status(code: str, language: str) -> ScanResult:
    suffix = EXTENSION_BY_LANGUAGE[language]
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as tmp:
        tmp.write(code)
        tmp_path = Path(tmp.name)

    runs = [("semgrep", run_semgrep)]
    if language == "python":
        runs.append(("bandit", run_bandit))
    elif language == "javascript":
        runs.append(("eslint", run_eslint))

    result = ScanResult()
    try:
        for name, run in runs:
            output = run(tmp_path)
            result.findings.extend(output)
            result.detectors[name] = status_of(output)
    finally:
        tmp_path.unlink(missing_ok=True)
    return result


def scan_text(code: str, language: str) -> list[dict]:
    result = scan_with_status(code, language)
    failed = sorted(name for name, status in result.detectors.items() if status != "ok")
    if failed:
        raise DetectorFailure("detectors did not finish: " + ", ".join(failed))
    return result.findings