import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import get_current_user_id
from app.config import settings
from app.database import get_db
from app.detectors.bandit_detector import run_bandit
from app.detectors.eslint_detector import run_eslint
from app.detectors.semgrep_detector import run_semgrep
from app.models import Finding, Scan
from app.schemas import FindingResponse, ScanRequest, ScanResponse

router = APIRouter()

EXTENSION_BY_LANGUAGE = {"python": ".py", "javascript": ".js"}


@router.post("/scan", response_model=ScanResponse)
def scan_code(
    payload: ScanRequest,
    db: Session = Depends(get_db),
    user_id: int | None = Depends(get_current_user_id),
):
    if payload.language not in EXTENSION_BY_LANGUAGE:
        raise HTTPException(status_code=400, detail="language must be python or javascript")

    code_bytes = payload.code.encode("utf-8")
    if len(code_bytes) > settings.max_code_size_bytes:
        raise HTTPException(status_code=413, detail="code exceeds max scan size")

    suffix = EXTENSION_BY_LANGUAGE[payload.language]
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as tmp:
        tmp.write(payload.code)
        tmp_path = Path(tmp.name)

    try:
        findings = run_semgrep(tmp_path)
        if payload.language == "python":
            findings += run_bandit(tmp_path)
        elif payload.language == "javascript":
            findings += run_eslint(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)

    scan = Scan(language=payload.language, filename=payload.filename, user_id=user_id)
    db.add(scan)
    db.flush()

    for item in findings:
        db.add(Finding(scan_id=scan.id, **item))
    db.commit()
    db.refresh(scan)

    return ScanResponse(
        scan_id=scan.id,
        language=scan.language,
        findings=[FindingResponse(**item) for item in findings],
    )