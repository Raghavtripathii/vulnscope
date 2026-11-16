from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import get_current_user_id
from app.config import settings
from app.database import get_db
from app.models import Finding, Scan
from app.scanner import EXTENSION_BY_LANGUAGE, scan_with_status
from app.schemas import FindingResponse, ScanRequest, ScanResponse

router = APIRouter()


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

    result = scan_with_status(payload.code, payload.language)
    findings = result.findings

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
        detectors=result.detectors,
        complete=result.complete,
    )