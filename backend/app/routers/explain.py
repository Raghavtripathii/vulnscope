from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import get_current_user_id
from app.config import settings
from app.database import get_db
from app.explanations.gemini_client import build_gemini_explainer
from app.explanations.grouping import group_findings
from app.explanations.schema import CLASS_LABELS, Explanation
from app.explanations.service import ExplanationService
from app.explanations.static_explainer import StaticExplainer
from app.models import Finding, Scan
from app.scanner import scan_text
from app.schemas import ExplainRequest, IssueResponse

router = APIRouter()


@lru_cache(maxsize=1)
def build_service() -> ExplanationService:
    llm = build_gemini_explainer(
        settings.gemini_api_key.get_secret_value(),
        settings.gemini_model,
    )
    return ExplanationService(static=StaticExplainer(), scan_fn=scan_text, llm=llm)


def get_explanation_service() -> ExplanationService:
    return build_service()


def require_user_id(user_id: int | None = Depends(get_current_user_id)) -> int:
    if user_id is None:
        raise HTTPException(status_code=401, detail="login required")
    return user_id


def load_scan_issues(db: Session, scan_id: int, user_id: int):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None or scan.user_id != user_id:
        raise HTTPException(status_code=404, detail="scan not found")

    rows = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.id).all()
    findings = [
        {
            "detector": row.detector,
            "rule_id": row.rule_id,
            "vulnerability_type": row.vulnerability_type,
            "severity": row.severity,
            "line_number": row.line_number,
            "message": row.message,
            "code_snippet": row.code_snippet,
        }
        for row in rows
    ]
    return scan, group_findings(findings)


@router.get("/scans/{scan_id}/issues", response_model=list[IssueResponse])
def list_issues(
    scan_id: int,
    db: Session = Depends(get_db),
    user_id: int = Depends(require_user_id),
):
    _, issues = load_scan_issues(db, scan_id, user_id)
    return [
        IssueResponse(
            index=position,
            line_number=issue.line_number,
            vulnerability_class=issue.vulnerability_class,
            label=CLASS_LABELS.get(issue.vulnerability_class, CLASS_LABELS["other"]),
            cwe=issue.cwe,
            owasp=issue.owasp,
            severity=issue.severity,
            code_snippet=issue.code_snippet,
            detectors=sorted({item["detector"] for item in issue.evidence}),
        )
        for position, issue in enumerate(issues)
    ]


@router.post("/explain", response_model=Explanation)
def explain_issue(
    payload: ExplainRequest,
    db: Session = Depends(get_db),
    user_id: int = Depends(require_user_id),
    service: ExplanationService = Depends(get_explanation_service),
):
    scan, issues = load_scan_issues(db, payload.scan_id, user_id)
    if payload.issue_index >= len(issues):
        raise HTTPException(status_code=404, detail="issue not found")
    return service.explain(issues[payload.issue_index], scan.language)