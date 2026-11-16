from collections import Counter, defaultdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.explanations.grouping import group_findings
from app.explanations.schema import CLASS_LABELS
from app.models import Finding, Scan
from app.routers.explain import require_user_id
from app.schemas import RepeatedMistake, ScanSummary, StatsResponse

router = APIRouter(prefix="/me")

MAX_STATS_SCANS = 500
REPEAT_THRESHOLD = 2


def recent_scans(db: Session, user_id: int, limit: int) -> list[Scan]:
    return (
        db.query(Scan)
        .filter(Scan.user_id == user_id)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(limit)
        .all()
    )


def issues_by_scan(db: Session, scan_ids: list[int]) -> dict[int, list]:
    if not scan_ids:
        return {}
    rows = db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).order_by(Finding.id).all()
    grouped: dict[int, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[row.scan_id].append(
            {
                "detector": row.detector,
                "rule_id": row.rule_id,
                "vulnerability_type": row.vulnerability_type,
                "severity": row.severity,
                "line_number": row.line_number,
                "message": row.message,
                "code_snippet": row.code_snippet,
            }
        )
    return {scan_id: group_findings(grouped.get(scan_id, [])) for scan_id in scan_ids}


@router.get("/scans", response_model=list[ScanSummary])
def my_scans(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user_id: int = Depends(require_user_id),
):
    scans = recent_scans(db, user_id, limit)
    issues = issues_by_scan(db, [scan.id for scan in scans])
    summaries = []
    for scan in scans:
        counts = Counter(issue.vulnerability_class for issue in issues[scan.id])
        summaries.append(
            ScanSummary(
                scan_id=scan.id,
                language=scan.language,
                filename=scan.filename,
                created_at=scan.created_at,
                issue_count=sum(counts.values()),
                issues_by_class=dict(counts),
            )
        )
    return summaries


@router.get("/stats", response_model=StatsResponse)
def my_stats(
    db: Session = Depends(get_db),
    user_id: int = Depends(require_user_id),
):
    scans = recent_scans(db, user_id, MAX_STATS_SCANS)
    issues = issues_by_scan(db, [scan.id for scan in scans])

    totals: Counter = Counter()
    scans_with_class: dict[str, set[int]] = defaultdict(set)
    last_seen: dict[str, object] = {}
    for scan in scans:
        for issue in issues[scan.id]:
            name = issue.vulnerability_class
            totals[name] += 1
            scans_with_class[name].add(scan.id)
            if name not in last_seen or (scan.created_at and scan.created_at > last_seen[name]):
                last_seen[name] = scan.created_at

    repeated = [
        RepeatedMistake(
            vulnerability_class=name,
            label=CLASS_LABELS.get(name, CLASS_LABELS["other"]),
            scans_affected=len(scan_ids),
            issues_total=totals[name],
            last_seen=last_seen.get(name),
        )
        for name, scan_ids in scans_with_class.items()
        if len(scan_ids) >= REPEAT_THRESHOLD
    ]
    repeated.sort(key=lambda item: (-item.scans_affected, -item.issues_total, item.vulnerability_class))

    return StatsResponse(
        scans_count=len(scans),
        issues_total=sum(totals.values()),
        issues_by_class=dict(totals),
        repeated_mistakes=repeated,
    )