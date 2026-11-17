from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.explanations.schema import CLASS_LABELS
from app.models import Scan, User
from app.routers.explain import require_user_id
from app.routers.me import issues_by_scan
from app.schemas import ClassStat, TeacherStatsResponse

router = APIRouter(prefix="/teacher")

MAX_CLASS_SCANS = 2000
CORE_CLASSES = ["sql_injection", "xss", "hardcoded_secret", "broken_authentication"]


def teacher_email_set() -> set[str]:
    return {email.strip().lower() for email in settings.teacher_emails.split(",") if email.strip()}


def require_teacher(
    db: Session = Depends(get_db),
    user_id: int = Depends(require_user_id),
) -> int:
    user = db.query(User).filter(User.id == user_id).first()
    if user is None or user.email.lower() not in teacher_email_set():
        raise HTTPException(status_code=403, detail="teacher access only")
    return user_id


@router.get("/stats", response_model=TeacherStatsResponse)
def class_stats(
    db: Session = Depends(get_db),
    _: int = Depends(require_teacher),
):
    scans = (
        db.query(Scan)
        .filter(Scan.user_id.isnot(None))
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(MAX_CLASS_SCANS)
        .all()
    )
    issues = issues_by_scan(db, [scan.id for scan in scans])

    students = {scan.user_id for scan in scans}
    issues_total: dict[str, int] = defaultdict(int)
    scans_by_student: dict[str, dict[int, set[int]]] = defaultdict(lambda: defaultdict(set))
    for scan in scans:
        for issue in issues[scan.id]:
            name = issue.vulnerability_class
            issues_total[name] += 1
            scans_by_student[name][scan.user_id].add(scan.id)

    names = list(CORE_CLASSES) + sorted(name for name in issues_total if name not in CORE_CLASSES)
    classes = []
    for name in names:
        per_student = scans_by_student.get(name, {})
        affected = len(per_student)
        classes.append(
            ClassStat(
                vulnerability_class=name,
                label=CLASS_LABELS.get(name, CLASS_LABELS["other"]),
                issues_total=issues_total.get(name, 0),
                students_affected=affected,
                students_repeating=sum(1 for scan_ids in per_student.values() if len(scan_ids) >= 2),
                share_of_students=round(affected / len(students), 3) if students else 0.0,
            )
        )
    classes.sort(key=lambda item: (-item.students_affected, -item.issues_total, item.vulnerability_class))

    return TeacherStatsResponse(
        students_count=len(students),
        scans_count=len(scans),
        issues_total=sum(issues_total.values()),
        classes=classes,
    )