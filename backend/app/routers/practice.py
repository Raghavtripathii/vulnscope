from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.exercises import EXERCISES, Exercise, exercises_for, get_exercise
from app.explanations.grouping import group_findings
from app.explanations.schema import CLASS_LABELS
from app.models import ExerciseAttempt
from app.routers.explain import require_user_id
from app.scanner import scan_with_status
from app.schemas import (
    AttemptRequest,
    AttemptResponse,
    ClassProgress,
    ExerciseDetail,
    ExerciseProgress,
    ExerciseSummary,
    ProgressResponse,
    RemainingIssue,
)

router = APIRouter()

CORE_CLASSES = ["sql_injection", "xss", "hardcoded_secret", "broken_authentication"]


def label_for(vulnerability_class: str) -> str:
    return CLASS_LABELS.get(vulnerability_class, CLASS_LABELS["other"])


def completed_ids(db: Session, user_id: int) -> set[str]:
    rows = (
        db.query(ExerciseAttempt.exercise_id)
        .filter(ExerciseAttempt.user_id == user_id, ExerciseAttempt.passed.is_(True))
        .distinct()
        .all()
    )
    return {row[0] for row in rows}


def summary_of(exercise: Exercise, completed: set[str]) -> ExerciseSummary:
    return ExerciseSummary(
        id=exercise.id,
        vulnerability_class=exercise.vulnerability_class,
        label=label_for(exercise.vulnerability_class),
        language=exercise.language,
        title=exercise.title,
        completed=exercise.id in completed,
    )


@router.get("/exercises", response_model=list[ExerciseSummary])
def list_exercises(
    vulnerability_class: Optional[Literal["sql_injection", "xss", "hardcoded_secret", "broken_authentication"]] = Query(None),
    db: Session = Depends(get_db),
    user_id: int = Depends(require_user_id),
):
    completed = completed_ids(db, user_id)
    return [summary_of(item, completed) for item in exercises_for(vulnerability_class)]


@router.get("/exercises/{exercise_id}", response_model=ExerciseDetail)
def exercise_detail(
    exercise_id: str,
    db: Session = Depends(get_db),
    user_id: int = Depends(require_user_id),
):
    exercise = get_exercise(exercise_id)
    if exercise is None:
        raise HTTPException(status_code=404, detail="exercise not found")
    base = summary_of(exercise, completed_ids(db, user_id))
    return ExerciseDetail(
        **base.model_dump(),
        scenario=exercise.scenario,
        vulnerable_code=exercise.vulnerable_code,
        hint=exercise.hint,
    )


@router.post("/exercises/{exercise_id}/attempt", response_model=AttemptResponse)
def attempt_exercise(
    exercise_id: str,
    payload: AttemptRequest,
    db: Session = Depends(get_db),
    user_id: int = Depends(require_user_id),
):
    exercise = get_exercise(exercise_id)
    if exercise is None:
        raise HTTPException(status_code=404, detail="exercise not found")
    if len(payload.code.encode("utf-8")) > settings.max_code_size_bytes:
        raise HTTPException(status_code=413, detail="code exceeds max scan size")

    result = scan_with_status(payload.code, exercise.language)
    if not result.complete:
        raise HTTPException(status_code=503, detail="could not check your code right now, please try again")

    issues = group_findings(result.findings)
    passed = all(issue.vulnerability_class != exercise.vulnerability_class for issue in issues)

    db.add(ExerciseAttempt(user_id=user_id, exercise_id=exercise.id, passed=passed))
    db.commit()

    return AttemptResponse(
        passed=passed,
        remaining=[
            RemainingIssue(
                line_number=issue.line_number,
                vulnerability_class=issue.vulnerability_class,
                label=label_for(issue.vulnerability_class),
            )
            for issue in issues
        ],
        detectors=result.detectors,
        reference_fix=exercise.reference_fix if passed else None,
    )


@router.get("/me/progress", response_model=ProgressResponse)
def my_progress(
    db: Session = Depends(get_db),
    user_id: int = Depends(require_user_id),
):
    attempts = (
        db.query(ExerciseAttempt)
        .filter(ExerciseAttempt.user_id == user_id)
        .order_by(ExerciseAttempt.id)
        .all()
    )
    count: dict[str, int] = {}
    passed_ids: set[str] = set()
    last_at: dict[str, object] = {}
    for row in attempts:
        count[row.exercise_id] = count.get(row.exercise_id, 0) + 1
        if row.passed:
            passed_ids.add(row.exercise_id)
        last_at[row.exercise_id] = row.created_at

    by_class = []
    for name in CORE_CLASSES:
        group = exercises_for(name)
        by_class.append(
            ClassProgress(
                vulnerability_class=name,
                label=label_for(name),
                total=len(group),
                completed=sum(1 for item in group if item.id in passed_ids),
            )
        )

    return ProgressResponse(
        exercises_total=len(EXERCISES),
        exercises_completed=sum(1 for item in EXERCISES if item.id in passed_ids),
        by_class=by_class,
        exercises=[
            ExerciseProgress(
                exercise_id=item.id,
                title=item.title,
                vulnerability_class=item.vulnerability_class,
                attempts=count.get(item.id, 0),
                completed=item.id in passed_ids,
                last_attempt_at=last_at.get(item.id),
            )
            for item in EXERCISES
        ],
    )