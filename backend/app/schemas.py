import datetime
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: str

    class Config:
        from_attributes = True


class ScanRequest(BaseModel):
    code: str = Field(..., min_length=1)
    language: Literal["python", "javascript"]
    filename: Optional[str] = None


class FindingResponse(BaseModel):
    detector: str
    rule_id: Optional[str]
    vulnerability_type: str
    severity: str
    line_number: Optional[int]
    message: str
    code_snippet: Optional[str]

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    scan_id: int
    language: str
    findings: list[FindingResponse]
    detectors: dict[str, str] = {}
    complete: bool = True


class ExplainRequest(BaseModel):
    scan_id: int
    issue_index: int = Field(..., ge=0)


class IssueResponse(BaseModel):
    index: int
    line_number: Optional[int]
    vulnerability_class: str
    label: str
    cwe: Optional[str]
    owasp: Optional[str]
    severity: str
    code_snippet: Optional[str]
    detectors: list[str]


class ScanSummary(BaseModel):
    scan_id: int
    language: str
    filename: Optional[str]
    created_at: datetime.datetime
    issue_count: int
    issues_by_class: dict[str, int]


class RepeatedMistake(BaseModel):
    vulnerability_class: str
    label: str
    scans_affected: int
    issues_total: int
    last_seen: Optional[datetime.datetime]


class StatsResponse(BaseModel):
    scans_count: int
    issues_total: int
    issues_by_class: dict[str, int]
    repeated_mistakes: list[RepeatedMistake]


class ClassStat(BaseModel):
    vulnerability_class: str
    label: str
    issues_total: int
    students_affected: int
    students_repeating: int
    share_of_students: float


class TeacherStatsResponse(BaseModel):
    students_count: int
    scans_count: int
    issues_total: int
    classes: list[ClassStat]


class ExerciseSummary(BaseModel):
    id: str
    vulnerability_class: str
    label: str
    language: str
    title: str
    completed: bool


class ExerciseDetail(ExerciseSummary):
    scenario: str
    vulnerable_code: str
    hint: str


class AttemptRequest(BaseModel):
    code: str = Field(..., min_length=1)


class RemainingIssue(BaseModel):
    line_number: Optional[int]
    vulnerability_class: str
    label: str


class AttemptResponse(BaseModel):
    passed: bool
    remaining: list[RemainingIssue]
    detectors: dict[str, str]
    reference_fix: Optional[str]


class ExerciseProgress(BaseModel):
    exercise_id: str
    title: str
    vulnerability_class: str
    attempts: int
    completed: bool
    last_attempt_at: Optional[datetime.datetime]


class ClassProgress(BaseModel):
    vulnerability_class: str
    label: str
    total: int
    completed: int


class ProgressResponse(BaseModel):
    exercises_total: int
    exercises_completed: int
    by_class: list[ClassProgress]
    exercises: list[ExerciseProgress]