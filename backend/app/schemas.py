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