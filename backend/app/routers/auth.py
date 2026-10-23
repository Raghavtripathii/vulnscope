from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.auth import COOKIE_NAME, create_access_token, hash_password, verify_password
from app.database import get_db
from app.models import User
from app.schemas import UserCreate, UserLogin, UserResponse

router = APIRouter(prefix="/auth")

COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 7


def _set_auth_cookie(response: Response, user_id: int) -> None:
    token = create_access_token(user_id)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=COOKIE_MAX_AGE_SECONDS,
    )


@router.post("/register", response_model=UserResponse, status_code=201)
def register(payload: UserCreate, response: Response, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="email already registered")

    user = User(email=payload.email, hashed_password=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)

    _set_auth_cookie(response, user.id)
    return user


@router.post("/login", response_model=UserResponse)
def login(payload: UserLogin, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="invalid email or password")

    _set_auth_cookie(response, user.id)
    return user


@router.post("/logout", status_code=204)
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME)