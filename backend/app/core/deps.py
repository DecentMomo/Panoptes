import secrets

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import (
    ACCESS_TOKEN_COOKIE,
    CSRF_HEADER,
    CSRF_TOKEN_COOKIE,
    decode_access_token,
)
from app.db.session import get_db
from app.models.user import User


def _same_secret(left: str, right: str) -> bool:
    if len(left) != len(right):
        return False
    return secrets.compare_digest(left, right)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    user_id = decode_access_token(token) if token else None
    user = db.get(User, user_id) if user_id is not None else None
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


def verify_csrf(request: Request) -> None:
    """Double-submit check: the header must match the csrf cookie.

    A cross-site request can make the browser send our cookies, but it cannot
    read them, so it cannot copy the cookie value into this header.
    """
    cookie = request.cookies.get(CSRF_TOKEN_COOKIE, "")
    header = request.headers.get(CSRF_HEADER, "")
    if not cookie or not header or not _same_secret(cookie, header):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF check failed")


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))
