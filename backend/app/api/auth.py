from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.deps import get_current_user, get_user_by_email, verify_csrf
from app.core.rate_limit import RateLimiter, RateLimitExceeded
from app.core.security import (
    ACCESS_TOKEN_COOKIE,
    CSRF_TOKEN_COOKIE,
    PasswordTooLongError,
    create_access_token,
    create_csrf_token,
    dummy_password_hash,
    hash_password,
    verify_password,
)
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import LoginIn, RegisterIn, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])

_INVALID_LOGIN = "Invalid email or password"
_TOO_MANY_LOGINS = "Too many login attempts. Try again in a minute."

login_ip_limiter = RateLimiter(settings.login_rate_limit_ip, settings.login_rate_window_seconds)
login_email_limiter = RateLimiter(
    settings.login_rate_limit_email, settings.login_rate_window_seconds
)


def _cookie_max_age() -> int:
    return settings.access_token_expire_minutes * 60


def set_auth_cookies(response: Response, user_id: int) -> None:
    response.set_cookie(
        ACCESS_TOKEN_COOKIE,
        create_access_token(user_id),
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
        max_age=_cookie_max_age(),
    )
    # Readable by JavaScript on purpose: the page copies it into X-CSRF-Token.
    response.set_cookie(
        CSRF_TOKEN_COOKIE,
        create_csrf_token(user_id),
        httponly=False,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
        max_age=_cookie_max_age(),
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_TOKEN_COOKIE, path="/")
    response.delete_cookie(CSRF_TOKEN_COOKIE, path="/")


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterIn, db: Session = Depends(get_db)) -> User:
    email = body.email.lower()
    try:
        hashed = hash_password(body.password)
    except PasswordTooLongError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    user = User(email=email, hashed_password=hashed)
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email already registered"
        ) from None
    db.refresh(user)
    return user


def client_ip(request: Request) -> str:
    """The address the app actually sees. A proxy's forwarded header is not trusted."""
    if request.client is None:
        return "unknown"
    return request.client.host


@router.post("/login", response_model=UserOut)
def login(
    body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)
) -> User:
    try:
        login_ip_limiter.check(client_ip(request))
        login_email_limiter.check(body.email.lower())
    except RateLimitExceeded:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=_TOO_MANY_LOGINS
        ) from None

    user = get_user_by_email(db, body.email.lower())
    # Always run a bcrypt check. Skipping it for unknown emails would let an
    # attacker tell "no such user" from "wrong password" by response time.
    hashed = user.hashed_password if user is not None else dummy_password_hash()
    if user is None or not verify_password(body.password, hashed):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_LOGIN)
    set_auth_cookies(response, user.id)
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def logout(response: Response) -> None:
    # No auth dependency: an expired access token must still be able to clear
    # the cookies. The CSRF check above is what keeps a cross-site page from
    # logging the user out.
    clear_auth_cookies(response)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user
