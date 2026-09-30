from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.explain_service import get_cached_explanation, request_explanation
from app.core.config import settings
from app.core.deps import get_current_user, verify_csrf
from app.core.rate_limit import RateLimiter, RateLimitExceeded
from app.db.session import get_db
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.schemas.explanation import ExplanationOut
from app.schemas.scan import FindingOut
from app.services.ai_runner import ExplanationRunner, get_explanation_runner

router = APIRouter(tags=["findings"])

ai_rate_limiter = RateLimiter(settings.ai_rate_limit, settings.ai_rate_window_seconds)


def get_owned_finding(db: Session, user: User, finding_id: int) -> Finding:
    finding = db.scalar(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Project, Scan.project_id == Project.id)
        .where(Finding.id == finding_id, Project.owner_id == user.id)
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


def enforce_ai_rate_limit(user: User = Depends(get_current_user)) -> User:
    try:
        ai_rate_limiter.check(user.id)
    except RateLimitExceeded:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many explanation requests. Try again in a minute.",
        ) from None
    return user


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Finding:
    return get_owned_finding(db, user, finding_id)


@router.post(
    "/findings/{finding_id}/explanation",
    response_model=ExplanationOut,
    dependencies=[Depends(verify_csrf)],
)
def create_explanation(
    finding_id: int,
    response: Response,
    user: User = Depends(enforce_ai_rate_limit),
    db: Session = Depends(get_db),
    runner: ExplanationRunner = Depends(get_explanation_runner),
) -> ExplanationOut:
    finding = get_owned_finding(db, user, finding_id)
    body, pending = request_explanation(db, finding, runner)
    response.status_code = status.HTTP_202_ACCEPTED if pending else status.HTTP_200_OK
    return body


@router.get("/findings/{finding_id}/explanation", response_model=ExplanationOut)
def get_explanation(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ExplanationOut:
    finding = get_owned_finding(db, user, finding_id)
    explanation = get_cached_explanation(db, finding)
    if explanation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No explanation has been requested.",
        )
    return explanation
