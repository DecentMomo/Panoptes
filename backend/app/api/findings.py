from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.explain_service import get_cached_explanation, request_explanation
from app.core.config import settings
from app.core.deps import get_current_user, verify_csrf
from app.core.rate_limit import RateLimiter, RateLimitExceeded
from app.db.session import get_db
from app.models.finding import Finding
from app.models.finding_status_history import STATUSES, FindingStatusHistory
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.schemas.explanation import ExplanationOut
from app.schemas.finding_status import StatusChangeIn, StatusHistoryOut
from app.schemas.scan import FindingOut
from app.services.ai_runner import ExplanationRunner, get_explanation_runner

router = APIRouter(tags=["findings"])

ai_rate_limiter = RateLimiter(settings.ai_rate_limit, settings.ai_rate_window_seconds)


def get_owned_finding(db: Session, user: User, finding_id: int, *, lock: bool = False) -> Finding:
    query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Project, Scan.project_id == Project.id)
        .where(Finding.id == finding_id, Project.owner_id == user.id)
    )
    if lock:
        query = query.with_for_update()
    finding = db.scalar(query)
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


@router.patch(
    "/findings/{finding_id}/status",
    response_model=FindingOut,
    dependencies=[Depends(verify_csrf)],
)
def change_status(
    finding_id: int,
    body: StatusChangeIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Finding:
    finding = get_owned_finding(db, user, finding_id, lock=True)
    reason = body.reason.strip() if body.reason else None
    if finding.status == body.status:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The finding already has that status.",
        )
    if body.status == "false_positive" and not reason:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A false positive needs a reason.",
        )
    if body.status not in STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown status.")
    db.add(
        FindingStatusHistory(
            finding_id=finding.id,
            user_id=user.id,
            from_status=finding.status,
            to_status=body.status,
            reason=reason,
        )
    )
    finding.status = body.status
    finding.status_reason = reason
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/findings/{finding_id}/history", response_model=list[StatusHistoryOut])
def list_status_history(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[StatusHistoryOut]:
    finding = get_owned_finding(db, user, finding_id)
    rows = db.execute(
        select(FindingStatusHistory, User.email)
        .join(User, FindingStatusHistory.user_id == User.id)
        .where(FindingStatusHistory.finding_id == finding.id)
        .order_by(FindingStatusHistory.created_at, FindingStatusHistory.id)
    )
    return [
        StatusHistoryOut(
            id=history.id,
            finding_id=history.finding_id,
            user_id=history.user_id,
            user_email=email,
            from_status=history.from_status,
            to_status=history.to_status,
            reason=history.reason,
            created_at=history.created_at,
        )
        for history, email in rows
    ]
