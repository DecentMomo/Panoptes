from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.ai_explanation import AIExplanation
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import StatsOut

router = APIRouter(tags=["stats"])


@router.get("/stats", response_model=StatsOut)
def get_stats(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> StatsOut:
    project_count = (
        db.scalar(select(func.count()).select_from(Project).where(Project.owner_id == user.id)) or 0
    )
    scan_count = (
        db.scalar(
            select(func.count())
            .select_from(Scan)
            .join(Project, Scan.project_id == Project.id)
            .where(Project.owner_id == user.id)
        )
        or 0
    )
    owned_findings = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Project, Scan.project_id == Project.id)
        .where(Project.owner_id == user.id)
        .subquery()
    )
    open_rows = db.scalars(
        select(owned_findings.c.severity).where(owned_findings.c.status == "open")
    )
    suppressed_count = (
        db.scalar(
            select(func.count())
            .select_from(owned_findings)
            .where(owned_findings.c.status.in_(("false_positive", "accepted_risk")))
        )
        or 0
    )
    fingerprints = select(owned_findings.c.fingerprint)
    completed = db.execute(
        select(func.count(), func.avg(AIExplanation.latency_ms)).where(
            AIExplanation.status == "completed",
            AIExplanation.fingerprint.in_(fingerprints),
        )
    ).one()
    average = completed[1]
    return StatsOut(
        project_count=project_count,
        scan_count=scan_count,
        open_by_severity=dict(Counter(open_rows)),
        suppressed_count=suppressed_count,
        explanations_completed=completed[0] or 0,
        avg_latency_ms=round(average) if average is not None else None,
    )
