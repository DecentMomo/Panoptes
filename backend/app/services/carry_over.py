from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.finding_status_history import FindingStatusHistory
from app.models.scan import Scan

CARRIED_STATUSES = ("false_positive", "accepted_risk")


def carry_over(db: Session, scan: Scan, rows: list[Finding]) -> None:
    """Copy suppressions onto matching fingerprints from the previous finished scan."""
    previous = db.scalar(
        select(Scan)
        .where(
            Scan.project_id == scan.project_id,
            Scan.id != scan.id,
            Scan.status.in_(("completed", "partial")),
        )
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    )
    if previous is None:
        return

    prior = list(
        db.scalars(
            select(Finding).where(
                Finding.scan_id == previous.id,
                Finding.status.in_(CARRIED_STATUSES),
            )
        )
    )
    by_fingerprint = {finding.fingerprint: finding for finding in prior}
    for row in rows:
        source = by_fingerprint.get(row.fingerprint)
        if source is None:
            continue
        decision = db.scalar(
            select(FindingStatusHistory)
            .where(
                FindingStatusHistory.finding_id == source.id,
                FindingStatusHistory.to_status == source.status,
            )
            .order_by(FindingStatusHistory.created_at.desc(), FindingStatusHistory.id.desc())
        )
        if decision is None:
            continue
        row.status = source.status
        row.status_reason = source.status_reason
        db.add(
            FindingStatusHistory(
                finding_id=row.id,
                user_id=decision.user_id,
                from_status="open",
                to_status=source.status,
                reason=decision.reason,
                carried_from_scan_id=previous.id,
            )
        )
