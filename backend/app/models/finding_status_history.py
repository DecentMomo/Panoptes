from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

STATUSES = ("open", "fixed", "false_positive", "accepted_risk")


class FindingStatusHistory(Base):
    __tablename__ = "finding_status_history"
    __table_args__ = (
        CheckConstraint(
            "from_status IN ('open', 'fixed', 'false_positive', 'accepted_risk')",
            name="ck_finding_status_history_from",
        ),
        CheckConstraint(
            "to_status IN ('open', 'fixed', 'false_positive', 'accepted_risk')",
            name="ck_finding_status_history_to",
        ),
        CheckConstraint(
            "to_status <> 'false_positive' OR (reason IS NOT NULL AND btrim(reason) <> '')",
            name="ck_finding_status_history_false_positive_reason",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    from_status: Mapped[str] = mapped_column(String(20))
    to_status: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
