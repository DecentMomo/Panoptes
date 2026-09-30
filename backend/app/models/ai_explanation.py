from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AIExplanation(Base):
    __tablename__ = "ai_explanations"
    __table_args__ = (
        UniqueConstraint(
            "fingerprint",
            "model_name",
            "prompt_version",
            name="uq_ai_explanations_cache_key",
        ),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="ck_ai_explanations_status",
        ),
        CheckConstraint(
            "failure_reason IS NULL OR failure_reason IN "
            "('model_unavailable', 'timeout', 'invalid_response')",
            name="ck_ai_explanations_failure_reason",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    model_name: Mapped[str] = mapped_column(String(120))
    prompt_version: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20))
    failure_reason: Mapped[str | None] = mapped_column(String(30), nullable=True)
    plain_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    why_it_matters: Mapped[str | None] = mapped_column(Text, nullable=True)
    fixed_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    fix_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_confidence: Mapped[str | None] = mapped_column(String(20), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
