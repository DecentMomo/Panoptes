"""AI explanation cache

Revision ID: 0005_ai_explanations
Revises: 0004_scanner_run_version
Create Date: 2026-09-30

"""

import sqlalchemy as sa
from alembic import op

revision: str = "0005_ai_explanations"
down_revision: str | None = "0004_scanner_run_version"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "ai_explanations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("model_name", sa.String(length=120), nullable=False),
        sa.Column("prompt_version", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("failure_reason", sa.String(length=30), nullable=True),
        sa.Column("plain_explanation", sa.Text(), nullable=True),
        sa.Column("why_it_matters", sa.Text(), nullable=True),
        sa.Column("fixed_code", sa.Text(), nullable=True),
        sa.Column("fix_rationale", sa.Text(), nullable=True),
        sa.Column("ai_confidence", sa.String(length=20), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "failure_reason IS NULL OR failure_reason IN "
            "('model_unavailable', 'timeout', 'invalid_response')",
            name="ck_ai_explanations_failure_reason",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="ck_ai_explanations_status",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "fingerprint",
            "model_name",
            "prompt_version",
            name="uq_ai_explanations_cache_key",
        ),
    )
    op.create_index(
        op.f("ix_ai_explanations_fingerprint"),
        "ai_explanations",
        ["fingerprint"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_ai_explanations_fingerprint"), table_name="ai_explanations")
    op.drop_table("ai_explanations")
