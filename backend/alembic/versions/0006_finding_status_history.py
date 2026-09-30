"""finding status history

Revision ID: 0006_finding_status_history
Revises: 0005_ai_explanations
Create Date: 2026-09-30

"""

import sqlalchemy as sa
from alembic import op

revision: str = "0006_finding_status_history"
down_revision: str | None = "0005_ai_explanations"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_findings_status",
        "findings",
        "status IN ('open', 'fixed', 'false_positive', 'accepted_risk')",
    )
    op.create_table(
        "finding_status_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("from_status", sa.String(length=20), nullable=False),
        sa.Column("to_status", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "from_status IN ('open', 'fixed', 'false_positive', 'accepted_risk')",
            name="ck_finding_status_history_from",
        ),
        sa.CheckConstraint(
            "to_status IN ('open', 'fixed', 'false_positive', 'accepted_risk')",
            name="ck_finding_status_history_to",
        ),
        sa.CheckConstraint(
            "to_status <> 'false_positive' OR (reason IS NOT NULL AND btrim(reason) <> '')",
            name="ck_finding_status_history_false_positive_reason",
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_finding_status_history_finding_id"),
        "finding_status_history",
        ["finding_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_finding_status_history_finding_id"),
        table_name="finding_status_history",
    )
    op.drop_table("finding_status_history")
    op.drop_constraint("ck_findings_status", "findings", type_="check")
