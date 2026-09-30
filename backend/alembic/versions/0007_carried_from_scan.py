"""carry-over source scan on status history

Revision ID: 0007_carried_from_scan
Revises: 0006_finding_status_history
Create Date: 2026-09-30

"""

import sqlalchemy as sa
from alembic import op

revision: str = "0007_carried_from_scan"
down_revision: str | None = "0006_finding_status_history"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "finding_status_history",
        sa.Column("carried_from_scan_id", sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        "fk_finding_status_history_carried_from_scan_id",
        "finding_status_history",
        "scans",
        ["carried_from_scan_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_finding_status_history_carried_from_scan_id",
        "finding_status_history",
        type_="foreignkey",
    )
    op.drop_column("finding_status_history", "carried_from_scan_id")
