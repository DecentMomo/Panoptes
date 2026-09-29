"""scanner run tool version

Revision ID: 0004_scanner_run_version
Revises: 0003_scans_findings
Create Date: 2026-09-30

"""

import sqlalchemy as sa
from alembic import op

revision: str = "0004_scanner_run_version"
down_revision: str | None = "0003_scans_findings"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("scanner_runs", sa.Column("tool_version", sa.String(length=120), nullable=True))


def downgrade() -> None:
    op.drop_column("scanner_runs", "tool_version")
