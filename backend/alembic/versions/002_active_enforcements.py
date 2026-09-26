"""Create active_enforcements table

Revision ID: 002_active_enforcements
Revises: 001_initial_schema
Create Date: 2026-09-27 01:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "002_active_enforcements"
down_revision: Union[str, None] = "001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "active_enforcements",
        sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column(
            "event_id",
            sa.String(length=64),
            sa.ForeignKey("security_events.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("target_ip", sa.String(length=45), nullable=False),
        sa.Column("target_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=16), nullable=True, server_default="ANY"),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="ACTIVE"),
        sa.Column("mode", sa.String(length=16), nullable=False, server_default="DRY_RUN"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("ttl_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_active_enforcements_id", "active_enforcements", ["id"], unique=False)
    op.create_index("ix_active_enforcements_event_id", "active_enforcements", ["event_id"], unique=False)
    op.create_index("ix_active_enforcements_target_ip", "active_enforcements", ["target_ip"], unique=False)
    op.create_index("ix_active_enforcements_status", "active_enforcements", ["status"], unique=False)
    op.create_index("ix_active_enforcements_expires_at", "active_enforcements", ["expires_at"], unique=False)


def downgrade() -> None:
    op.drop_table("active_enforcements")
