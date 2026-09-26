"""Initial schema for security_events and policy_audit_logs

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-09-27 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create security_events table
    op.create_table(
        "security_events",
        sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=False),
        sa.Column("destination_ip", sa.String(length=45), nullable=False),
        sa.Column("attack_type", sa.String(length=64), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("threat_level", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("action_recommendation", sa.String(length=16), nullable=False),
        sa.Column("current_policy_action", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("is_anomaly", sa.Boolean(), nullable=False, default=False),
        sa.Column("is_demo", sa.Boolean(), nullable=False, default=False),
        sa.Column("flow_features", sa.JSON(), nullable=False),
        sa.Column("class_probabilities", sa.JSON(), nullable=False),
        sa.Column("top_contributing_features", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="chk_risk_score_range"),
    )
    op.create_index("ix_security_events_id", "security_events", ["id"], unique=False)
    op.create_index("ix_security_events_timestamp", "security_events", ["timestamp"], unique=False)
    op.create_index("ix_security_events_source_ip", "security_events", ["source_ip"], unique=False)
    op.create_index("ix_security_events_destination_ip", "security_events", ["destination_ip"], unique=False)
    op.create_index("ix_security_events_attack_type", "security_events", ["attack_type"], unique=False)
    op.create_index("ix_security_events_risk_score", "security_events", ["risk_score"], unique=False)
    op.create_index("ix_security_events_threat_level", "security_events", ["threat_level"], unique=False)
    op.create_index("ix_security_events_current_policy_action", "security_events", ["current_policy_action"], unique=False)
    op.create_index("ix_security_events_is_anomaly", "security_events", ["is_anomaly"], unique=False)
    op.create_index("ix_security_events_is_demo", "security_events", ["is_demo"], unique=False)

    # 2. Create policy_audit_logs table
    op.create_table(
        "policy_audit_logs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column(
            "event_id",
            sa.String(length=64),
            sa.ForeignKey("security_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("requested_action", sa.String(length=16), nullable=False),
        sa.Column("previous_action", sa.String(length=16), nullable=True),
        sa.Column("resulting_status", sa.String(length=24), nullable=False),
        sa.Column("actor", sa.String(length=64), nullable=False, server_default="system"),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_policy_audit_logs_event_id", "policy_audit_logs", ["event_id"], unique=False)
    op.create_index("ix_policy_audit_logs_timestamp", "policy_audit_logs", ["timestamp"], unique=False)


def downgrade() -> None:
    op.drop_table("policy_audit_logs")
    op.drop_table("security_events")
