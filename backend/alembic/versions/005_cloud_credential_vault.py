"""Cloud credential vault for AES-256-GCM encrypted secret management

Revision ID: 005_cloud_credentials
Revises: 004_enterprise_schema
Create Date: 2026-11-17 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "005_cloud_credentials"
down_revision: Union[str, None] = "004_enterprise_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    # Create internal tracking table for tracking ownership of tables created by this revision
    if "_alembic_005_created_tables" not in existing_tables:
        op.create_table(
            "_alembic_005_created_tables",
            sa.Column("table_name", sa.String(length=64), primary_key=True, nullable=False),
        )

    # 1. cloud_credential_vault
    if "cloud_credential_vault" not in existing_tables:
        op.create_table(
            "cloud_credential_vault",
            sa.Column(
                "account_id",
                sa.String(length=128),
                sa.ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
                primary_key=True,
                nullable=False,
            ),
            sa.Column("provider", sa.String(length=32), nullable=False),
            sa.Column("auth_method", sa.String(length=64), nullable=False),
            sa.Column("encrypted_blob", sa.Text(), nullable=False),
            sa.Column("key_version", sa.String(length=32), server_default="v1", nullable=False),
            sa.Column("masked_identity", sa.String(length=255), nullable=False),
            sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_cloud_credential_vault_account_id", "cloud_credential_vault", ["account_id"], unique=False)
        op.create_index("ix_cloud_credential_vault_provider", "cloud_credential_vault", ["provider"], unique=False)
        op.execute(sa.text("INSERT INTO _alembic_005_created_tables (table_name) VALUES ('cloud_credential_vault')"))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    created_by_005: set[str] = set()
    if "_alembic_005_created_tables" in existing_tables:
        res = bind.execute(sa.text("SELECT table_name FROM _alembic_005_created_tables")).fetchall()
        created_by_005 = {row[0] for row in res}

    if "cloud_credential_vault" in created_by_005 and "cloud_credential_vault" in existing_tables:
        op.drop_table("cloud_credential_vault")

    if "_alembic_005_created_tables" in existing_tables:
        op.drop_table("_alembic_005_created_tables")
