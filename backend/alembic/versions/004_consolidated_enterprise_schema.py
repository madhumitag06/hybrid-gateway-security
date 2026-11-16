"""Consolidated enterprise schema for multi-cloud, PCAP, shadow mode, adaptive learning, and audit ledger

Revision ID: 004_consolidated_enterprise_schema
Revises: 003_auth_users
Create Date: 2026-11-16 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "004_enterprise_schema"
down_revision: Union[str, None] = "003_auth_users"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    # Create internal tracking table for tracking ownership of tables created by this revision
    if "_alembic_004_created_tables" not in existing_tables:
        op.create_table(
            "_alembic_004_created_tables",
            sa.Column("table_name", sa.String(length=64), primary_key=True, nullable=False),
        )

    # 1. policy_audit_logs
    if "policy_audit_logs" not in existing_tables:
        op.create_table(
            "policy_audit_logs",
            sa.Column(
                "id",
                sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
                primary_key=True,
                autoincrement=True,
                nullable=False,
            ),
            sa.Column(
                "event_id",
                sa.String(length=64),
                sa.ForeignKey("security_events.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("requested_action", sa.String(length=16), nullable=False),
            sa.Column("previous_action", sa.String(length=16), nullable=True),
            sa.Column("resulting_status", sa.String(length=24), nullable=False),
            sa.Column("actor", sa.String(length=64), server_default="system", nullable=False),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_policy_audit_logs_event_id", "policy_audit_logs", ["event_id"], unique=False)
        op.create_index("ix_policy_audit_logs_timestamp", "policy_audit_logs", ["timestamp"], unique=False)
        op.execute(sa.text("INSERT INTO _alembic_004_created_tables (table_name) VALUES ('policy_audit_logs')"))

    # 2. shadow_predictions
    if "shadow_predictions" not in existing_tables:
        op.create_table(
            "shadow_predictions",
            sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
            sa.Column("flow_id", sa.String(length=64), nullable=True),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
            sa.Column("source_ip", sa.String(length=45), nullable=False),
            sa.Column("destination_ip", sa.String(length=45), nullable=False),
            sa.Column("dst_port", sa.Integer(), nullable=True),
            sa.Column("protocol", sa.String(length=16), server_default="TCP", nullable=True),
            sa.Column("feature_schema_version", sa.String(length=16), server_default="v2", nullable=False),
            sa.Column("flow_features", sa.JSON(), nullable=False),
            sa.Column("prod_model_version", sa.String(length=32), server_default="v1_random_forest", nullable=False),
            sa.Column("prod_attack_type", sa.String(length=64), nullable=False),
            sa.Column("prod_confidence", sa.Float(), nullable=False),
            sa.Column("prod_risk_score", sa.Integer(), nullable=False),
            sa.Column("prod_latency_ms", sa.Float(), server_default="0.0", nullable=False),
            sa.Column("candidate_model_version", sa.String(length=32), server_default="v2_xgboost", nullable=False),
            sa.Column("candidate_attack_type", sa.String(length=64), nullable=False),
            sa.Column("candidate_confidence", sa.Float(), nullable=False),
            sa.Column("candidate_risk_score", sa.Integer(), nullable=False),
            sa.Column("candidate_latency_ms", sa.Float(), server_default="0.0", nullable=False),
            sa.Column("agreement", sa.Boolean(), nullable=False),
            sa.Column("disagreement_type", sa.String(length=64), nullable=True),
            sa.Column("shap_feature_importance", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_shadow_predictions_id", "shadow_predictions", ["id"], unique=False)
        op.create_index("ix_shadow_predictions_flow_id", "shadow_predictions", ["flow_id"], unique=False)
        op.create_index("ix_shadow_predictions_timestamp", "shadow_predictions", ["timestamp"], unique=False)
        op.create_index("ix_shadow_predictions_source_ip", "shadow_predictions", ["source_ip"], unique=False)
        op.create_index("ix_shadow_predictions_destination_ip", "shadow_predictions", ["destination_ip"], unique=False)
        op.create_index("ix_shadow_predictions_prod_attack_type", "shadow_predictions", ["prod_attack_type"], unique=False)
        op.create_index("ix_shadow_predictions_prod_risk_score", "shadow_predictions", ["prod_risk_score"], unique=False)
        op.create_index("ix_shadow_predictions_candidate_attack_type", "shadow_predictions", ["candidate_attack_type"], unique=False)
        op.create_index("ix_shadow_predictions_candidate_risk_score", "shadow_predictions", ["candidate_risk_score"], unique=False)
        op.create_index("ix_shadow_predictions_agreement", "shadow_predictions", ["agreement"], unique=False)
        op.create_index("ix_shadow_predictions_disagreement_type", "shadow_predictions", ["disagreement_type"], unique=False)
        op.execute(sa.text("INSERT INTO _alembic_004_created_tables (table_name) VALUES ('shadow_predictions')"))

    # 3. pcap_ingestions
    if "pcap_ingestions" not in existing_tables:
        op.create_table(
            "pcap_ingestions",
            sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
            sa.Column("filename", sa.String(length=255), nullable=False),
            sa.Column("file_type", sa.String(length=32), server_default="PCAP", nullable=False),
            sa.Column("file_size_bytes", sa.Integer(), server_default="0", nullable=False),
            sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("processing_started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("processing_completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status", sa.String(length=32), server_default="PROCESSING", nullable=False),
            sa.Column("total_packets", sa.Integer(), server_default="0", nullable=False),
            sa.Column("total_flows", sa.Integer(), server_default="0", nullable=False),
            sa.Column("flows_evaluated", sa.Integer(), server_default="0", nullable=False),
            sa.Column("benign_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("suspicious_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("high_risk_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("attack_distribution", sa.JSON(), nullable=True),
            sa.Column("model_version", sa.String(length=64), server_default="candidate_xgboost_v2", nullable=False),
            sa.Column("metrics", sa.JSON(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("summary_results", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_pcap_ingestions_id", "pcap_ingestions", ["id"], unique=False)
        op.create_index("ix_pcap_ingestions_uploaded_at", "pcap_ingestions", ["uploaded_at"], unique=False)
        op.create_index("ix_pcap_ingestions_status", "pcap_ingestions", ["status"], unique=False)
        op.execute(sa.text("INSERT INTO _alembic_004_created_tables (table_name) VALUES ('pcap_ingestions')"))

    # 4. adaptive_flow_feedbacks
    if "adaptive_flow_feedbacks" not in existing_tables:
        op.create_table(
            "adaptive_flow_feedbacks",
            sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
            sa.Column(
                "ingestion_id",
                sa.String(length=64),
                sa.ForeignKey("pcap_ingestions.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("flow_id", sa.String(length=64), nullable=False),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
            sa.Column("source_ip", sa.String(length=45), nullable=False),
            sa.Column("destination_ip", sa.String(length=45), nullable=False),
            sa.Column("dst_port", sa.Integer(), nullable=False),
            sa.Column("protocol", sa.String(length=16), server_default="TCP", nullable=False),
            sa.Column("flow_features", sa.JSON(), nullable=False),
            sa.Column("predicted_class", sa.String(length=32), nullable=False),
            sa.Column("prediction_confidence", sa.Float(), nullable=False),
            sa.Column("model_version", sa.String(length=64), nullable=False),
            sa.Column("verified_label", sa.String(length=32), nullable=True),
            sa.Column("feedback_status", sa.String(length=32), server_default="UNVERIFIED", nullable=False),
            sa.Column("reviewed_by", sa.String(length=64), nullable=True),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("is_training_eligible", sa.Boolean(), server_default=sa.text("false"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_adaptive_flow_feedbacks_id", "adaptive_flow_feedbacks", ["id"], unique=False)
        op.create_index("ix_adaptive_flow_feedbacks_ingestion_id", "adaptive_flow_feedbacks", ["ingestion_id"], unique=False)
        op.create_index("ix_adaptive_flow_feedbacks_flow_id", "adaptive_flow_feedbacks", ["flow_id"], unique=False)
        op.create_index("ix_adaptive_flow_feedbacks_timestamp", "adaptive_flow_feedbacks", ["timestamp"], unique=False)
        op.create_index("ix_adaptive_flow_feedbacks_source_ip", "adaptive_flow_feedbacks", ["source_ip"], unique=False)
        op.create_index("ix_adaptive_flow_feedbacks_verified_label", "adaptive_flow_feedbacks", ["verified_label"], unique=False)
        op.create_index("ix_adaptive_flow_feedbacks_feedback_status", "adaptive_flow_feedbacks", ["feedback_status"], unique=False)
        op.create_index("ix_adaptive_flow_feedbacks_is_training_eligible", "adaptive_flow_feedbacks", ["is_training_eligible"], unique=False)
        op.execute(sa.text("INSERT INTO _alembic_004_created_tables (table_name) VALUES ('adaptive_flow_feedbacks')"))

    # 5. adaptive_training_runs
    if "adaptive_training_runs" not in existing_tables:
        op.create_table(
            "adaptive_training_runs",
            sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
            sa.Column("candidate_version", sa.String(length=64), nullable=False),
            sa.Column("base_model_version", sa.String(length=64), server_default="candidate_xgboost_v2", nullable=False),
            sa.Column("status", sa.String(length=32), server_default="PENDING", nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("sample_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("class_distribution", sa.JSON(), nullable=True),
            sa.Column("training_metrics", sa.JSON(), nullable=True),
            sa.Column("evaluation_comparison", sa.JSON(), nullable=True),
            sa.Column("artifacts_dir", sa.String(length=255), nullable=False),
            sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("promoted_by", sa.String(length=64), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_adaptive_training_runs_id", "adaptive_training_runs", ["id"], unique=False)
        op.create_index("ix_adaptive_training_runs_candidate_version", "adaptive_training_runs", ["candidate_version"], unique=True)
        op.create_index("ix_adaptive_training_runs_status", "adaptive_training_runs", ["status"], unique=False)
        op.execute(sa.text("INSERT INTO _alembic_004_created_tables (table_name) VALUES ('adaptive_training_runs')"))

    # 6. cloud_accounts
    if "cloud_accounts" not in existing_tables:
        op.create_table(
            "cloud_accounts",
            sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
            sa.Column("provider", sa.String(length=32), nullable=False),
            sa.Column("account_id", sa.String(length=128), nullable=False),
            sa.Column("display_name", sa.String(length=128), nullable=False),
            sa.Column("region", sa.String(length=64), server_default="us-east-1", nullable=False),
            sa.Column("status", sa.String(length=32), server_default="NOT_CONFIGURED", nullable=False),
            sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
            sa.Column("capabilities", sa.JSON().with_variant(JSONB, "postgresql"), nullable=False),
            sa.Column("last_connection_check", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_telemetry_sync", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("metadata_json", sa.JSON().with_variant(JSONB, "postgresql"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_cloud_accounts_id", "cloud_accounts", ["id"], unique=False)
        op.create_index("ix_cloud_accounts_provider", "cloud_accounts", ["provider"], unique=False)
        op.create_index("ix_cloud_accounts_account_id", "cloud_accounts", ["account_id"], unique=False)
        op.create_index("ix_cloud_accounts_status", "cloud_accounts", ["status"], unique=False)
        op.execute(sa.text("INSERT INTO _alembic_004_created_tables (table_name) VALUES ('cloud_accounts')"))

    # 7. cloud_resources
    if "cloud_resources" not in existing_tables:
        op.create_table(
            "cloud_resources",
            sa.Column("id", sa.String(length=128), primary_key=True, nullable=False),
            sa.Column(
                "cloud_account_id",
                sa.String(length=64),
                sa.ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("provider", sa.String(length=32), nullable=False),
            sa.Column("resource_type", sa.String(length=64), nullable=False),
            sa.Column("resource_id", sa.String(length=128), nullable=False),
            sa.Column("resource_name", sa.String(length=128), nullable=False),
            sa.Column("region", sa.String(length=64), nullable=False),
            sa.Column("cidr_block", sa.String(length=64), nullable=True),
            sa.Column("parent_resource_id", sa.String(length=128), nullable=True),
            sa.Column("metadata_json", sa.JSON().with_variant(JSONB, "postgresql"), nullable=False),
            sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_cloud_resources_id", "cloud_resources", ["id"], unique=False)
        op.create_index("ix_cloud_resources_cloud_account_id", "cloud_resources", ["cloud_account_id"], unique=False)
        op.create_index("ix_cloud_resources_provider", "cloud_resources", ["provider"], unique=False)
        op.create_index("ix_cloud_resources_resource_type", "cloud_resources", ["resource_type"], unique=False)
        op.create_index("ix_cloud_resources_resource_id", "cloud_resources", ["resource_id"], unique=False)
        op.execute(sa.text("INSERT INTO _alembic_004_created_tables (table_name) VALUES ('cloud_resources')"))

    # 8. cloud_telemetry_checkpoints
    if "cloud_telemetry_checkpoints" not in existing_tables:
        op.create_table(
            "cloud_telemetry_checkpoints",
            sa.Column("id", sa.String(length=128), primary_key=True, nullable=False),
            sa.Column("provider", sa.String(length=32), nullable=False),
            sa.Column("account_id", sa.String(length=128), nullable=False),
            sa.Column("source_type", sa.String(length=32), nullable=False),
            sa.Column("source_identifier", sa.String(length=255), nullable=False),
            sa.Column("last_timestamp_ms", sa.BigInteger(), nullable=True),
            sa.Column("last_token", sa.String(length=1024), nullable=True),
            sa.Column("last_object_key", sa.String(length=1024), nullable=True),
            sa.Column("total_records_processed", sa.Integer(), server_default="0", nullable=False),
            sa.Column("last_poll_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("metadata_json", sa.JSON().with_variant(JSONB, "postgresql"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_cloud_telemetry_checkpoints_id", "cloud_telemetry_checkpoints", ["id"], unique=False)
        op.create_index("ix_cloud_telemetry_checkpoints_provider", "cloud_telemetry_checkpoints", ["provider"], unique=False)
        op.create_index("ix_cloud_telemetry_checkpoints_account_id", "cloud_telemetry_checkpoints", ["account_id"], unique=False)
        op.execute(sa.text("INSERT INTO _alembic_004_created_tables (table_name) VALUES ('cloud_telemetry_checkpoints')"))

    # 9. cloud_telemetry_ingestions
    if "cloud_telemetry_ingestions" not in existing_tables:
        op.create_table(
            "cloud_telemetry_ingestions",
            sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
            sa.Column("provider", sa.String(length=32), nullable=False),
            sa.Column("account_id", sa.String(length=128), nullable=False),
            sa.Column("source_type", sa.String(length=32), nullable=False),
            sa.Column("source_identifier", sa.String(length=255), nullable=True),
            sa.Column("records_discovered", sa.Integer(), server_default="0", nullable=False),
            sa.Column("records_ingested", sa.Integer(), server_default="0", nullable=False),
            sa.Column("records_duplicate_skipped", sa.Integer(), server_default="0", nullable=False),
            sa.Column("records_rejected", sa.Integer(), server_default="0", nullable=False),
            sa.Column("high_risk_detected", sa.Integer(), server_default="0", nullable=False),
            sa.Column("flows_accepted", sa.Integer(), server_default="0", nullable=False),
            sa.Column("flows_dropped", sa.Integer(), server_default="0", nullable=False),
            sa.Column("status", sa.String(length=32), server_default="SUCCESS", nullable=False),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("duration_ms", sa.Float(), server_default="0.0", nullable=False),
            sa.Column("summary_json", sa.JSON().with_variant(JSONB, "postgresql"), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_cloud_telemetry_ingestions_id", "cloud_telemetry_ingestions", ["id"], unique=False)
        op.create_index("ix_cloud_telemetry_ingestions_provider", "cloud_telemetry_ingestions", ["provider"], unique=False)
        op.create_index("ix_cloud_telemetry_ingestions_account_id", "cloud_telemetry_ingestions", ["account_id"], unique=False)
        op.execute(sa.text("INSERT INTO _alembic_004_created_tables (table_name) VALUES ('cloud_telemetry_ingestions')"))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    # Only drop tables that were explicitly created by this revision (004)
    # This prevents dropping pre-existing tables that revision 004 skipped.
    created_by_004: set[str] = set()
    if "_alembic_004_created_tables" in existing_tables:
        res = bind.execute(sa.text("SELECT table_name FROM _alembic_004_created_tables")).fetchall()
        created_by_004 = {row[0] for row in res}

    tables_to_drop = [
        "cloud_telemetry_ingestions",
        "cloud_telemetry_checkpoints",
        "cloud_resources",
        "cloud_accounts",
        "adaptive_training_runs",
        "adaptive_flow_feedbacks",
        "pcap_ingestions",
        "shadow_predictions",
        "policy_audit_logs",
    ]

    for table in tables_to_drop:
        if table in created_by_004 and table in existing_tables:
            op.drop_table(table)

    if "_alembic_004_created_tables" in existing_tables:
        op.drop_table("_alembic_004_created_tables")
