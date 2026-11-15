"""
Cloud Account & Discovered Resource ORM Models
==============================================
Persists non-secret cloud provider metadata, discovered network resources
(VPCs, Subnets, Security Groups, Firewalls), connection statuses, and capability flags.
Guaranteed NEVER to store secret keys, tokens, or private credentials.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.db.base import Base, TimestampMixin


class CloudAccountModel(Base, TimestampMixin):
    """
    Persists cloud provider integration accounts and connection telemetry.
    """
    __tablename__ = "cloud_accounts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # AWS, GCP, AZURE, DOCKER_LAB
    account_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)  # Account ID / Project ID / Subscription ID
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="us-east-1")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="NOT_CONFIGURED", index=True)  # NOT_CONFIGURED, CONFIGURED, CONNECTED, DEGRADED, ERROR
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    capabilities: Mapped[Dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=False,
        default=dict,
    )
    last_connection_check: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_telemetry_sync: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=False,
        default=dict,
    )

    resources = relationship(
        "CloudResourceModel",
        back_populates="account",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class CloudResourceModel(Base, TimestampMixin):
    """
    Persists discovered network resources across cloud providers.
    """
    __tablename__ = "cloud_resources"

    id: Mapped[str] = mapped_column(String(128), primary_key=True, index=True)
    cloud_account_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # VPC, SUBNET, SECURITY_GROUP, FIREWALL_RULE, NETWORK_INTERFACE
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    resource_name: Mapped[str] = mapped_column(String(128), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    cidr_block: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    parent_resource_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=False,
        default=dict,
    )
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    account = relationship("CloudAccountModel", back_populates="resources")


class CloudTelemetryCheckpointModel(Base, TimestampMixin):
    """
    Tracks incremental telemetry ingestion checkpoints per provider and source destination.
    Enables restart recovery without reprocessing historical events.
    """
    __tablename__ = "cloud_telemetry_checkpoints"

    id: Mapped[str] = mapped_column(String(128), primary_key=True, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    account_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)  # CLOUDWATCH_LOGS, S3, SIMULATED
    source_identifier: Mapped[str] = mapped_column(String(255), nullable=False)  # log group name or s3 bucket/prefix
    last_timestamp_ms: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    last_token: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    last_object_key: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    total_records_processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_poll_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=False,
        default=dict,
    )


class CloudTelemetryIngestionModel(Base, TimestampMixin):
    """
    Historical audit record for each telemetry polling/ingestion batch.
    """
    __tablename__ = "cloud_telemetry_ingestions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)  # cld-ingest-<uuid>
    provider: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    account_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)  # CLOUDWATCH_LOGS, S3, SIMULATED_MOCK
    source_identifier: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    records_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_ingested: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_duplicate_skipped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_rejected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_risk_detected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    flows_accepted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    flows_dropped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="SUCCESS")  # SUCCESS, EMPTY, PARTIAL, FAILED
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    summary_json: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
        default=list,
    )

