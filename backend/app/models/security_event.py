"""
Security Event ORM Model
========================
Represents evaluated network security incidents, associated flow features,
ML classification metrics, and active gateway policy states.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.db.base import Base, TimestampMixin


class SecurityEventModel(Base, TimestampMixin):
    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="chk_risk_score_range"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)

    # ML Threat Classification & Risk
    attack_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    threat_level: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    action_recommendation: Mapped[str] = mapped_column(String(16), nullable=False)

    # Policy Enforcement State
    current_policy_action: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)

    # Rich ML Feature Vectors & Explainability Data
    flow_features: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    class_probabilities: Mapped[Dict[str, float]] = mapped_column(JSON, nullable=False, default=dict)
    top_contributing_features: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)

    # Audit Trail Relationship
    audit_logs: Mapped[List["PolicyAuditLogModel"]] = relationship(
        "PolicyAuditLogModel",
        back_populates="event",
        cascade="all, delete-orphan",
        order_by="desc(PolicyAuditLogModel.timestamp)",
    )
