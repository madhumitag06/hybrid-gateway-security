"""
Adaptive Machine Learning Feedback & Retraining Models
======================================================
Stores analyst feedback, verified ground-truth labels, curated dataset snapshots,
and versioned candidate retraining runs without modifying active production weights.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from backend.app.db.base import Base, TimestampMixin


class AdaptiveFlowFeedbackModel(Base, TimestampMixin):
    """
    Persists evaluated network flows with optional verified analyst labels.
    Never treats model predictions as ground truth.
    """
    __tablename__ = "adaptive_flow_feedbacks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)  # e.g. "fb-1a2b3c4d"
    ingestion_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("pcap_ingestions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    flow_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="TCP")
    
    # 9-feature schema (V2)
    flow_features: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    
    predicted_class: Mapped[str] = mapped_column(String(32), nullable=False)
    prediction_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    
    # Verified ground truth label: "BENIGN", "PORT_SCAN", "BRUTE_FORCE", "TRAFFIC_SPIKE", "SUSPICIOUS_TRANSFER"
    verified_label: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    
    # Status: "UNVERIFIED", "CONFIRMED", "CORRECTED", "EXCLUDED"
    feedback_status: Mapped[str] = mapped_column(String(32), nullable=False, default="UNVERIFIED", index=True)
    
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    is_training_eligible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "ingestion_id": self.ingestion_id,
            "flow_id": self.flow_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "flow_features": self.flow_features,
            "predicted_class": self.predicted_class,
            "prediction_confidence": round(self.prediction_confidence, 4),
            "model_version": self.model_version,
            "verified_label": self.verified_label,
            "feedback_status": self.feedback_status,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "notes": self.notes,
            "is_training_eligible": self.is_training_eligible,
        }


class AdaptiveTrainingRunModel(Base, TimestampMixin):
    """
    Audit record for isolated, administrator-triggered candidate model retraining runs.
    """
    __tablename__ = "adaptive_training_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)  # e.g. "run-adaptive-v1"
    candidate_version: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    base_model_version: Mapped[str] = mapped_column(String(64), nullable=False, default="candidate_xgboost_v2")
    
    # Status: "PENDING", "TRAINING", "COMPLETED", "FAILED", "EVALUATED", "PROMOTED", "REJECTED"
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING", index=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    class_distribution: Mapped[Optional[Dict[str, int]]] = mapped_column(JSON, nullable=True, default=dict)
    
    training_metrics: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)
    evaluation_comparison: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)
    
    artifacts_dir: Mapped[str] = mapped_column(String(255), nullable=False)
    promoted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    promoted_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "candidate_version": self.candidate_version,
            "base_model_version": self.base_model_version,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "sample_count": self.sample_count,
            "class_distribution": self.class_distribution or {},
            "training_metrics": self.training_metrics or {},
            "evaluation_comparison": self.evaluation_comparison or {},
            "artifacts_dir": self.artifacts_dir,
            "promoted_at": self.promoted_at.isoformat() if self.promoted_at else None,
            "promoted_by": self.promoted_by,
            "error_message": self.error_message,
        }

