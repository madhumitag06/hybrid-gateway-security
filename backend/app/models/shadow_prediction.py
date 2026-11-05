"""
Shadow Prediction ORM Model (Phase 3)
=====================================
Persists parallel evaluations from the candidate machine-learning model (Big Data XGBoost V2)
running in advisory SHADOW MODE alongside the authoritative production model (Random Forest).
Enables telemetry capture, latency tracking, agreement/disagreement auditing, and SHAP attribution storage
without granting the candidate model any firewall enforcement authority.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.db.base import Base, TimestampMixin


class ShadowPredictionModel(Base, TimestampMixin):
    __tablename__ = "shadow_predictions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    flow_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, default="TCP")

    # Feature vector schema metadata
    feature_schema_version: Mapped[str] = mapped_column(String(16), default="v2", nullable=False)
    flow_features: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Production Model (Authoritative Random Forest) Telemetry
    prod_model_version: Mapped[str] = mapped_column(String(32), default="v1_random_forest", nullable=False)
    prod_attack_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    prod_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    prod_risk_score: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    prod_latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Candidate Model (Advisory XGBoost V2) Telemetry
    candidate_model_version: Mapped[str] = mapped_column(String(32), default="v2_xgboost", nullable=False)
    candidate_attack_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    candidate_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    candidate_risk_score: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    candidate_latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Model Comparison & Agreement Analysis
    agreement: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    disagreement_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    # Explainability Data (SHAP Local Attributions for Candidate)
    shap_attributions: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=True)

