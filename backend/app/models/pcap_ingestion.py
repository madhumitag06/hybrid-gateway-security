"""
PCAP Ingestion Record ORM Model
===============================
Persists comprehensive metadata, status, throughput metrics, flow counts,
and evaluated flow summaries for raw network capture uploads.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    DateTime,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from backend.app.db.base import Base, TimestampMixin


class PcapIngestionModel(Base, TimestampMixin):
    __tablename__ = "pcap_ingestions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)  # e.g. "ingest-7f9a2b1c"
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_type: Mapped[str] = mapped_column(String(32), nullable=False, default="PCAP")  # "PCAP", "PCAPNG", "SAMPLE"
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    processing_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    processing_completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Status: "QUEUED", "PROCESSING", "COMPLETED", "PARTIAL", "FAILED"
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PROCESSING", index=True)
    
    total_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_flows: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    flows_evaluated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    
    benign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suspicious_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_risk_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    
    attack_distribution: Mapped[Optional[Dict[str, int]]] = mapped_column(JSON, nullable=True, default=dict)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False, default="candidate_xgboost_v2")
    metrics: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)
    
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    summary_results: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSON, nullable=True, default=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "filename": self.filename,
            "file_type": self.file_type,
            "file_size_bytes": self.file_size_bytes,
            "uploaded_at": self.uploaded_at.isoformat() if self.uploaded_at else None,
            "processing_started_at": self.processing_started_at.isoformat() if self.processing_started_at else None,
            "processing_completed_at": self.processing_completed_at.isoformat() if self.processing_completed_at else None,
            "status": self.status,
            "total_packets": self.total_packets,
            "total_flows": self.total_flows,
            "flows_evaluated": self.flows_evaluated,
            "benign_count": self.benign_count,
            "suspicious_count": self.suspicious_count,
            "high_risk_count": self.high_risk_count,
            "attack_distribution": self.attack_distribution or {},
            "model_version": self.model_version,
            "metrics": self.metrics or {},
            "error_message": self.error_message,
            "summary_results": self.summary_results or [],
        }

