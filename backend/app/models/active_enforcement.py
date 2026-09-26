"""
Active Enforcement ORM Model
============================
Represents active, expired, or revoked network containment rules evaluated by
the Adaptive Policy Engine and executed via controlled enforcement adapters.
"""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.db.base import Base, TimestampMixin


class ActiveEnforcementModel(Base, TimestampMixin):
    __tablename__ = "active_enforcements"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)  # e.g. "rule-7a2f1c09"
    event_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("security_events.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    target_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, default="ANY")
    action: Mapped[str] = mapped_column(String(16), nullable=False)  # "Monitor", "Restrict", "Block"
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="ACTIVE", index=True)  # "ACTIVE", "EXPIRED", "REVOKED", "FAILED"
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="DRY_RUN")  # "DRY_RUN", "SANDBOX"
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Optional relationship back to the triggering security event
    event = relationship("SecurityEventModel", foreign_keys=[event_id], lazy="joined")
