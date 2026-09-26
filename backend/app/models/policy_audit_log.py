"""
Policy Audit Log ORM Model
==========================
Maintains an immutable historical ledger of all policy actions, updates,
and automated gateway enforcements.
"""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.db.base import Base


class PolicyAuditLogModel(Base):
    __tablename__ = "policy_audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("security_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requested_action: Mapped[str] = mapped_column(String(16), nullable=False)
    previous_action: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    resulting_status: Mapped[str] = mapped_column(String(24), nullable=False)
    actor: Mapped[str] = mapped_column(String(64), default="system", nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    event: Mapped["SecurityEventModel"] = relationship(
        "SecurityEventModel",
        back_populates="audit_logs",
    )
