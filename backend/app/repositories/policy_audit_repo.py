"""
Policy Audit Repository
=======================
Handles immutable audit ledger operations for gateway policy changes.
"""

from typing import List, Optional
from sqlalchemy import desc, select
from sqlalchemy.orm import Session
from backend.app.models.policy_audit_log import PolicyAuditLogModel


class PolicyAuditRepository:
    def __init__(self, db: Session):
        self.db = db

    def log_action(
        self,
        event_id: str,
        requested_action: str,
        previous_action: Optional[str],
        resulting_status: str,
        actor: str = "system",
    ) -> PolicyAuditLogModel:
        """Create and commit a new policy change audit entry."""
        log_entry = PolicyAuditLogModel(
            event_id=event_id,
            requested_action=requested_action,
            previous_action=previous_action,
            resulting_status=resulting_status,
            actor=actor,
        )
        self.db.add(log_entry)
        self.db.flush()
        return log_entry

    def get_history_for_event(self, event_id: str) -> List[PolicyAuditLogModel]:
        """Fetch chronological audit history for a specific security event."""
        stmt = (
            select(PolicyAuditLogModel)
            .where(PolicyAuditLogModel.event_id == event_id)
            .order_by(desc(PolicyAuditLogModel.timestamp))
        )
        return list(self.db.scalars(stmt).all())

    def get_recent_logs(self, limit: int = 20) -> List[PolicyAuditLogModel]:
        """Fetch most recent policy audit events across the gateway."""
        stmt = (
            select(PolicyAuditLogModel)
            .order_by(desc(PolicyAuditLogModel.timestamp))
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())
