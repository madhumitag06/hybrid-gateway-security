"""
Security Event Repository
=========================
Encapsulates all database operations for security events, querying, filtering,
aggregation, and policy state updates.
"""

from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import desc, func, select, or_
from sqlalchemy.orm import Session
from backend.app.models.security_event import SecurityEventModel


class SecurityEventRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, event: SecurityEventModel) -> SecurityEventModel:
        """Insert and commit a new security event record."""
        self.db.add(event)
        self.db.flush()
        return event

    def get_by_id(self, event_id: str) -> Optional[SecurityEventModel]:
        """Fetch a single security event by its ID."""
        stmt = select(SecurityEventModel).where(SecurityEventModel.id == event_id)
        return self.db.scalars(stmt).first()

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        threat_level: Optional[str] = None,
        attack_type: Optional[str] = None,
        action: Optional[str] = None,
        min_risk: Optional[int] = None,
        max_risk: Optional[int] = None,
        is_anomaly: Optional[bool] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[SecurityEventModel], int]:
        """
        Query security events with multi-dimensional filtering, search, and pagination.
        Returns (list_of_events, total_matching_count).
        """
        stmt = select(SecurityEventModel)

        if threat_level:
            stmt = stmt.where(SecurityEventModel.threat_level == threat_level.upper())
        if attack_type:
            stmt = stmt.where(SecurityEventModel.attack_type == attack_type.upper())
        if action:
            stmt = stmt.where(SecurityEventModel.current_policy_action == action)
        if min_risk is not None:
            stmt = stmt.where(SecurityEventModel.risk_score >= min_risk)
        if max_risk is not None:
            stmt = stmt.where(SecurityEventModel.risk_score <= max_risk)
        if is_anomaly is not None:
            stmt = stmt.where(SecurityEventModel.is_anomaly == is_anomaly)
        if search:
            search_pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    SecurityEventModel.id.ilike(search_pattern),
                    SecurityEventModel.source_ip.ilike(search_pattern),
                    SecurityEventModel.destination_ip.ilike(search_pattern),
                    SecurityEventModel.attack_type.ilike(search_pattern),
                    SecurityEventModel.description.ilike(search_pattern),
                )
            )

        # Count total matching rows
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_count = self.db.scalar(count_stmt) or 0

        # Apply ordering and pagination
        stmt = stmt.order_by(desc(SecurityEventModel.timestamp)).limit(limit).offset(offset)
        events = list(self.db.scalars(stmt).all())
        return events, total_count

    def update_policy_action(
        self, event_id: str, new_action: str, new_status: str
    ) -> Optional[SecurityEventModel]:
        """Update current policy action and status on an existing event."""
        event = self.get_by_id(event_id)
        if not event:
            return None
        event.current_policy_action = new_action
        event.status = new_status
        self.db.flush()
        return event

    def count(self) -> int:
        """Count total events stored in the database."""
        stmt = select(func.count(SecurityEventModel.id))
        return self.db.scalar(stmt) or 0

    def get_recent(self, limit: int = 10) -> List[SecurityEventModel]:
        """Get the most recent security events ordered by timestamp descending."""
        stmt = (
            select(SecurityEventModel)
            .order_by(desc(SecurityEventModel.timestamp))
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def delete_by_id(self, event_id: str) -> bool:
        """Delete an event by ID."""
        event = self.get_by_id(event_id)
        if not event:
            return False
        self.db.delete(event)
        self.db.flush()
        return True
