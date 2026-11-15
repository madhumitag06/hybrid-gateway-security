"""
Active Enforcement Repository
=============================
Handles persistence, queries, lifecycle state updates, and TTL expirations
for active network containment rules in PostgreSQL.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session
from backend.app.models.active_enforcement import ActiveEnforcementModel


class EnforcementRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, rule: ActiveEnforcementModel) -> ActiveEnforcementModel:
        self.db.add(rule)
        self.db.flush()
        return rule

    def get_by_id(self, rule_id: str) -> Optional[ActiveEnforcementModel]:
        stmt = select(ActiveEnforcementModel).where(ActiveEnforcementModel.id == rule_id)
        return self.db.scalar(stmt)

    def find_active_by_target(
        self, target_ip: str, target_port: Optional[int] = None
    ) -> Optional[ActiveEnforcementModel]:
        """
        Find any currently ACTIVE or SIMULATED non-expired rule for the given IP (and optional port).
        """
        now = datetime.now(timezone.utc)
        stmt = select(ActiveEnforcementModel).where(
            ActiveEnforcementModel.target_ip == target_ip,
            ActiveEnforcementModel.status.in_(["ACTIVE", "SIMULATED"]),
            ActiveEnforcementModel.expires_at > now,
        )
        if target_port is not None:
            stmt = stmt.where(
                (ActiveEnforcementModel.target_port == target_port)
                | (ActiveEnforcementModel.target_port.is_(None))
                | (ActiveEnforcementModel.action == "Block")
            )
        stmt = stmt.order_by(
            (ActiveEnforcementModel.action == "Block").desc(),
            (ActiveEnforcementModel.status == "ACTIVE").desc(),
            ActiveEnforcementModel.expires_at.desc(),
        )

        return self.db.scalars(stmt).first()

    def list_active_rules(self) -> List[ActiveEnforcementModel]:
        """
        List all currently active and non-expired containment rules (ACTIVE and SIMULATED).
        """
        now = datetime.now(timezone.utc)
        stmt = (
            select(ActiveEnforcementModel)
            .where(
                ActiveEnforcementModel.status.in_(["ACTIVE", "SIMULATED"]),
                ActiveEnforcementModel.expires_at > now,
            )
            .order_by(ActiveEnforcementModel.expires_at.asc())
        )
        return list(self.db.scalars(stmt).all())

    def list_all_rules(
        self,
        limit: int = 50,
        offset: int = 0,
        status_filter: Optional[str] = None,
    ) -> Tuple[List[ActiveEnforcementModel], int]:
        """
        List containment rules with pagination and status filtering.
        Supports explicit status filter ('ACTIVE', 'SIMULATED', 'EXPIRED', 'REVOKED') or 'ALL' / None.
        """
        stmt = select(ActiveEnforcementModel)
        count_stmt = select(func.count(ActiveEnforcementModel.id))

        if status_filter and status_filter.strip().upper() != "ALL":
            filter_val = status_filter.strip().upper()
            stmt = stmt.where(ActiveEnforcementModel.status == filter_val)
            count_stmt = count_stmt.where(ActiveEnforcementModel.status == filter_val)

        total = self.db.scalar(count_stmt) or 0
        stmt = stmt.order_by(ActiveEnforcementModel.created_at.desc()).limit(limit).offset(offset)
        rules = list(self.db.scalars(stmt).all())
        return rules, total

    def extend_ttl(self, rule_id: str, extra_seconds: int) -> Optional[ActiveEnforcementModel]:
        """
        Refresh the expiration time of an existing active or simulated rule using sliding-window semantics.
        Never compounds TTL by adding onto previous expiry; slides from current evaluation time.
        Preserves an explicitly longer existing expiration date.
        """
        rule = self.get_by_id(rule_id)
        if not rule or rule.status not in ("ACTIVE", "SIMULATED"):
            return None

        now = datetime.now(timezone.utc)
        cur_exp = rule.expires_at
        if cur_exp.tzinfo is None:
            cur_exp = cur_exp.replace(tzinfo=timezone.utc)

        # If already expired, do not extend
        if cur_exp <= now:
            return None

        # Sliding window: refresh expiration relative to current evaluation timestamp
        sliding_expiry = now + timedelta(seconds=extra_seconds)

        # Do not shorten an explicitly longer expiry if a policy requires preservation
        if sliding_expiry > cur_exp:
            rule.expires_at = sliding_expiry

        rule.ttl_seconds = max(rule.ttl_seconds, extra_seconds)
        rule.updated_at = now
        self.db.flush()
        return rule

    def revoke_rule(self, rule_id: str, actor: str = "analyst") -> Optional[ActiveEnforcementModel]:
        """
        Manually revoke an active containment rule.
        """
        rule = self.get_by_id(rule_id)
        if not rule:
            return None

        now = datetime.now(timezone.utc)
        rule.status = "REVOKED"
        rule.revoked_at = now
        rule.revoked_by = actor
        rule.updated_at = now
        self.db.flush()
        return rule

    def prune_expired_rules(self) -> List[str]:
        """
        Find rules whose TTL has expired (both ACTIVE and SIMULATED) and mark them as EXPIRED in PostgreSQL.
        Returns the list of expired rule IDs.
        """
        now = datetime.now(timezone.utc)
        stmt = select(ActiveEnforcementModel).where(
            ActiveEnforcementModel.status.in_(["ACTIVE", "SIMULATED"]),
            ActiveEnforcementModel.expires_at <= now,
        )
        expired_rules = list(self.db.scalars(stmt).all())
        expired_ids = []

        for rule in expired_rules:
            rule.status = "EXPIRED"
            rule.updated_at = now
            expired_ids.append(rule.id)

        if expired_ids:
            self.db.flush()

        return expired_ids
