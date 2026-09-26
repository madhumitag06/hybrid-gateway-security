"""
Enforcement Service Orchestrator
================================
Coordinates active containment adapters, rule deduplication, TTL pruning,
PostgreSQL persistence, and restart reconciliation.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
import uuid
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.active_enforcement import ActiveEnforcementModel
from backend.app.repositories.enforcement_repo import EnforcementRepository
from backend.app.repositories.policy_audit_repo import PolicyAuditRepository
from backend.app.schemas.policy import ActiveEnforcementRule, PolicyDecision
from backend.app.services.enforcement.base import EnforcementAdapter, EnforcementResult
from backend.app.services.enforcement.dry_run_adapter import DryRunAdapter
from backend.app.services.enforcement.sandbox_adapter import SandboxAdapter


class EnforcementService:
    _dry_run_adapter: DryRunAdapter = DryRunAdapter()
    _sandbox_adapter: SandboxAdapter = SandboxAdapter()
    _active_mode: str = settings.default_enforcement_mode  # "DRY_RUN" (default) or "SANDBOX"

    @classmethod
    def get_mode(cls) -> str:
        return cls._active_mode

    @classmethod
    def set_mode(cls, mode: str) -> None:
        mode_upper = mode.upper()
        if mode_upper not in ["DRY_RUN", "SANDBOX"]:
            raise ValueError(f"Invalid enforcement mode '{mode}'. Allowed: ['DRY_RUN', 'SANDBOX']")
        cls._active_mode = mode_upper

    @classmethod
    def get_adapter(cls) -> EnforcementAdapter:
        if cls._active_mode == "SANDBOX":
            return cls._sandbox_adapter
        return cls._dry_run_adapter

    @classmethod
    def get_sandbox_adapter(cls) -> SandboxAdapter:
        return cls._sandbox_adapter

    @classmethod
    def execute_decision(
        cls,
        decision: PolicyDecision,
        db: Session,
        actor: str = "ml_policy_engine",
    ) -> Tuple[EnforcementResult, Optional[ActiveEnforcementModel]]:
        """
        Execute a policy decision through the active adapter and persist the resulting rule & audit trail.
        """
        repo = EnforcementRepository(db)
        audit_repo = PolicyAuditRepository(db)

        # 1. Prune any expired rules before evaluating new actions
        repo.prune_expired_rules()
        cls.get_adapter().prune_expired()

        if not decision.enforcement_required or decision.policy_action == "Allow":
            # No containment rule creation required for Allow
            now = datetime.now(timezone.utc)
            result = EnforcementResult(
                success=True,
                rule_id="no-rule",
                target_ip=decision.target_ip,
                target_port=decision.target_port,
                action="Allow",
                status="ACTIVE" if cls._active_mode == "SANDBOX" else "SIMULATED",
                mode=cls._active_mode,
                message="Traffic allowed; no containment rule created.",
                ttl_seconds=0,
                expires_at=now,
            )
            return result, None

        # 2. Check Rule Deduplication for Target IP
        existing_rule = repo.find_active_by_target(
            target_ip=decision.target_ip, target_port=decision.target_port
        )

        adapter = cls.get_adapter()

        if existing_rule:
            # Rule already exists: extend TTL rather than creating duplicate
            extra_seconds = decision.suggested_ttl_seconds
            updated_rule = repo.extend_ttl(existing_rule.id, extra_seconds)

            # If action escalated (e.g. Restrict -> Block), update action
            if decision.policy_action == "Block" and existing_rule.action != "Block":
                existing_rule.action = "Block"
                existing_rule.reason = decision.reason
                db.flush()

            # Update in adapter
            enforce_res = adapter.enforce(decision, existing_rule.id)

            # Audit log entry for TTL extension / modification
            if decision.event_id:
                audit_repo.log_action(
                    event_id=decision.event_id,
                    requested_action=decision.policy_action,
                    previous_action=existing_rule.action,
                    resulting_status="Applied" if cls._active_mode == "SANDBOX" else "Monitoring",
                    actor=actor,
                )

            return enforce_res, updated_rule

        # 3. Create New Active Containment Rule
        rule_id = f"rule-{uuid.uuid4().hex[:8]}"
        enforce_res = adapter.enforce(decision, rule_id)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=decision.suggested_ttl_seconds)

        rule_model = ActiveEnforcementModel(
            id=rule_id,
            event_id=decision.event_id,
            target_ip=decision.target_ip,
            target_port=decision.target_port,
            protocol=decision.protocol or "ANY",
            action=decision.policy_action,
            status=enforce_res.status,
            mode=cls._active_mode,
            reason=decision.reason,
            ttl_seconds=decision.suggested_ttl_seconds,
            expires_at=expires_at,
        )

        repo.create(rule_model)

        # 4. Log to immutable policy audit trail
        if decision.event_id:
            audit_repo.log_action(
                event_id=decision.event_id,
                requested_action=decision.policy_action,
                previous_action=None,
                resulting_status="Applied" if cls._active_mode == "SANDBOX" else "Monitoring",
                actor=actor,
            )

        return enforce_res, rule_model

    @classmethod
    def revoke_rule(
        cls, rule_id: str, db: Session, actor: str = "analyst"
    ) -> Tuple[bool, str]:
        """
        Revoke an active containment rule in both the active adapter and PostgreSQL.
        """
        repo = EnforcementRepository(db)
        audit_repo = PolicyAuditRepository(db)

        rule_model = repo.revoke_rule(rule_id, actor=actor)
        if not rule_model:
            return False, f"Rule '{rule_id}' not found in database."

        # Revoke in adapter
        cls.get_adapter().revoke(rule_id, actor=actor)

        if rule_model.event_id:
            audit_repo.log_action(
                event_id=rule_model.event_id,
                requested_action="Allow",
                previous_action=rule_model.action,
                resulting_status="Allowed",
                actor=actor,
            )

        return True, f"Rule '{rule_id}' for {rule_model.target_ip} revoked successfully."

    @classmethod
    def reconcile_from_db(cls, db: Session) -> int:
        """
        Restores active, non-expired containment rules from PostgreSQL into the in-memory sandbox on startup.
        """
        repo = EnforcementRepository(db)
        repo.prune_expired_rules()
        active_db_rules = repo.list_active_rules()

        sandbox = cls._sandbox_adapter
        reconciled = 0

        for r in active_db_rules:
            decision = PolicyDecision(
                decision_id=f"reconciled-{r.id}",
                event_id=r.event_id,
                target_ip=r.target_ip,
                target_port=r.target_port,
                protocol=r.protocol,
                policy_action=r.action,  # type: ignore
                enforcement_required=True,
                confidence=1.0,
                threat_level="HIGH" if r.action == "Block" else "MEDIUM",
                attack_type="PERSISTED_RULE",
                risk_score=80 if r.action == "Block" else 50,
                rule_name="RECONCILED_STARTUP_RULE",
                reason=r.reason,
                suggested_ttl_seconds=max(int((r.expires_at - datetime.now(timezone.utc)).total_seconds()), 10),
            )
            sandbox.enforce(decision, r.id)
            reconciled += 1

        print(f"[+] Reconciled {reconciled} active containment rules from PostgreSQL into Sandbox adapter.")
        return reconciled
