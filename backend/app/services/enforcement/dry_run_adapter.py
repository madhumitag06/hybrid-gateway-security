"""
Dry-Run Enforcement Adapter
===========================
Simulates policy enforcement decisions without altering environment or sandbox state.
Used as the safe default operating mode for the security gateway.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from backend.app.schemas.policy import ActiveEnforcementRule, PolicyDecision
from backend.app.services.enforcement.base import EnforcementAdapter, EnforcementResult


class DryRunAdapter(EnforcementAdapter):
    """
    Dry-run implementation calculating theoretical enforcement outcomes.
    """

    @property
    def mode_name(self) -> str:
        return "DRY_RUN"

    def enforce(self, decision: PolicyDecision, rule_id: str) -> EnforcementResult:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=decision.suggested_ttl_seconds)

        return EnforcementResult(
            success=True,
            rule_id=rule_id,
            target_ip=decision.target_ip,
            target_port=decision.target_port,
            action=decision.policy_action,
            status="SIMULATED",
            mode=self.mode_name,
            message=f"[DRY_RUN] Simulated policy action '{decision.policy_action}' calculated for {decision.target_ip}. No network state modified.",
            ttl_seconds=decision.suggested_ttl_seconds,
            expires_at=expires_at,
            metadata={"simulated": True, "dry_run": True},
        )

    def revoke(self, rule_id: str, actor: str = "analyst") -> EnforcementResult:
        now = datetime.now(timezone.utc)
        return EnforcementResult(
            success=True,
            rule_id=rule_id,
            target_ip="0.0.0.0",
            target_port=None,
            action="Allow",
            status="REVOKED",
            mode=self.mode_name,
            message=f"[DRY_RUN] Simulated rule '{rule_id}' marked as revoked.",
            ttl_seconds=0,
            expires_at=now,
            metadata={"revoked_by": actor},
        )

    def list_active_rules(self) -> List[ActiveEnforcementRule]:
        return []

    def prune_expired(self) -> List[str]:
        return []

    def health_check(self) -> Dict[str, Any]:
        return {
            "status": "HEALTHY",
            "mode": self.mode_name,
            "description": "Dry-run simulation mode active (Zero host state modifications).",
        }
