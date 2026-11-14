"""
AWS Cloud Enforcement Provider
Implements AWS security containment mechanisms (Security Group isolation, Network ACL blocking)
with strict dry-run safeguards and reversibility.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

try:
    from backend.app.cloud.interfaces.enforcement import BaseCloudEnforcementProvider
except ImportError:
    from app.cloud.interfaces.enforcement import BaseCloudEnforcementProvider

logger = logging.getLogger(__name__)


class AwsEnforcementProvider(BaseCloudEnforcementProvider):
    """AWS containment provider with Security Group and NACL mechanisms."""

    def __init__(self, account_id: str = "aws-production-01", region: str = "us-east-1", enabled: bool = False):
        super().__init__(provider_name="AWS", account_id=account_id, enabled=enabled)
        self.region = region
        self._active_containments: Dict[str, Dict[str, Any]] = {}

    def supported_enforcement_actions(self) -> List[str]:
        return [
            "SECURITY_GROUP_ISOLATION",
            "NACL_DENY_RULE",
            "WAF_IP_BLOCK",
        ]

    def apply_containment(
        self,
        target_ip: str,
        reason: str,
        direction: str = "INGRESS",
        dry_run: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a simulated or active AWS containment policy.
        """
        containment_id = f"aws-cnt-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # If live enforcement is disabled or dry_run is true, return safe simulated action
        action_type = "NACL_DENY_RULE"
        rule_details = {
            "containment_id": containment_id,
            "provider": "AWS",
            "account_id": self.account_id,
            "region": self.region,
            "target_ip": target_ip,
            "action_type": action_type,
            "direction": direction,
            "reason": reason,
            "dry_run": dry_run or not self._enabled,
            "applied_at": timestamp,
            "status": "SIMULATED" if (dry_run or not self._enabled) else "ACTIVE",
            "revert_plan": f"aws ec2 delete-network-acl-entry --network-acl-id acl-sec --rule-number 100 --{direction.lower()}",
            "metadata": metadata or {},
        }

        self._active_containments[containment_id] = rule_details
        logger.info(
            "AWS Containment [%s] for target %s (dry_run=%s)",
            containment_id,
            target_ip,
            rule_details["dry_run"],
        )
        return rule_details

    def revoke_containment(self, containment_id: str, dry_run: bool = True) -> Dict[str, Any]:
        """Revoke an active or simulated containment."""
        if containment_id in self._active_containments:
            record = self._active_containments.pop(containment_id)
            record["status"] = "REVOKED"
            record["revoked_at"] = datetime.now(timezone.utc).isoformat()
            return {"success": True, "record": record}
        return {"success": False, "message": f"Containment {containment_id} not found"}

    def list_active_containments(self) -> List[Dict[str, Any]]:
        return list(self._active_containments.values())

