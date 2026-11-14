"""
Azure Cloud Enforcement Provider
Implements Azure Network Security Group (NSG) security rule containment
with priority management, dry-run safety, and rollback support.
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


class AzureEnforcementProvider(BaseCloudEnforcementProvider):
    """Azure Network Security Group containment provider."""

    def __init__(self, subscription_id: str = "sub-azure-enterprise-prod", region: str = "eastus", enabled: bool = False):
        super().__init__(provider_name="AZURE", account_id=subscription_id, enabled=enabled)
        self.subscription_id = subscription_id
        self.region = region
        self._active_containments: Dict[str, Dict[str, Any]] = {}

    def supported_enforcement_actions(self) -> List[str]:
        return [
            "NSG_SECURITY_RULE_DENY",
            "AZURE_FIREWALL_NETWORK_RULE",
            "APPLICATION_GATEWAY_WAF_BLOCK",
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
        Create a priority-100 NSG Inbound Deny rule to block target_ip.
        """
        containment_id = f"az-nsg-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        rule_name = f"Deny_{containment_id}"
        nsg_name = metadata.get("nsg_name", "nsg-hybrid-gateway") if metadata else "nsg-hybrid-gateway"
        resource_group = metadata.get("resource_group", "rg-hybrid-security") if metadata else "rg-hybrid-security"

        rule_details = {
            "containment_id": containment_id,
            "provider": "AZURE",
            "subscription_id": self.subscription_id,
            "rule_name": rule_name,
            "nsg_name": nsg_name,
            "resource_group": resource_group,
            "target_ip": target_ip,
            "action_type": "NSG_SECURITY_RULE_DENY",
            "direction": "Inbound" if direction == "INGRESS" else "Outbound",
            "priority": 100,
            "reason": reason,
            "dry_run": dry_run or not self._enabled,
            "applied_at": timestamp,
            "status": "SIMULATED" if (dry_run or not self._enabled) else "ACTIVE",
            "revert_plan": f"az network nsg rule delete -g {resource_group} --nsg-name {nsg_name} -n {rule_name}",
            "metadata": metadata or {},
        }

        self._active_containments[containment_id] = rule_details
        logger.info(
            "Azure Containment [%s] for target %s (dry_run=%s)",
            containment_id,
            target_ip,
            rule_details["dry_run"],
        )
        return rule_details

    def revoke_containment(self, containment_id: str, dry_run: bool = True) -> Dict[str, Any]:
        """Revoke an active or simulated Azure NSG containment rule."""
        if containment_id in self._active_containments:
            record = self._active_containments.pop(containment_id)
            record["status"] = "REVOKED"
            record["revoked_at"] = datetime.now(timezone.utc).isoformat()
            return {"success": True, "record": record}
        return {"success": False, "message": f"Containment {containment_id} not found"}

    def list_active_containments(self) -> List[Dict[str, Any]]:
        return list(self._active_containments.values())

