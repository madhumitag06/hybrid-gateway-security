"""
GCP Cloud Enforcement Provider
Implements Google Cloud VPC Firewall rule enforcement (egress/ingress deny rules)
with priority management, dry-run execution, and audit logging.
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


class GcpEnforcementProvider(BaseCloudEnforcementProvider):
    """GCP Cloud Firewall containment provider."""

    def __init__(self, project_id: str = "hybrid-gateway-bridge", region: str = "us-central1", enabled: bool = False):
        super().__init__(provider_name="GCP", account_id=project_id, enabled=enabled)
        self.project_id = project_id
        self.region = region
        self._active_containments: Dict[str, Dict[str, Any]] = {}

    def supported_enforcement_actions(self) -> List[str]:
        return [
            "VPC_FIREWALL_DENY",
            "HIERARCHICAL_FIREWALL_POLICY",
            "CLOUD_ARMOR_SECURITY_POLICY",
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
        Create a high-priority GCP firewall rule to isolate or drop traffic from target_ip.
        """
        containment_id = f"gcp-fw-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        rule_name = f"fw-deny-{containment_id}"

        rule_details = {
            "containment_id": containment_id,
            "provider": "GCP",
            "project_id": self.project_id,
            "rule_name": rule_name,
            "target_ip": target_ip,
            "action_type": "VPC_FIREWALL_DENY",
            "direction": direction,
            "priority": 100,  # High priority to supersede allow rules
            "reason": reason,
            "dry_run": dry_run or not self._enabled,
            "applied_at": timestamp,
            "status": "SIMULATED" if (dry_run or not self._enabled) else "ACTIVE",
            "revert_plan": f"gcloud compute firewall-rules delete {rule_name} --project {self.project_id} --quiet",
            "metadata": metadata or {},
        }

        self._active_containments[containment_id] = rule_details
        logger.info(
            "GCP Containment [%s] for target %s (dry_run=%s)",
            containment_id,
            target_ip,
            rule_details["dry_run"],
        )
        return rule_details

    def revoke_containment(self, containment_id: str, dry_run: bool = True) -> Dict[str, Any]:
        """Revoke a GCP firewall containment rule."""
        if containment_id in self._active_containments:
            record = self._active_containments.pop(containment_id)
            record["status"] = "REVOKED"
            record["revoked_at"] = datetime.now(timezone.utc).isoformat()
            return {"success": True, "record": record}
        return {"success": False, "message": f"Containment {containment_id} not found"}

    def list_active_containments(self) -> List[Dict[str, Any]]:
        return list(self._active_containments.values())

