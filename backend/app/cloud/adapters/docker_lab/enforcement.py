"""
Docker Lab Enforcement Provider
Bridges containerized hybrid-cloud containment to local iptables and route null-routing.
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


class DockerLabEnforcementProvider(BaseCloudEnforcementProvider):
    """Docker Lab network containment provider."""

    def __init__(self, lab_id: str = "docker-hybrid-lab-01", enabled: bool = True):
        super().__init__(provider_name="DOCKER_LAB", account_id=lab_id, enabled=enabled)
        self._active_containments: Dict[str, Dict[str, Any]] = {}

    def supported_enforcement_actions(self) -> List[str]:
        return [
            "IPTABLES_DROP",
            "ROUTE_BLACKHOLE",
            "CONTAINER_ISOLATION",
        ]

    def apply_containment(
        self,
        target_ip: str,
        reason: str,
        direction: str = "INGRESS",
        dry_run: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        containment_id = f"lab-cnt-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        rule_details = {
            "containment_id": containment_id,
            "provider": "DOCKER_LAB",
            "target_ip": target_ip,
            "action_type": "IPTABLES_DROP",
            "direction": direction,
            "reason": reason,
            "dry_run": dry_run,
            "applied_at": timestamp,
            "status": "SIMULATED" if dry_run else "ACTIVE",
            "revert_plan": f"iptables -D FORWARD -s {target_ip} -j DROP",
            "metadata": metadata or {},
        }
        self._active_containments[containment_id] = rule_details
        return rule_details

    def revoke_containment(self, containment_id: str, dry_run: bool = False) -> Dict[str, Any]:
        if containment_id in self._active_containments:
            record = self._active_containments.pop(containment_id)
            record["status"] = "REVOKED"
            record["revoked_at"] = datetime.now(timezone.utc).isoformat()
            return {"success": True, "record": record}
        return {"success": False, "message": f"Containment {containment_id} not found"}

    def list_active_containments(self) -> List[Dict[str, Any]]:
        return list(self._active_containments.values())

