"""
Cloud Provider Abstraction - Enforcement Provider Interface.
Defines the contract for cloud-level security containment (Security Groups, Firewalls, NSGs).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseCloudEnforcementProvider(ABC):
    """Abstract base class for cloud containment and dynamic firewall enforcement."""

    def __init__(self, provider_name: str, account_id: str, enabled: bool = False):
        self.provider_name = provider_name
        self.account_id = account_id
        self._enabled = enabled

    @abstractmethod
    def supported_enforcement_actions(self) -> List[str]:
        """
        List supported containment mechanisms (e.g., 'security_group_isolation', 'nacl_block', 'firewall_rule').
        """
        pass

    def is_enforcement_enabled(self) -> bool:
        """Check if active cloud enforcement is allowed (default to safe dry-run if false)."""
        return self._enabled

    @abstractmethod
    def apply_containment(
        self,
        target_ip: str,
        reason: str,
        direction: str = "INGRESS",
        dry_run: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Apply network containment on a malicious IP or resource.
        """
        pass

    @abstractmethod
    def revoke_containment(
        self, containment_id: str, dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Roll back or revoke an existing cloud containment rule.
        """
        pass

    @abstractmethod
    def list_active_containments(self) -> List[Dict[str, Any]]:
        """
        List all currently active containment policies placed by the gateway in this cloud.
        """
        pass

