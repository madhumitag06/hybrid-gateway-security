"""
Enforcement Adapter Interface & Result Models
=============================================
Defines the standard abstraction for containment execution adapters.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from backend.app.schemas.policy import ActiveEnforcementRule, PolicyDecision


@dataclass
class EnforcementResult:
    """
    Result returned by an EnforcementAdapter after executing a policy action.
    """
    success: bool
    rule_id: str
    target_ip: str
    target_port: Optional[int]
    action: str                        # "Allow", "Monitor", "Restrict", "Block"
    status: str                        # "ACTIVE", "SIMULATED", "FAILED", "REVOKED", "EXPIRED"
    mode: str                          # "DRY_RUN", "SANDBOX"
    message: str
    ttl_seconds: int
    expires_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class EnforcementAdapter(ABC):
    """
    Abstract contract for security gateway enforcement adapters.
    """

    @property
    @abstractmethod
    def mode_name(self) -> str:
        """Return mode name: 'DRY_RUN' or 'SANDBOX'."""
        pass

    @abstractmethod
    def enforce(self, decision: PolicyDecision, rule_id: str) -> EnforcementResult:
        """
        Execute containment for the given PolicyDecision.
        """
        pass

    @abstractmethod
    def revoke(self, rule_id: str, actor: str = "analyst") -> EnforcementResult:
        """
        Revoke an active containment rule.
        """
        pass

    @abstractmethod
    def list_active_rules(self) -> List[ActiveEnforcementRule]:
        """
        List all currently active in-memory containment rules.
        """
        pass

    @abstractmethod
    def prune_expired(self) -> List[str]:
        """
        Deactivate rules that have exceeded their TTL.
        """
        pass

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """
        Check adapter operational health and statistics.
        """
        pass
