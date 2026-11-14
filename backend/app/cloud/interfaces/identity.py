"""
Cloud Provider Abstraction - Identity Provider Interface.
Defines the contract for cloud authentication, IAM validation, STS/OIDC federation, and caller identity.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple


class BaseCloudIdentityProvider(ABC):
    """Abstract base class for cloud identity, IAM verification, and OIDC federation."""

    def __init__(self, provider_name: str, account_id: str):
        self.provider_name = provider_name
        self.account_id = account_id

    @abstractmethod
    def validate_credentials(self) -> Tuple[bool, str]:
        """
        Validate whether configured credentials or workload identity tokens are syntactically valid and active.
        """
        pass

    @abstractmethod
    def get_caller_identity(self) -> Dict[str, Any]:
        """
        Verify credentials by querying the cloud identity service (e.g. AWS STS GetCallerIdentity, GCP Token Info, Azure Graph).
        """
        pass

    @abstractmethod
    def get_federation_metadata(self) -> Dict[str, Any]:
        """
        Return federation metadata (OIDC issuer, audience, role ARN, service account) without exposing secrets.
        """
        pass

