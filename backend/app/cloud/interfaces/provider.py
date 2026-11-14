"""
Cloud Provider Abstraction - Base Cloud Provider Adapter Interface.
Defines the uniform contract that all cloud provider adapters (AWS, GCP, Azure, DockerLab) must implement.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

try:
    from backend.app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountStatusSchema,
        CloudCapabilitiesSchema,
    )
    from backend.app.cloud.schemas.cloud_resource import CloudResourceSchema
except ImportError:
    from app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountStatusSchema,
        CloudCapabilitiesSchema,
    )
    from app.cloud.schemas.cloud_resource import CloudResourceSchema


class BaseCloudProviderAdapter(ABC):
    """Abstract base class for all cloud provider adapters."""

    def __init__(self, config: CloudAccountConfigSchema):
        self.config = config
        self.provider = config.provider
        self.account_id = config.account_id
        self.account_name = config.account_name
        self.region = config.region

    @abstractmethod
    def validate_configuration(self) -> Tuple[bool, str]:
        """
        Validate provider configuration parameters without making external network calls.
        Returns (is_valid, validation_message).
        """
        pass

    @abstractmethod
    def check_connection(self) -> Dict[str, Any]:
        """
        Test provider connectivity, credentials, and API access.
        Returns status dictionary compatible with CloudAccountStatusSchema.
        """
        pass

    @abstractmethod
    def get_capabilities(self) -> CloudCapabilitiesSchema:
        """
        Return the provider's feature matrix and capabilities.
        """
        pass

    @abstractmethod
    def list_network_resources(self) -> List[CloudResourceSchema]:
        """
        Discover and list VPCs, subnets, gateways, and security groups.
        """
        pass

    @abstractmethod
    def get_health(self) -> Dict[str, Any]:
        """
        Perform a live health probe of the adapter and underlying cloud services.
        """
        pass

    @abstractmethod
    def get_identity_provider(self):
        """Return the identity and credential provider for this adapter."""
        pass

    @abstractmethod
    def get_telemetry_provider(self):
        """Return the flow log and telemetry provider for this adapter."""
        pass

    @abstractmethod
    def get_enforcement_provider(self):
        """Return the firewall and containment enforcement provider for this adapter."""
        pass
