"""
Docker Lab Identity Provider
Handles identity and authentication for local simulated hybrid Docker lab environment.
"""

from typing import Any, Dict, Optional, Tuple

try:
    from backend.app.cloud.interfaces.identity import BaseCloudIdentityProvider
except ImportError:
    from app.cloud.interfaces.identity import BaseCloudIdentityProvider


class DockerLabIdentityProvider(BaseCloudIdentityProvider):
    """Identity provider for local containerized hybrid-cloud lab."""

    def __init__(self, lab_id: str = "docker-hybrid-lab-01"):
        super().__init__(provider_name="DOCKER_LAB", account_id=lab_id)

    def validate_credentials(self) -> Tuple[bool, str]:
        return True, "Docker Lab local credentials always valid"

    def get_caller_identity(self) -> Dict[str, Any]:
        return {
            "lab_id": self.account_id,
            "router_endpoint": "http://10.30.10.2:8099",
            "environment": "SIMULATED_DOCKER_HYBRID_LAB",
            "status": "VERIFIED",
            "auth_method": "LOCAL_CONTAINER_SOCKET",
        }

    def get_federation_metadata(self) -> Dict[str, Any]:
        return {
            "mode": "LOCAL_SIMULATION",
            "federation_supported": False,
        }

