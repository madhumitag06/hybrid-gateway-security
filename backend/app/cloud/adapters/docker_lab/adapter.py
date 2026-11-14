"""
Docker Lab Adapter
Provider adapter for the containerized hybrid-cloud simulation lab.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

try:
    from backend.app.cloud.adapters.docker_lab.enforcement import DockerLabEnforcementProvider
    from backend.app.cloud.adapters.docker_lab.identity import DockerLabIdentityProvider
    from backend.app.cloud.adapters.docker_lab.telemetry import DockerLabTelemetryProvider
    from backend.app.cloud.interfaces.provider import BaseCloudProviderAdapter
    from backend.app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountStatusSchema,
        CloudCapabilitiesSchema,
    )
    from backend.app.cloud.schemas.cloud_resource import CloudResourceSchema
except ImportError:
    from app.cloud.adapters.docker_lab.enforcement import DockerLabEnforcementProvider
    from app.cloud.adapters.docker_lab.identity import DockerLabIdentityProvider
    from app.cloud.adapters.docker_lab.telemetry import DockerLabTelemetryProvider
    from app.cloud.interfaces.provider import BaseCloudProviderAdapter
    from app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountStatusSchema,
        CloudCapabilitiesSchema,
    )
    from app.cloud.schemas.cloud_resource import CloudResourceSchema


class DockerLabCloudAdapter(BaseCloudProviderAdapter):
    """Local Docker hybrid-cloud simulation lab adapter."""

    def __init__(self, config: CloudAccountConfigSchema):
        super().__init__(config)
        self.identity_provider = DockerLabIdentityProvider(lab_id=self.account_id)
        self.telemetry_provider = DockerLabTelemetryProvider(lab_id=self.account_id)
        self.enforcement_provider = DockerLabEnforcementProvider(
            lab_id=self.account_id,
            enabled=config.enforcement_enabled,
        )

    def validate_configuration(self) -> Tuple[bool, str]:
        return True, "Docker Lab local simulation is active"

    def check_connection(self) -> Dict[str, Any]:
        return {
            "provider": "DOCKER_LAB",
            "status": "CONNECTED",
            "message": "Docker Lab bridge connected",
            "latency_ms": 0.4,
            "caller_identity": self.identity_provider.get_caller_identity(),
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_capabilities(self) -> CloudCapabilitiesSchema:
        return CloudCapabilitiesSchema(
            read_inventory=True,
            read_flow_logs=True,
            read_telemetry_streaming=True,
            write_containment=True,
            write_firewall_rules=True,
            supports_oidc_federation=False,
            supports_workload_identity=False,
            supports_private_endpoints=True,
            supports_flow_logs_v2=True,
        )

    def list_network_resources(self) -> List[CloudResourceSchema]:
        now = datetime.now(timezone.utc)
        return [
            CloudResourceSchema(
                resource_id="net-onprem",
                account_id=self.account_id,
                provider="DOCKER_LAB",
                resource_type="SUBNET",
                name="simulated-onprem-subnet",
                cidr_block="10.10.10.0/24",
                region="local",
                state="ACTIVE",
                tags={"Zone": "ONPREM"},
                created_at=now,
            ),
            CloudResourceSchema(
                resource_id="net-cloud",
                account_id=self.account_id,
                provider="DOCKER_LAB",
                resource_type="SUBNET",
                name="simulated-cloud-subnet",
                cidr_block="10.20.10.0/24",
                region="local",
                state="ACTIVE",
                tags={"Zone": "CLOUD"},
                created_at=now,
            ),
            CloudResourceSchema(
                resource_id="hybrid-lab-router",
                account_id=self.account_id,
                provider="DOCKER_LAB",
                resource_type="GATEWAY",
                name="hybrid-lab-router",
                region="local",
                state="ACTIVE",
                tags={"IP": "10.30.10.2"},
                created_at=now,
            ),
        ]

    def get_health(self) -> Dict[str, Any]:
        return {
            "provider": "DOCKER_LAB",
            "healthy": True,
            "status": "CONNECTED",
            "region": "local",
            "account_id": self.account_id,
            "telemetry_ready": True,
            "enforcement_ready": True,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_identity_provider(self) -> DockerLabIdentityProvider:
        return self.identity_provider

    def get_telemetry_provider(self) -> DockerLabTelemetryProvider:
        return self.telemetry_provider

    def get_enforcement_provider(self) -> DockerLabEnforcementProvider:
        return self.enforcement_provider

