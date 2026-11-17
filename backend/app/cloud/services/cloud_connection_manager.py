"""
Cloud Connection Manager Service
================================
Manages adapter lifecycle, adapter instantiation, health probes, and connection testing
across AWS, GCP, Azure, and Docker Lab.
"""

from datetime import datetime, timezone
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from backend.app.cloud.adapters.aws.adapter import AwsCloudAdapter
    from backend.app.cloud.adapters.azure.adapter import AzureCloudAdapter
    from backend.app.cloud.adapters.docker_lab.adapter import DockerLabCloudAdapter
    from backend.app.cloud.adapters.gcp.adapter import GcpCloudAdapter
    from backend.app.cloud.interfaces.provider import BaseCloudProviderAdapter
    from backend.app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountStatusSchema,
        CloudCapabilitiesSchema,
    )
    from backend.app.config import settings
except ImportError:
    from app.cloud.adapters.aws.adapter import AwsCloudAdapter
    from app.cloud.adapters.azure.adapter import AzureCloudAdapter
    from app.cloud.adapters.docker_lab.adapter import DockerLabCloudAdapter
    from app.cloud.adapters.gcp.adapter import GcpCloudAdapter
    from app.cloud.interfaces.provider import BaseCloudProviderAdapter
    from app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountStatusSchema,
        CloudCapabilitiesSchema,
    )
    from app.config import settings

logger = logging.getLogger(__name__)


class CloudConnectionManager:
    """
    Central connection and adapter factory for multi-cloud integrations.
    """

    _adapters: Dict[str, BaseCloudProviderAdapter] = {}

    ADAPTER_CLASSES = {
        "AWS": AwsCloudAdapter,
        "GCP": GcpCloudAdapter,
        "AZURE": AzureCloudAdapter,
        "DOCKER_LAB": DockerLabCloudAdapter,
    }

    @classmethod
    def create_adapter(cls, config: CloudAccountConfigSchema) -> BaseCloudProviderAdapter:
        provider = config.provider.upper()
        adapter_cls = cls.ADAPTER_CLASSES.get(provider)
        if not adapter_cls:
            raise ValueError(f"Unsupported cloud provider: '{config.provider}'")

        adapter = adapter_cls(config)
        cls._adapters[config.account_id] = adapter
        return adapter

    @classmethod
    def get_adapter(cls, account_id: str) -> Optional[BaseCloudProviderAdapter]:
        return cls._adapters.get(account_id)

    @classmethod
    def test_connection(cls, config: CloudAccountConfigSchema) -> Dict[str, Any]:
        """
        Safely test configuration and connectivity without modifying resources.
        """
        adapter = cls.create_adapter(config)
        return adapter.check_connection()

    @classmethod
    def get_or_create_aws_adapter(
        cls,
        role_arn: Optional[str] = None,
        region: Optional[str] = None,
        profile_name: Optional[str] = None,
        account_id: Optional[str] = None,
    ) -> AwsCloudAdapter:
        """Returns or instantiates the authoritative AWS adapter using environment or explicit configuration."""
        aws_id = account_id or os.environ.get("AWS_ACCOUNT_ID") or "698766075180"
        if aws_id in cls._adapters and isinstance(cls._adapters[aws_id], AwsCloudAdapter):
            return cls._adapters[aws_id]  # type: ignore

        resolved_region = (
            region
            or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or "ap-southeast-2"
        )
        resolved_role_arn = (
            role_arn
            or os.environ.get("AWS_ROLE_ARN")
            or "arn:aws:iam::698766075180:role/SecurityGatewayReadOnlyRole"
        )
        resolved_ext_id = (
            os.environ.get("AWS_EXTERNAL_ID")
            or "AdaptiveGatewayAuth"
        )
        resolved_profile = (
            profile_name
            or os.environ.get("AWS_PROFILE")
            or "security-gateway-readonly"
        )

        cfg = CloudAccountConfigSchema(
            account_id=aws_id,
            provider="AWS",
            account_name="AWS Primary Account",
            display_name=f"AWS Production ({aws_id})",
            region=resolved_region,
            role_arn=resolved_role_arn,
            external_id=resolved_ext_id,
            profile_name=resolved_profile,
            enabled=True,
            enforcement_enabled=False,
            metadata={"profile_name": resolved_profile},
        )
        return cls.create_adapter(cfg)  # type: ignore

    @classmethod
    def get_or_create_gcp_adapter(
        cls,
        project_id: Optional[str] = None,
        region: Optional[str] = None,
        account_id: Optional[str] = None,
    ) -> GcpCloudAdapter:
        """Returns or instantiates the authoritative GCP adapter using environment or explicit configuration."""
        proj_id = (
            account_id
            or project_id
            or os.environ.get("GCP_PROJECT_ID")
            or getattr(settings, "gcp_project_id", "hybrid-gateway-bridge")
            or "hybrid-gateway-bridge"
        )
        if proj_id in cls._adapters and isinstance(cls._adapters[proj_id], GcpCloudAdapter):
            return cls._adapters[proj_id]  # type: ignore

        resolved_region = (
            region
            or os.environ.get("GCP_REGION")
            or getattr(settings, "gcp_region", "us-central1")
            or "us-central1"
        )
        resolved_proj_num = (
            os.environ.get("GCP_PROJECT_NUMBER")
            or getattr(settings, "gcp_project_number", "77380112089")
            or "77380112089"
        )
        resolved_pool = (
            os.environ.get("GCP_WORKLOAD_IDENTITY_POOL")
            or getattr(settings, "gcp_workload_identity_pool", "hybrid-gateway-pool")
            or "hybrid-gateway-pool"
        )
        resolved_provider = (
            os.environ.get("GCP_WORKLOAD_IDENTITY_PROVIDER")
            or getattr(
                settings,
                "gcp_workload_identity_provider",
                "projects/77380112089/locations/global/workloadIdentityPools/hybrid-gateway-pool/providers/aws-hybrid-gateway",
            )
        )
        resolved_sa = (
            os.environ.get("GCP_SERVICE_ACCOUNT")
            or os.environ.get("GCP_SERVICE_ACCOUNT_EMAIL")
            or getattr(
                settings,
                "gcp_service_account_email",
                "hybrid-gateway-security@hybrid-gateway-bridge.iam.gserviceaccount.com",
            )
        )
        cred_path = (
            os.environ.get("GCP_SERVICE_ACCOUNT_JSON_PATH")
            or getattr(settings, "gcp_service_account_json_path", None)
            or str(Path.home() / ".config" / "hybrid-gateway" / "gcp-wif-credentials.json")
        )

        cfg = CloudAccountConfigSchema(
            account_id=proj_id,
            provider="GCP",
            account_name="Google Cloud Platform (hybrid-gateway-bridge)",
            display_name=f"Google Cloud Platform ({proj_id})",
            project_id=proj_id,
            region=resolved_region,
            workload_identity_pool=resolved_pool,
            workload_identity_provider=resolved_provider,
            service_account_email=resolved_sa,
            enabled=getattr(settings, "gcp_enabled", True),
            enforcement_enabled=False,
            metadata={
                "project_number": resolved_proj_num,
                "workload_identity_pool": resolved_pool,
                "workload_identity_provider": resolved_provider,
                "service_account_email": resolved_sa,
                "credential_path": cred_path,
                "auth_mode": "workload_identity",
            },
        )
        return cls.create_adapter(cfg)  # type: ignore

    @classmethod
    def get_default_lab_adapter(cls) -> DockerLabCloudAdapter:
        """Returns the default Docker simulated hybrid lab adapter."""
        lab_id = "docker-hybrid-lab-01"
        if lab_id not in cls._adapters:
            cfg = CloudAccountConfigSchema(
                account_id=lab_id,
                provider="DOCKER_LAB",
                account_name="Simulated Hybrid Docker Lab",
                region="local",
                enabled=True,
                enforcement_enabled=True,
            )
            cls.create_adapter(cfg)
        return cls._adapters[lab_id]  # type: ignore

