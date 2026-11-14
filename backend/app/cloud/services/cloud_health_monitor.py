"""
Cloud Health Monitor Service
============================
Aggregates health, latency, connectivity status, and capability matrix across all active cloud providers.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

try:
    from backend.app.cloud.schemas.cloud_account import CloudAccountConfigSchema
    from backend.app.cloud.services.cloud_connection_manager import CloudConnectionManager
    from backend.app.cloud.services.cloud_registry import CloudRegistry
    from backend.app.config import settings
except ImportError:
    from app.cloud.schemas.cloud_account import CloudAccountConfigSchema
    from app.cloud.services.cloud_connection_manager import CloudConnectionManager
    from app.cloud.services.cloud_registry import CloudRegistry
    from app.config import settings


class CloudHealthMonitor:
    """Multi-cloud health status aggregator."""

    @classmethod
    def get_provider_health_summary(cls, db: Optional[Session] = None) -> Dict[str, Any]:
        """
        Gathers health across AWS, GCP, Azure, and Docker Lab.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        providers_status: Dict[str, Any] = {}

        # 1. AWS
        aws_cfg = CloudAccountConfigSchema(
            account_id=getattr(settings, "aws_account_id", "aws-production-01") or "aws-production-01",
            provider="AWS",
            account_name="AWS Cloud Network",
            region=getattr(settings, "aws_region", "us-east-1") or "us-east-1",
            role_arn=getattr(settings, "aws_role_arn", None),
            enabled=getattr(settings, "aws_enabled", True),
            enforcement_enabled=False,
        )
        aws_adapter = CloudConnectionManager.create_adapter(aws_cfg)
        providers_status["AWS"] = aws_adapter.get_health()

        # 2. GCP
        gcp_cfg = CloudAccountConfigSchema(
            account_id=getattr(settings, "gcp_project_id", "gcp-builders-hub-prod") or "gcp-builders-hub-prod",
            provider="GCP",
            account_name="Google Cloud (Builders Hub)",
            project_id=getattr(settings, "gcp_project_id", "gcp-builders-hub-prod"),
            region=getattr(settings, "gcp_region", "us-central1") or "us-central1",
            enabled=getattr(settings, "gcp_enabled", True),
            enforcement_enabled=False,
        )
        gcp_adapter = CloudConnectionManager.create_adapter(gcp_cfg)
        providers_status["GCP"] = gcp_adapter.get_health()

        # 3. Azure
        az_cfg = CloudAccountConfigSchema(
            account_id=getattr(settings, "azure_subscription_id", "sub-azure-enterprise-prod") or "sub-azure-enterprise-prod",
            provider="AZURE",
            account_name="Microsoft Azure Network",
            subscription_id=getattr(settings, "azure_subscription_id", "sub-azure-enterprise-prod"),
            tenant_id=getattr(settings, "azure_tenant_id", "tenant-entra-id-01"),
            region=getattr(settings, "azure_region", "eastus") or "eastus",
            enabled=getattr(settings, "azure_enabled", True),
            enforcement_enabled=False,
        )
        az_adapter = CloudConnectionManager.create_adapter(az_cfg)
        providers_status["AZURE"] = az_adapter.get_health()

        # 4. Docker Lab
        lab_adapter = CloudConnectionManager.get_default_lab_adapter()
        providers_status["DOCKER_LAB"] = lab_adapter.get_health()

        # Overall health assessment
        all_healthy = all(p["healthy"] for p in providers_status.values())
        overall_status = "HEALTHY" if all_healthy else "DEGRADED"

        return {
            "overall_status": overall_status,
            "checked_at": now_iso,
            "providers": providers_status,
            "multi_cloud_ready": True,
        }

