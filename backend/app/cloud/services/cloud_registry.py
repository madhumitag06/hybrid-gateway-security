"""
Cloud Account & Resource Registry Service
=========================================
Provides non-secret persistence, discovery synchronization, and inventory query capabilities
backed by PostgreSQL (CloudAccountModel & CloudResourceModel).
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

try:
    from backend.app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountStatusSchema,
    )
    from backend.app.cloud.schemas.cloud_resource import (
        CloudInventorySummary,
        CloudResourceSchema,
    )
    from backend.app.models.cloud_account import CloudAccountModel, CloudResourceModel
except ImportError:
    from app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountStatusSchema,
    )
    from app.cloud.schemas.cloud_resource import (
        CloudInventorySummary,
        CloudResourceSchema,
    )
    from app.models.cloud_account import CloudAccountModel, CloudResourceModel

logger = logging.getLogger(__name__)


class CloudRegistry:
    """Registry service managing multi-cloud accounts and discovered network resources."""

    @classmethod
    def get_account(cls, db: Session, account_id: str) -> Optional[CloudAccountModel]:
        return db.query(CloudAccountModel).filter(CloudAccountModel.account_id == account_id).first()

    @classmethod
    def list_accounts(
        cls, db: Session, provider: Optional[str] = None
    ) -> List[CloudAccountModel]:
        query = db.query(CloudAccountModel)
        if provider:
            query = query.filter(CloudAccountModel.provider == provider.upper())
        return query.order_by(CloudAccountModel.provider, CloudAccountModel.display_name).all()

    @classmethod
    def upsert_account(
        cls,
        db: Session,
        config: CloudAccountConfigSchema,
        status: Optional[str] = None,
        error_message: Optional[str] = None,
        latency_ms: Optional[float] = None,
    ) -> CloudAccountModel:
        """
        Create or update a non-secret cloud account record.
        """
        account = cls.get_account(db, config.account_id)
        now = datetime.now(timezone.utc)
        display_name = config.display_name or config.account_name or config.account_id

        # Build non-secret config metadata
        safe_meta = {
            "role_arn": config.role_arn,
            "oidc_role_arn": config.oidc_role_arn,
            "project_id": config.project_id,
            "workload_identity_provider": config.workload_identity_provider,
            "subscription_id": config.subscription_id,
            "tenant_id": config.tenant_id,
            "client_id": config.client_id,
            "latency_ms": latency_ms,
            "enforcement_enabled": config.enforcement_enabled,
            "metadata": config.metadata,
        }

        caps_dict = config.capabilities.model_dump() if hasattr(config.capabilities, "model_dump") else {}

        if account is None:
            account = CloudAccountModel(
                id=config.account_id,
                account_id=config.account_id,
                provider=config.provider,
                display_name=display_name,
                region=config.region,
                status=status or "CONFIGURED",
                enabled=config.enabled,
                capabilities=caps_dict,
                last_error=error_message,
                last_connection_check=now,
                metadata_json=safe_meta,
            )
            db.add(account)
        else:
            account.display_name = display_name
            account.provider = config.provider
            account.region = config.region
            account.enabled = config.enabled
            account.capabilities = caps_dict
            account.metadata_json = safe_meta
            if status is not None:
                account.status = status
            account.last_error = error_message
            account.last_connection_check = now

        db.commit()
        db.refresh(account)
        return account

    @classmethod
    def update_account_status(
        cls,
        db: Session,
        account_id: str,
        status: str,
        latency_ms: Optional[float] = None,
        error_message: Optional[str] = None,
    ) -> Optional[CloudAccountModel]:
        account = cls.get_account(db, account_id)
        if not account:
            return None

        account.status = status
        account.last_connection_check = datetime.now(timezone.utc)
        if latency_ms is not None:
            meta = dict(account.metadata_json or {})
            meta["latency_ms"] = latency_ms
            account.metadata_json = meta
        account.last_error = error_message
        db.commit()
        db.refresh(account)
        return account

    @classmethod
    def sync_resources(
        cls,
        db: Session,
        account_id: str,
        resources: List[CloudResourceSchema],
    ) -> int:
        """
        Synchronize discovered resources for a specific cloud account.
        """
        account = cls.get_account(db, account_id)
        if not account:
            prov = resources[0].provider if resources else "AWS"
            reg = resources[0].region if resources else "us-east-1"
            account = CloudAccountModel(
                id=account_id,
                account_id=account_id,
                provider=prov,
                display_name=account_id,
                region=reg,
                status="CONNECTED",
                enabled=True,
                metadata_json={},
            )
            db.add(account)
            db.commit()
            db.refresh(account)

        now = datetime.now(timezone.utc)
        synced_count = 0

        for r in resources:
            composite_id = f"{account.id}-{r.resource_id}"
            existing = (
                db.query(CloudResourceModel)
                .filter(CloudResourceModel.id == composite_id)
                .first()
            )

            res_name = r.name or r.resource_name or r.resource_id
            parent_id = r.vpc_id or r.parent_resource_id
            meta = r.metadata or r.extra_data or {}

            if existing is None:
                new_res = CloudResourceModel(
                    id=composite_id,
                    cloud_account_id=account.id,
                    provider=r.provider,
                    resource_type=r.resource_type,
                    resource_id=r.resource_id,
                    resource_name=res_name,
                    region=r.region,
                    cidr_block=r.cidr_block,
                    parent_resource_id=parent_id,
                    metadata_json=meta,
                    discovered_at=r.created_at or now,
                )
                db.add(new_res)
            else:
                existing.resource_name = res_name
                existing.cidr_block = r.cidr_block
                existing.region = r.region
                existing.parent_resource_id = parent_id
                existing.metadata_json = meta
                existing.discovered_at = now

            synced_count += 1

        db.commit()
        return synced_count

    @classmethod
    def list_resources(
        cls,
        db: Session,
        provider: Optional[str] = None,
        account_id: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> List[CloudResourceModel]:
        query = db.query(CloudResourceModel)
        if provider:
            query = query.filter(CloudResourceModel.provider == provider.upper())
        if account_id:
            query = query.filter(CloudResourceModel.cloud_account_id == account_id)
        if resource_type:
            query = query.filter(CloudResourceModel.resource_type == resource_type.upper())
        return query.order_by(CloudResourceModel.provider, CloudResourceModel.resource_type).all()

    @classmethod
    def get_inventory_summary(cls, db: Session) -> CloudInventorySummary:
        resources = db.query(CloudResourceModel).all()
        # Ensure connected AWS resources are represented if not yet synchronized
        if not any(r.provider == "AWS" for r in resources):
            try:
                try:
                    from backend.app.cloud.services.cloud_connection_manager import CloudConnectionManager
                except ImportError:
                    from app.cloud.services.cloud_connection_manager import CloudConnectionManager
                aws_adapter = CloudConnectionManager.get_or_create_aws_adapter()
                live_res = aws_adapter.list_network_resources()
                if live_res:
                    cls.sync_resources(db, aws_adapter.account_id, live_res)
                    resources = db.query(CloudResourceModel).all()
            except Exception as e:
                logger.debug("AWS inventory summary sync omitted: %s", e)

        vpc_count = sum(1 for r in resources if r.resource_type in ("VPC", "VNET"))
        subnet_count = sum(1 for r in resources if r.resource_type == "SUBNET")
        sg_count = sum(1 for r in resources if r.resource_type in ("SECURITY_GROUP", "FIREWALL_POLICY", "NSG"))
        gw_count = sum(1 for r in resources if r.resource_type in ("GATEWAY", "INTERNET_GATEWAY", "NAT_GATEWAY"))
        fw_count = sum(1 for r in resources if r.resource_type in ("FIREWALL_RULE", "NETWORK_ACL"))
        if_count = sum(1 for r in resources if r.resource_type in ("NETWORK_INTERFACE", "FLOW_LOG_SUBSCRIPTION"))

        by_provider: Dict[str, int] = {}
        for r in resources:
            by_provider[r.provider] = by_provider.get(r.provider, 0) + 1

        return CloudInventorySummary(
            total_resources=len(resources),
            total_vpcs=vpc_count,
            vpcs_count=vpc_count,
            total_subnets=subnet_count,
            subnets_count=subnet_count,
            total_security_groups=sg_count,
            security_groups_count=sg_count,
            total_gateways=gw_count,
            gateways_count=gw_count,
            firewall_rules_count=fw_count,
            interfaces_count=if_count,
            by_provider=by_provider,
        )
