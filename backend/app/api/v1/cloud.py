"""
Multi-Cloud Management & Telemetry Ingestion Router
===================================================
Provides endpoints for multi-cloud provider accounts, health diagnostics,
network resource discovery, and canonical telemetry normalization.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

try:
    from backend.app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountCreateRequest,
        CloudAccountStatusSchema,
        CloudCapabilitiesSchema,
    )
    from backend.app.cloud.schemas.cloud_resource import (
        CloudInventorySummary,
        CloudResourceSchema,
    )
    from backend.app.cloud.schemas.cloud_telemetry import (
        CanonicalFlowRecord,
        CloudTelemetryBatchRequest,
        CloudTelemetryBatchResponse,
    )
    from backend.app.cloud.services.cloud_connection_manager import CloudConnectionManager
    from backend.app.cloud.services.cloud_health_monitor import CloudHealthMonitor
    from backend.app.cloud.services.cloud_registry import CloudRegistry
    from backend.app.cloud.services.telemetry_normalizer import TelemetryNormalizer
    from backend.app.db.session import get_db
except ImportError:
    from app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountCreateRequest,
        CloudAccountStatusSchema,
        CloudCapabilitiesSchema,
    )
    from app.cloud.schemas.cloud_resource import (
        CloudInventorySummary,
        CloudResourceSchema,
    )
    from app.cloud.schemas.cloud_telemetry import (
        CanonicalFlowRecord,
        CloudTelemetryBatchRequest,
        CloudTelemetryBatchResponse,
    )
    from app.cloud.services.cloud_connection_manager import CloudConnectionManager
    from app.cloud.services.cloud_health_monitor import CloudHealthMonitor
    from app.cloud.services.cloud_registry import CloudRegistry
    from app.cloud.services.telemetry_normalizer import TelemetryNormalizer
    from app.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cloud", tags=["Multi-Cloud Architecture"])


@router.get("/providers", response_model=Dict[str, Any])
def list_supported_providers():
    """
    List supported cloud providers and their static capability matrix.
    """
    return {
        "providers": [
            {
                "id": "AWS",
                "name": "Amazon Web Services",
                "auth_methods": ["STS_ASSUME_ROLE", "OIDC_WEB_IDENTITY", "IAM_USER"],
                "telemetry_types": ["VPC_FLOW_LOGS_V2", "CLOUDWATCH_LOGS", "S3"],
                "enforcement_mechanisms": ["SECURITY_GROUP_ISOLATION", "NACL_DENY_RULE"],
            },
            {
                "id": "GCP",
                "name": "Google Cloud Platform (Builders Hub)",
                "auth_methods": ["WORKLOAD_IDENTITY_FEDERATION", "SERVICE_ACCOUNT_ADC"],
                "telemetry_types": ["CLOUD_LOGGING_VPC_FLOWS", "PUBSUB"],
                "enforcement_mechanisms": ["VPC_FIREWALL_DENY", "HIERARCHICAL_FIREWALL"],
            },
            {
                "id": "AZURE",
                "name": "Microsoft Azure",
                "auth_methods": ["FEDERATED_CREDENTIAL_OIDC", "MANAGED_IDENTITY", "SERVICE_PRINCIPAL"],
                "telemetry_types": ["NETWORK_WATCHER_NSG_FLOW_V1", "NETWORK_WATCHER_NSG_FLOW_V2"],
                "enforcement_mechanisms": ["NSG_SECURITY_RULE_DENY", "AZURE_FIREWALL_RULE"],
            },
            {
                "id": "DOCKER_LAB",
                "name": "Simulated Hybrid Docker Lab",
                "auth_methods": ["LOCAL_CONTAINER_SOCKET"],
                "telemetry_types": ["ROUTER_PCAP_STREAM", "LOCAL_FORWARD_LOGS"],
                "enforcement_mechanisms": ["IPTABLES_DROP", "ROUTE_BLACKHOLE"],
            },
        ]
    }


@router.get("/accounts", response_model=List[CloudAccountStatusSchema])
def list_accounts(
    provider: Optional[str] = Query(None, description="Filter by provider: AWS, GCP, AZURE, DOCKER_LAB"),
    db: Session = Depends(get_db),
):
    """
    List configured cloud accounts with current connection statuses.
    """
    db_accounts = CloudRegistry.list_accounts(db, provider=provider)
    if db_accounts:
        return [
            CloudAccountStatusSchema(
                account_id=acc.account_id,
                provider=acc.provider,
                account_name=acc.account_name,
                region=acc.region,
                status=acc.status,
                enabled=acc.enabled,
                enforcement_enabled=acc.enforcement_enabled,
                latency_ms=acc.latency_ms,
                error_message=acc.last_error,
                last_checked_at=acc.last_checked_at,
            )
            for acc in db_accounts
        ]

    # If no DB records yet, return active defaults from health monitor
    summary = CloudHealthMonitor.get_provider_health_summary(db)
    statuses: List[CloudAccountStatusSchema] = []
    for prov_name, prov_data in summary.get("providers", {}).items():
        if provider and prov_name != provider.upper():
            continue
        statuses.append(
            CloudAccountStatusSchema(
                account_id=prov_data.get("account_id", f"{prov_name.lower()}-default"),
                provider=prov_name,
                account_name=f"{prov_name} Primary Adapter",
                region=prov_data.get("region", "global"),
                status=prov_data.get("status", "CONFIGURED"),
                enabled=True,
                enforcement_enabled=prov_data.get("enforcement_ready", False),
                latency_ms=1.5,
                error_message=None,
                last_checked_at=datetime.now(timezone.utc),
            )
        )
    return statuses


@router.post("/accounts", response_model=CloudAccountStatusSchema)
def register_or_update_account(
    req: CloudAccountCreateRequest,
    db: Session = Depends(get_db),
):
    """
    Register or update a cloud account configuration.
    """
    cfg = CloudAccountConfigSchema(**req.model_dump())
    # Test connection non-destructively
    test_result = CloudConnectionManager.test_connection(cfg)
    status_str = test_result.get("status", "CONFIGURED")
    latency = test_result.get("latency_ms")

    saved = CloudRegistry.upsert_account(
        db=db,
        config=cfg,
        status=status_str,
        latency_ms=latency,
    )

    # Sync initial network resources from adapter
    adapter = CloudConnectionManager.get_adapter(cfg.account_id)
    if adapter:
        try:
            resources = adapter.list_network_resources()
            CloudRegistry.sync_resources(db, cfg.account_id, resources)
        except Exception as e:
            logger.warning("Resource sync during account register omitted: %s", e)

    return CloudAccountStatusSchema(
        account_id=saved.account_id,
        provider=saved.provider,
        account_name=saved.account_name,
        region=saved.region,
        status=saved.status,
        enabled=saved.enabled,
        enforcement_enabled=saved.enforcement_enabled,
        latency_ms=saved.latency_ms,
        error_message=saved.last_error,
        last_checked_at=saved.last_checked_at,
    )


@router.post("/accounts/{provider}/test-connection")
def test_provider_connection(
    provider: str,
    config: Optional[CloudAccountConfigSchema] = None,
):
    """
    Test connectivity and caller identity for a specific provider.
    """
    prov_upper = provider.upper()
    if config:
        cfg = config
    else:
        # Default test config
        cfg = CloudAccountConfigSchema(
            account_id=f"{prov_upper.lower()}-test",
            provider=prov_upper,
            account_name=f"{prov_upper} Test Account",
            region="us-east-1" if prov_upper == "AWS" else ("us-central1" if prov_upper == "GCP" else "eastus"),
            enabled=True,
        )

    try:
        return CloudConnectionManager.test_connection(cfg)
    except Exception as e:
        return {
            "provider": prov_upper,
            "status": "ERROR",
            "message": str(e),
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }


@router.get("/resources", response_model=List[CloudResourceSchema])
def list_cloud_resources(
    provider: Optional[str] = Query(None, description="Filter by provider"),
    resource_type: Optional[str] = Query(None, description="Filter by type: VPC, SUBNET, GATEWAY, SECURITY_GROUP"),
    db: Session = Depends(get_db),
):
    """
    List discovered network resources across clouds.
    """
    db_res = CloudRegistry.list_resources(db, provider=provider, resource_type=resource_type)
    if db_res:
        return [
            CloudResourceSchema(
                resource_id=r.resource_id,
                account_id=r.account_id,
                provider=r.provider,
                resource_type=r.resource_type,
                name=r.name,
                cidr_block=r.cidr_block,
                region=r.region,
                zone=r.zone,
                vpc_id=r.vpc_id,
                state=r.state,
                tags=r.tags or {},
                extra_data=r.extra_data or {},
                created_at=r.created_at,
            )
            for r in db_res
        ]

    # If DB has no resources yet, discover live from active adapters
    all_res: List[CloudResourceSchema] = []
    for prov in ["AWS", "GCP", "AZURE", "DOCKER_LAB"]:
        if provider and prov != provider.upper():
            continue
        cfg = CloudAccountConfigSchema(
            account_id=f"{prov.lower()}-default",
            provider=prov,
            account_name=f"{prov} Account",
            region="us-east-1" if prov == "AWS" else ("us-central1" if prov == "GCP" else ("eastus" if prov == "AZURE" else "local")),
            enabled=True,
        )
        adapter = CloudConnectionManager.create_adapter(cfg)
        prov_res = adapter.list_network_resources()
        if resource_type:
            prov_res = [r for r in prov_res if r.resource_type == resource_type.upper()]
        all_res.extend(prov_res)

    return all_res


@router.get("/inventory/summary", response_model=CloudInventorySummary)
def get_inventory_summary(db: Session = Depends(get_db)):
    """
    Return summary counts of VPCs, Subnets, Gateways, and Firewalls across all clouds.
    """
    return CloudRegistry.get_inventory_summary(db)


@router.post("/telemetry/ingest", response_model=CloudTelemetryBatchResponse)
def ingest_cloud_telemetry(
    batch: CloudTelemetryBatchRequest,
    db: Session = Depends(get_db),
):
    """
    Ingest, normalize, evaluate via XGBoost V2, and persist a batch of cloud flow telemetry.
    Supports AWS VPC Flow Logs, GCP Cloud Logging JSON, Azure NSG Tuples, and Docker Lab logs.
    """
    provider = batch.provider.upper()
    account_id = batch.account_id

    # 1. Parse raw records using provider-specific adapter
    cfg = CloudAccountConfigSchema(
        account_id=account_id,
        provider=provider,
        account_name=f"{provider} Ingestion Source",
        region=batch.region or "us-east-1",
        enabled=True,
    )
    adapter = CloudConnectionManager.create_adapter(cfg)
    telemetry_provider = adapter.get_telemetry_provider()

    canonical_records: List[CanonicalFlowRecord] = []

    # If records are already CanonicalFlowRecord dicts or raw strings
    for rec in batch.records:
        parsed = telemetry_provider.parse_raw_log_record(rec)
        if parsed is not None:
            canonical_records.append(parsed)

    if not canonical_records:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No valid flow records could be parsed for provider '{provider}'. Please verify raw telemetry format.",
        )

    # 2. Process via TelemetryNormalizer (9-feature XGBoost V2 schema + ML inference + Policy + DB)
    response = TelemetryNormalizer.process_canonical_batch(
        records=canonical_records,
        provider=provider,
        account_id=account_id,
        db=db,
        persist=batch.persist_events,
    )

    return response


@router.get("/health", response_model=Dict[str, Any])
def get_multi_cloud_health(db: Session = Depends(get_db)):
    """
    Real-time health check across AWS, GCP, Azure, and Docker Lab adapters.
    """
    return CloudHealthMonitor.get_provider_health_summary(db)

