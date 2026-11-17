"""
Multi-Cloud Management & Telemetry Ingestion Router
===================================================
Provides endpoints for multi-cloud provider accounts, health diagnostics,
network resource discovery, and canonical telemetry normalization.
"""

from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

try:
    from backend.app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountCreateRequest,
        CloudAccountStatusSchema,
        CloudCapabilitiesSchema,
        CloudCredentialRotateRequest,
        CloudVaultInfoSchema,
    )
    from backend.app.cloud.schemas.cloud_resource import (
        CloudInventorySummary,
        CloudResourceSchema,
    )
    from backend.app.cloud.schemas.cloud_telemetry import (
        CanonicalFlowRecord,
        CloudTelemetryBatchRequest,
        CloudTelemetryBatchResponse,
        TelemetryNormalizationReport,
    )
    from backend.app.cloud.services.cloud_connection_manager import CloudConnectionManager
    from backend.app.cloud.services.cloud_health_monitor import CloudHealthMonitor
    from backend.app.cloud.services.cloud_registry import CloudRegistry
    from backend.app.cloud.services.credential_vault import CredentialVaultService
    from backend.app.api.deps import (
        require_admin,
        require_analyst,
        require_operator,
        require_service_or_trusted_network,
    )
    from backend.app.cloud.services.telemetry_checkpoint_service import TelemetryCheckpointService
    from backend.app.cloud.services.telemetry_normalizer import TelemetryNormalizer
    from backend.app.db.session import get_db
    from backend.app.models.cloud_account import (
        CloudAccountModel,
        CloudCredentialVaultModel,
        CloudResourceModel,
        CloudTelemetryCheckpointModel,
    )
    from ml.features.extractor import FEATURE_NAMES_V2
except ImportError:
    from app.api.deps import (
        require_admin,
        require_analyst,
        require_operator,
        require_service_or_trusted_network,
    )
    from app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountCreateRequest,
        CloudAccountStatusSchema,
        CloudCapabilitiesSchema,
        CloudCredentialRotateRequest,
        CloudVaultInfoSchema,
    )
    from app.cloud.schemas.cloud_resource import (
        CloudInventorySummary,
        CloudResourceSchema,
    )
    from app.cloud.schemas.cloud_telemetry import (
        CanonicalFlowRecord,
        CloudTelemetryBatchRequest,
        CloudTelemetryBatchResponse,
        TelemetryNormalizationReport,
    )
    from app.cloud.services.cloud_connection_manager import CloudConnectionManager
    from app.cloud.services.cloud_health_monitor import CloudHealthMonitor
    from app.cloud.services.cloud_registry import CloudRegistry
    from app.cloud.services.credential_vault import CredentialVaultService
    from app.cloud.services.telemetry_checkpoint_service import TelemetryCheckpointService
    from app.cloud.services.telemetry_normalizer import TelemetryNormalizer
    from app.db.session import get_db
    from app.models.cloud_account import (
        CloudAccountModel,
        CloudCredentialVaultModel,
        CloudResourceModel,
        CloudTelemetryCheckpointModel,
    )
    from ml.features.extractor import FEATURE_NAMES_V2

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cloud", tags=["Multi-Cloud Architecture"])


@router.get("/providers", response_model=Dict[str, Any])
def list_supported_providers(_user=Depends(require_analyst)):
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
    _user=Depends(require_analyst),
):
    """
    List configured cloud accounts with current connection statuses and masked vault indicators.
    """
    db_accounts = CloudRegistry.list_accounts(db, provider=provider)
    if db_accounts:
        results = []
        for acc in db_accounts:
            vault_info = CredentialVaultService.get_vault_info(db, acc.account_id)
            res_count = db.query(CloudResourceModel).filter(CloudResourceModel.cloud_account_id == acc.id).count()
            results.append(
                CloudAccountStatusSchema(
                    account_id=acc.account_id,
                    provider=acc.provider,
                    account_name=acc.display_name,
                    display_name=acc.display_name,
                    region=acc.region,
                    status=acc.status,
                    enabled=acc.enabled,
                    enforcement_enabled=acc.capabilities.get("write_containment", False) if isinstance(acc.capabilities, dict) else False,
                    latency_ms=acc.metadata_json.get("latency_ms") if isinstance(acc.metadata_json, dict) else None,
                    error_message=acc.last_error,
                    last_checked_at=acc.last_connection_check,
                    resources_count=res_count,
                    has_stored_credentials=bool(vault_info),
                    masked_identity=vault_info.get("masked_identity") if vault_info else None,
                    auth_method=vault_info.get("auth_method") if vault_info else None,
                    rotated_at=datetime.fromisoformat(vault_info["rotated_at"]) if vault_info and vault_info.get("rotated_at") else None,
                )
            )
        return results

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
                display_name=f"{prov_name} Primary Adapter",
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
    current_user: Any = Depends(require_operator),
    db: Session = Depends(get_db),
):
    """
    Register or update a cloud account configuration with secure server-side vault encryption.
    """
    # 1. Process and encrypt credentials into vault if supplied
    auth_method = req.auth_method or "CONFIGURED"
    if req.credentials:
        prov = req.provider.upper()
        if prov == "AWS":
            auth_method = "STS_ASSUME_ROLE" if "role_arn" in req.credentials else "ACCESS_KEYS"
        elif prov == "GCP":
            auth_method = "SERVICE_ACCOUNT_KEY" if "private_key" in str(req.credentials) else "WORKLOAD_IDENTITY"
        elif prov == "AZURE":
            auth_method = "CLIENT_SECRET" if "client_secret" in req.credentials else "FEDERATED_CREDENTIAL"

        CredentialVaultService.store_credentials(
            db=db,
            account_id=req.account_id,
            provider=req.provider,
            auth_method=auth_method,
            credentials=req.credentials,
        )

    # 2. Build non-secret config
    cfg_data = req.model_dump(exclude={"credentials"})
    cfg = CloudAccountConfigSchema(**cfg_data)

    # Temporarily supply credentials to adapter for initial verification
    if req.credentials:
        cfg.metadata.update(req.credentials)

    test_result = CloudConnectionManager.test_connection(cfg)
    status_str = test_result.get("status", "CONFIGURED")
    latency = test_result.get("latency_ms")

    # Clean out any sensitive values before persisting to metadata_json
    clean_meta = {
        k: v for k, v in cfg.metadata.items()
        if not any(s in k.lower() for s in ["secret", "key", "password", "token", "private"])
    }
    cfg.metadata = clean_meta

    saved = CloudRegistry.upsert_account(
        db=db,
        config=cfg,
        status=status_str,
        latency_ms=latency,
        error_message=test_result.get("message") if status_str in ("ERROR", "AUTHENTICATION_FAILED") else None,
    )

    # Discover and sync initial resources
    res_count = 0
    adapter = CloudConnectionManager.get_adapter(cfg.account_id)
    if adapter:
        try:
            resources = adapter.list_network_resources()
            res_count = CloudRegistry.sync_resources(db, cfg.account_id, resources)
        except Exception as e:
            logger.warning("Resource discovery omitted during registration: %s", e)

    vault_info = CredentialVaultService.get_vault_info(db, saved.account_id)
    return CloudAccountStatusSchema(
        account_id=saved.account_id,
        provider=saved.provider,
        account_name=saved.display_name,
        display_name=saved.display_name,
        region=saved.region,
        status=saved.status,
        enabled=saved.enabled,
        enforcement_enabled=False,
        latency_ms=latency,
        error_message=saved.last_error,
        last_checked_at=saved.last_connection_check,
        resources_count=res_count,
        has_stored_credentials=bool(vault_info),
        masked_identity=vault_info.get("masked_identity") if vault_info else None,
        auth_method=vault_info.get("auth_method") if vault_info else None,
        rotated_at=datetime.fromisoformat(vault_info["rotated_at"]) if vault_info and vault_info.get("rotated_at") else None,
    )


@router.delete("/accounts/{provider}/{account_id}")
def disconnect_and_delete_account(
    provider: str,
    account_id: str,
    current_user: Any = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Disconnects and deletes a cloud account, purging encrypted vault credentials
    and discovered inventory while preserving historical audit telemetry.
    """
    deleted = CloudRegistry.delete_account(db, account_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cloud account '{account_id}' not found",
        )
    return {
        "success": True,
        "provider": provider.upper(),
        "account_id": account_id,
        "message": f"Cloud integration for '{account_id}' successfully disconnected and credentials purged from vault.",
    }


@router.post("/accounts/{provider}/{account_id}/rotate-credentials")
def rotate_account_credentials(
    provider: str,
    account_id: str,
    req: CloudCredentialRotateRequest,
    current_user: Any = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Rotates existing credentials with new AES-256-GCM encrypted secrets in vault.
    """
    account = CloudRegistry.get_account(db, account_id)
    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cloud account '{account_id}' not found",
        )

    try:
        updated_entry = CredentialVaultService.rotate_credentials(
            db=db,
            account_id=account_id,
            new_credentials=req.credentials,
            new_auth_method=req.auth_method,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Credential rotation failed: {str(e)}",
        )

    # Re-test connection with new credentials
    cfg = CloudAccountConfigSchema(
        provider=account.provider,
        account_id=account.account_id,
        region=account.region,
        metadata=dict(req.credentials),
    )
    test_result = CloudConnectionManager.test_connection(cfg)
    new_status = test_result.get("status", "CONFIGURED")
    CloudRegistry.update_account_status(
        db,
        account_id=account_id,
        status=new_status,
        latency_ms=test_result.get("latency_ms"),
        error_message=test_result.get("message") if new_status in ("ERROR", "AUTHENTICATION_FAILED") else None,
    )

    return {
        "success": True,
        "account_id": account_id,
        "provider": account.provider,
        "status": new_status,
        "masked_identity": updated_entry.masked_identity,
        "rotated_at": updated_entry.rotated_at.isoformat() if updated_entry.rotated_at else None,
    }


@router.post("/accounts/{provider}/test-connection")
def test_provider_connection(
    provider: str,
    config: Optional[CloudAccountConfigSchema] = None,
    _user=Depends(require_operator),
):
    """
    Test connectivity and caller identity for a specific provider.
    """
    prov_upper = provider.upper()
    if config:
        cfg = config
    else:
        # Default test config with environment awareness
        default_region = "us-east-1"
        role_arn = None
        ext_id = None
        if prov_upper == "AWS":
            default_region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "ap-southeast-2"
            role_arn = os.environ.get("AWS_ROLE_ARN") or "arn:aws:iam::698766075180:role/SecurityGatewayReadOnlyRole"
            ext_id = os.environ.get("AWS_EXTERNAL_ID") or "AdaptiveGatewayAuth"
            profile = os.environ.get("AWS_PROFILE") or "security-gateway-readonly"
            acc_id = os.environ.get("AWS_ACCOUNT_ID") or "698766075180"
            cfg = CloudAccountConfigSchema(
                account_id=acc_id,
                provider="AWS",
                account_name="AWS Primary Account",
                display_name=f"AWS Production ({acc_id})",
                region=default_region,
                role_arn=role_arn,
                external_id=ext_id,
                profile_name=profile,
                enabled=True,
                metadata={"profile_name": profile},
            )
        elif prov_upper == "GCP":
            default_region = "us-central1"
            cfg = CloudAccountConfigSchema(
                account_id=f"{prov_upper.lower()}-test",
                provider=prov_upper,
                account_name=f"{prov_upper} Test Account",
                region=default_region,
                enabled=True,
            )
        elif prov_upper == "AZURE":
            default_region = "eastus"
            cfg = CloudAccountConfigSchema(
                account_id=f"{prov_upper.lower()}-test",
                provider=prov_upper,
                account_name=f"{prov_upper} Test Account",
                region=default_region,
                enabled=True,
            )
        else:
            cfg = CloudAccountConfigSchema(
                account_id=f"{prov_upper.lower()}-test",
                provider=prov_upper,
                account_name=f"{prov_upper} Test Account",
                region="local",
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


@router.post("/accounts/{provider}/discover", response_model=Dict[str, Any])
def discover_provider_network_resources(
    provider: str,
    account_id: Optional[str] = Query(None, description="Target account ID"),
    region: Optional[str] = Query(None, description="Optional region override"),
    db: Session = Depends(get_db),
    _user=Depends(require_operator),
):
    """
    Triggers network resource discovery (VPCs, Subnets, Gateways, Firewalls/SGs, Routes)
    for the specified cloud provider (AWS, GCP, AZURE, DOCKER_LAB).
    Persists discovered resources in PostgreSQL and returns inventory breakdown.
    """
    prov_upper = provider.upper()
    if prov_upper == "AWS" and not account_id:
        return discover_aws_network_resources(region=region, db=db, _user=_user)

    # Find account or use first registered for provider
    acc = None
    if account_id:
        acc = CloudRegistry.get_account(db, account_id)
    else:
        accounts = CloudRegistry.list_accounts(db, provider=prov_upper)
        if accounts:
            acc = accounts[0]

    if acc:
        target_account_id = acc.account_id
        target_region = region or acc.region
        cfg = CloudAccountConfigSchema(
            provider=acc.provider,
            account_id=acc.account_id,
            display_name=acc.display_name,
            region=target_region,
            enabled=acc.enabled,
            metadata=dict(acc.metadata_json or {}),
        )
    else:
        target_account_id = account_id or f"{prov_upper.lower()}-default"
        target_region = region or ("us-central1" if prov_upper == "GCP" else "eastus" if prov_upper == "AZURE" else "us-east-1")
        cfg = CloudAccountConfigSchema(
            provider=prov_upper,
            account_id=target_account_id,
            region=target_region,
            enabled=True,
        )

    # Check vault for credentials
    creds = CredentialVaultService.get_credentials(db, target_account_id)
    if creds:
        cfg.metadata.update(creds)

    adapter = CloudConnectionManager.create_adapter(cfg)
    conn = adapter.check_connection()

    try:
        resources = adapter.list_network_resources()
    except Exception as e:
        logger.warning("Resource discovery failed for %s: %s", prov_upper, e)
        resources = []

    synced_count = 0
    if resources:
        synced_count = CloudRegistry.sync_resources(db, target_account_id, resources)
        CloudRegistry.update_account_status(
            db,
            target_account_id,
            status=conn.get("status", "CONNECTED"),
            latency_ms=conn.get("latency_ms"),
        )

    counts: Dict[str, int] = {}
    for r in resources:
        counts[r.resource_type] = counts.get(r.resource_type, 0) + 1

    return {
        "status": "SUCCESS",
        "provider": prov_upper,
        "account_id": target_account_id,
        "region": target_region,
        "total_resources": len(resources),
        "synced_to_db": synced_count,
        "counts_by_type": counts,
        "caller_identity": conn.get("caller_identity"),
        "resources": [r.model_dump() for r in resources],
    }


@router.post("/accounts/AWS/discover", response_model=Dict[str, Any])
def discover_aws_network_resources(
    region: Optional[str] = Query(None, description="Optional region override"),
    db: Session = Depends(get_db),
    _user=Depends(require_operator),
):
    """
    Triggers read-only AWS EC2 discovery of VPCs, Subnets, Route Tables, Security Groups, NACLs, and Flow Logs.
    Persists discovered resources in PostgreSQL and returns inventory breakdown.
    """
    adapter = CloudConnectionManager.get_or_create_aws_adapter(region=region)
    conn = adapter.check_connection()
    if conn.get("status") not in ("CONNECTED", "CONFIGURED"):
        return {
            "status": conn.get("status"),
            "message": conn.get("message"),
            "resources_discovered": 0,
            "caller_identity": conn.get("caller_identity"),
            "inventory": [],
        }

    resources = adapter.list_network_resources()
    synced_count = 0
    if resources:
        synced_count = CloudRegistry.sync_resources(db, adapter.account_id, resources)
        CloudRegistry.update_account_status(
            db,
            adapter.account_id,
            status=conn.get("status", "CONNECTED"),
            latency_ms=conn.get("latency_ms"),
        )

    counts: Dict[str, int] = {}
    for r in resources:
        counts[r.resource_type] = counts.get(r.resource_type, 0) + 1

    return {
        "status": "SUCCESS",
        "account_id": adapter.account_id,
        "region": adapter.region,
        "total_resources": len(resources),
        "synced_to_db": synced_count,
        "counts_by_type": counts,
        "caller_identity": conn.get("caller_identity"),
        "resources": [r.model_dump() for r in resources],
    }


@router.get("/accounts/AWS/flow-logs", response_model=Dict[str, Any])
def get_aws_flow_log_subscriptions(
    region: Optional[str] = Query(None, description="Optional region override"),
    _user=Depends(require_analyst),
):
    """
    Inspects active VPC Flow Log subscriptions on AWS, identifying destinations (CloudWatch Logs vs S3).
    """
    adapter = CloudConnectionManager.get_or_create_aws_adapter(region=region)
    subscriptions = adapter.get_flow_log_subscriptions()
    return {
        "account_id": adapter.account_id,
        "region": adapter.region,
        "subscriptions_count": len(subscriptions),
        "subscriptions": subscriptions,
    }


@router.post("/accounts/AWS/poll-telemetry", response_model=CloudTelemetryBatchResponse)
def poll_aws_telemetry(
    limit: int = Query(50, ge=1, le=500),
    log_group: Optional[str] = Query(None, description="Specific CloudWatch log group"),
    s3_bucket: Optional[str] = Query(None, description="Specific S3 bucket destination"),
    mock_fallback: bool = Query(False, description="Allow mock fixture fallback if no live AWS flow logs exist"),
    db: Session = Depends(get_db),
    _user=Depends(require_operator),
):
    """
    Polls real AWS VPC flow log events from CloudWatch Logs or Amazon S3,
    normalizes them into the canonical 9-feature XGBoost V2 format,
    runs threat prediction, updates persistent checkpoints, and records security events.
    """
    adapter = CloudConnectionManager.get_or_create_aws_adapter()
    telemetry_provider = adapter.get_telemetry_provider()

    filter_params: Dict[str, Any] = {}
    if log_group:
        filter_params["log_group"] = log_group
    if s3_bucket:
        filter_params["s3_bucket"] = s3_bucket

    target_source_id = log_group or s3_bucket or "default"
    existing_chk = TelemetryCheckpointService.get_checkpoint(
        db, provider="AWS", account_id=adapter.account_id, source_identifier=target_source_id
    )

    chk_dict = None
    if existing_chk:
        chk_dict = {
            "last_timestamp_ms": existing_chk.last_timestamp_ms,
            "last_token": existing_chk.last_token,
            "last_object_key": existing_chk.last_object_key,
        }

    poll_res = telemetry_provider.poll_flow_telemetry(
        checkpoint=chk_dict,
        limit=limit,
        filter_params=filter_params or None,
        mock_fallback=mock_fallback,
    )

    raw_events = poll_res.get("events", [])
    chk_err = poll_res.get("checkpoint", {}).get("error")
    if not raw_events:
        # Return structured NO_NEW_EVENTS (or ERROR) response rather than failure
        resp_status = "ERROR" if chk_err else "NO_NEW_EVENTS"
        err_msg = chk_err if chk_err else None
        user_msg = (
            f"CloudWatch poll notice: {chk_err}"
            if chk_err
            else "No new flow events detected in selected CloudWatch log window."
        )
        return CloudTelemetryBatchResponse(
            status=resp_status,
            provider="AWS",
            account_id=adapter.account_id,
            records_received=0,
            records_parsed=0,
            records_aggregated=0,
            high_risk_flows_detected=0,
            flows_accepted=0,
            flows_dropped=0,
            parsing_duration_ms=0.0,
            inference_duration_ms=0.0,
            flows=[],
            normalization_report=TelemetryNormalizationReport(
                features_extracted=FEATURE_NAMES_V2,
                schema_version="v2_canonical",
                failed_auth_synthesized=False,
                timestamp_provenance=True,
                direction_classified=True,
            ),
            error_message=err_msg,
            message=user_msg,
        )

    canonical_records: List[CanonicalFlowRecord] = []
    for ev in raw_events:
        parsed = telemetry_provider.parse_raw_log_record(ev)
        if parsed is not None:
            canonical_records.append(parsed)

    if not canonical_records:
        return CloudTelemetryBatchResponse(
            status="NO_NEW_EVENTS",
            provider="AWS",
            account_id=adapter.account_id,
            records_received=len(raw_events),
            records_parsed=0,
            records_aggregated=0,
            high_risk_flows_detected=0,
            flows_accepted=0,
            flows_dropped=0,
            parsing_duration_ms=0.0,
            inference_duration_ms=0.0,
            flows=[],
            normalization_report=TelemetryNormalizationReport(
                features_extracted=FEATURE_NAMES_V2,
                schema_version="v2_canonical",
                failed_auth_synthesized=False,
                timestamp_provenance=True,
                direction_classified=True,
            ),
        )

    return TelemetryNormalizer.process_canonical_batch(
        records=canonical_records,
        provider="AWS",
        account_id=adapter.account_id,
        db=db,
        persist=True,
        checkpoint_data=poll_res.get("checkpoint"),
        source_type=poll_res.get("source_type"),
        source_identifier=poll_res.get("source_identifier"),
    )


@router.get("/accounts/AWS/telemetry-status", response_model=Dict[str, Any])
def get_aws_telemetry_status(
    db: Session = Depends(get_db),
    _user=Depends(require_analyst),
):
    """
    Returns live ingestion health metrics, source identifier, and last checkpoint information.
    Distinguishes clearly between latest ingestion run metrics and cumulative checkpoint metrics.
    """
    adapter = CloudConnectionManager.get_or_create_aws_adapter()
    telemetry_provider = adapter.get_telemetry_provider()
    ingest_status = telemetry_provider.get_ingestion_status()

    # Get checkpoints
    sources = telemetry_provider.discover_flow_log_sources()
    checkpoints: List[Dict[str, Any]] = []
    cumulative_records = 0
    for s in sources:
        dest = s.get("destination", "")
        if dest:
            chk = TelemetryCheckpointService.get_checkpoint(
                db, provider="AWS", account_id=adapter.account_id, source_identifier=dest
            )
            if chk:
                checkpoints.append({
                    "source_identifier": chk.source_identifier,
                    "source_type": chk.source_type,
                    "last_timestamp_ms": chk.last_timestamp_ms,
                    "last_poll_at": chk.last_poll_at.isoformat() if chk.last_poll_at else None,
                    "total_records_processed": chk.total_records_processed,
                })
                cumulative_records += (chk.total_records_processed or 0)

    # If no active sources from EC2 describe_flow_logs, check DB for stored checkpoints
    if not checkpoints:
        db_chks = db.query(CloudTelemetryCheckpointModel).filter(
            CloudTelemetryCheckpointModel.provider == "AWS",
            CloudTelemetryCheckpointModel.account_id == adapter.account_id,
        ).all()
        for chk in db_chks:
            checkpoints.append({
                "source_identifier": chk.source_identifier,
                "source_type": chk.source_type,
                "last_timestamp_ms": chk.last_timestamp_ms,
                "last_poll_at": chk.last_poll_at.isoformat() if chk.last_poll_at else None,
                "total_records_processed": chk.total_records_processed,
            })
            cumulative_records += (chk.total_records_processed or 0)

    # Retrieve latest persistent ingestion run from DB
    recent_runs = TelemetryCheckpointService.list_ingestion_history(
        db, provider="AWS", account_id=adapter.account_id, limit=1
    )
    latest_run = recent_runs[0] if recent_runs else None

    latest_run_metrics = {
        "status": latest_run.status if latest_run else "INITIALIZED",
        "records_discovered": latest_run.records_discovered if latest_run else 0,
        "records_ingested": latest_run.records_ingested if latest_run else 0,
        "records_duplicate_skipped": latest_run.records_duplicate_skipped if latest_run else 0,
        "records_rejected": latest_run.records_rejected if latest_run else 0,
        "high_risk_detected": latest_run.high_risk_detected if latest_run else 0,
        "last_poll_at": latest_run.created_at.isoformat() if latest_run and latest_run.created_at else None,
        "source_identifier": latest_run.source_identifier if latest_run else None,
    }

    cumulative_checkpoint_metrics = {
        "total_records_processed": cumulative_records,
        "checkpoints_tracked": len(checkpoints),
    }

    return {
        "provider": "AWS",
        "account_id": adapter.account_id,
        "region": adapter.region,
        "metrics": ingest_status,
        "latest_run_metrics": latest_run_metrics,
        "cumulative_checkpoint_metrics": cumulative_checkpoint_metrics,
        "active_sources_count": len(sources) or len(checkpoints),
        "sources": sources,
        "checkpoints": checkpoints,
    }


@router.get("/accounts/AWS/telemetry-history", response_model=List[Dict[str, Any]])
def get_aws_telemetry_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _user=Depends(require_analyst),
):
    """
    Returns historical ingestion audit logs for AWS telemetry.
    """
    adapter = CloudConnectionManager.get_or_create_aws_adapter()
    runs = TelemetryCheckpointService.list_ingestion_history(
        db, provider="AWS", account_id=adapter.account_id, limit=limit
    )
    return [
        {
            "id": r.id,
            "provider": r.provider,
            "account_id": r.account_id,
            "source_type": r.source_type,
            "source_identifier": r.source_identifier,
            "records_discovered": r.records_discovered,
            "records_ingested": r.records_ingested,
            "records_duplicate_skipped": r.records_duplicate_skipped,
            "records_rejected": r.records_rejected,
            "high_risk_detected": r.high_risk_detected,
            "flows_accepted": r.flows_accepted,
            "flows_dropped": r.flows_dropped,
            "status": r.status,
            "error_message": r.error_message,
            "duration_ms": r.duration_ms,
            "ingested_at": r.created_at.isoformat() if r.created_at else None,
            "summary": r.summary_json,
        }
        for r in runs
    ]


@router.post("/accounts/AWS/telemetry-checkpoints/reset", response_model=Dict[str, Any])
def reset_aws_telemetry_checkpoint(
    source_identifier: Optional[str] = Query(None, description="Specific log group or bucket to reset, or omit to reset all"),
    current_user: Any = Depends(require_operator),
    db: Session = Depends(get_db),
):
    """
    Resets ingestion checkpoints and deduplication cache to allow clean re-ingestion.
    """
    adapter = CloudConnectionManager.get_or_create_aws_adapter()
    dedup_cache = TelemetryCheckpointService.get_dedup_cache()
    dedup_cache.clear()

    q = db.query(CloudTelemetryCheckpointModel).filter(
        CloudTelemetryCheckpointModel.provider == "AWS",
        CloudTelemetryCheckpointModel.account_id == adapter.account_id,
    )
    if source_identifier:
        q = q.filter(CloudTelemetryCheckpointModel.source_identifier == source_identifier)

    deleted_count = q.delete(synchronize_session=False)
    db.commit()

    return {
        "status": "SUCCESS",
        "provider": "AWS",
        "account_id": adapter.account_id,
        "checkpoints_reset": deleted_count,
        "dedup_cache_cleared": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/resources", response_model=List[CloudResourceSchema])
def list_cloud_resources(
    provider: Optional[str] = Query(None, description="Filter by provider"),
    resource_type: Optional[str] = Query(None, description="Filter by type: VPC, SUBNET, GATEWAY, SECURITY_GROUP"),
    sync_live: bool = Query(False, description="Force re-sync from active cloud providers"),
    db: Session = Depends(get_db),
    _user=Depends(require_analyst),
):
    """
    List discovered network resources across clouds.
    Preserves idempotent persistence and avoids redundant discovery on routine polls.
    """
    if sync_live:
        for prov in ["AWS", "GCP", "AZURE", "DOCKER_LAB"]:
            if provider and prov != provider.upper():
                continue
            try:
                if prov == "AWS":
                    adapter = CloudConnectionManager.get_or_create_aws_adapter()
                else:
                    cfg = CloudAccountConfigSchema(
                        account_id=f"{prov.lower()}-default",
                        provider=prov,
                        account_name=f"{prov} Account",
                        region=("us-central1" if prov == "GCP" else ("eastus" if prov == "AZURE" else "local")),
                        enabled=True,
                    )
                    adapter = CloudConnectionManager.create_adapter(cfg)
                prov_res = adapter.list_network_resources()
                if prov_res:
                    CloudRegistry.sync_resources(db, adapter.account_id, prov_res)
            except Exception as sync_err:
                logger.debug("Live sync error for %s: %s", prov, sync_err)

    # Check if AWS has zero resources in DB and sync once idempotently if requested or unpopulated
    if not sync_live and (provider is None or provider.upper() == "AWS"):
        aws_db = CloudRegistry.list_resources(db, provider="AWS")
        if not aws_db:
            try:
                adapter = CloudConnectionManager.get_or_create_aws_adapter()
                prov_res = adapter.list_network_resources()
                if prov_res:
                    CloudRegistry.sync_resources(db, adapter.account_id, prov_res)
            except Exception as aws_err:
                logger.debug("Auto-initialization of AWS resources omitted: %s", aws_err)

    db_res = CloudRegistry.list_resources(db, provider=provider, resource_type=resource_type)
    schemas: List[CloudResourceSchema] = []
    for r in db_res:
        meta = r.metadata_json or {}
        # Determine vpc_id preserving correct resource relationships
        if r.resource_type in ("VPC", "VNET"):
            vpc_id = r.resource_id
        elif "vpc_id" in meta:
            vpc_id = meta["vpc_id"]
        elif r.resource_type in (
            "SUBNET",
            "ROUTE_TABLE",
            "SECURITY_GROUP",
            "NETWORK_ACL",
            "GATEWAY",
            "INTERNET_GATEWAY",
            "NAT_GATEWAY",
        ):
            vpc_id = r.parent_resource_id
        else:
            vpc_id = None

        schemas.append(
            CloudResourceSchema(
                id=r.id,
                resource_id=r.resource_id,
                account_id=r.cloud_account_id,
                cloud_account_id=r.cloud_account_id,
                provider=r.provider,
                resource_type=r.resource_type,
                name=r.resource_name,
                resource_name=r.resource_name,
                cidr_block=r.cidr_block,
                region=r.region,
                zone=meta.get("zone") or meta.get("AvailabilityZone"),
                vpc_id=vpc_id,
                parent_resource_id=r.parent_resource_id,
                state=meta.get("state") or meta.get("State") or "available",
                tags=meta.get("tags") or meta.get("Tags") or {},
                extra_data=meta,
                metadata=meta,
                created_at=r.discovered_at,
                discovered_at=r.discovered_at,
            )
        )
    return schemas


@router.get("/inventory/summary", response_model=CloudInventorySummary)
def get_inventory_summary(
    db: Session = Depends(get_db),
    _user=Depends(require_analyst),
):
    """
    Return summary counts of VPCs, Subnets, Gateways, and Firewalls across all clouds.
    """
    return CloudRegistry.get_inventory_summary(db)


@router.post("/telemetry/ingest", response_model=CloudTelemetryBatchResponse)
def ingest_cloud_telemetry(
    batch: CloudTelemetryBatchRequest,
    db: Session = Depends(get_db),
    _auth=Depends(require_service_or_trusted_network),
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
def get_multi_cloud_health(
    db: Session = Depends(get_db),
    _user=Depends(require_analyst),
):
    """
    Real-time health check across AWS, GCP, Azure, and Docker Lab adapters.
    """
    return CloudHealthMonitor.get_provider_health_summary(db)

