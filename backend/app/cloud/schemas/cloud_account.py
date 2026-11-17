"""
Cloud Account & Provider Schemas
================================
Defines contract for cloud provider configurations, identity models,
and connection health diagnostics across AWS, GCP, Azure, and Docker Lab.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, model_validator

CloudProviderType = Literal["AWS", "GCP", "AZURE", "DOCKER_LAB"]
ConnectionStatusType = Literal[
    "NOT_CONFIGURED",
    "CONFIGURED",
    "CONNECTED",
    "DEGRADED",
    "ERROR",
]


class CloudCapabilitiesSchema(BaseModel):
    read_inventory: bool = True
    read_flow_logs: bool = True
    read_telemetry_streaming: bool = False
    write_containment: bool = False
    write_security_group: bool = False
    write_nacl: bool = False
    write_firewall_rule: bool = False
    write_firewall_rules: bool = False
    dry_run_only: bool = True
    supports_oidc_federation: bool = True
    supports_workload_identity: bool = False
    supports_private_endpoints: bool = True
    supports_flow_logs_v2: bool = True


class CloudAccountConfigSchema(BaseModel):
    provider: CloudProviderType
    account_id: str = Field(..., description="AWS Account ID, GCP Project ID, or Azure Subscription ID")
    display_name: str = ""
    account_name: Optional[str] = None
    region: str = "us-east-1"
    enabled: bool = True
    role_arn: Optional[str] = Field(None, description="AWS IAM Role ARN or Workload Identity provider")
    oidc_role_arn: Optional[str] = None
    external_id: Optional[str] = Field(None, description="Optional STS External ID")
    profile_name: Optional[str] = Field(None, description="AWS CLI named profile, e.g. security-gateway-readonly")
    project_id: Optional[str] = None
    workload_identity_provider: Optional[str] = None
    workload_identity_pool: Optional[str] = None
    subscription_id: Optional[str] = None
    tenant_id: Optional[str] = Field(None, description="Azure Entra ID Tenant ID")
    client_id: Optional[str] = None
    resource_group: Optional[str] = Field(None, description="Azure Resource Group")
    vpc_network_name: Optional[str] = Field(None, description="Target VPC / VNet name")
    telemetry_enabled: bool = False
    enforcement_enabled: bool = False
    capabilities: CloudCapabilitiesSchema = Field(default_factory=CloudCapabilitiesSchema)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def sync_names(cls, values: Any) -> Any:
        if isinstance(values, dict):
            acc_name = values.get("account_name")
            disp_name = values.get("display_name")
            if acc_name and not disp_name:
                values["display_name"] = acc_name
            elif disp_name and not acc_name:
                values["account_name"] = disp_name
            elif not acc_name and not disp_name:
                values["display_name"] = values.get("account_id", "Cloud Account")
                values["account_name"] = values.get("account_id", "Cloud Account")
        return values


class CloudAccountStatusSchema(BaseModel):
    id: Optional[str] = None
    account_id: str
    provider: CloudProviderType
    display_name: str = ""
    account_name: Optional[str] = None
    region: str = "global"
    status: ConnectionStatusType = "CONFIGURED"
    enabled: bool = True
    enforcement_enabled: bool = False
    capabilities: Optional[CloudCapabilitiesSchema] = None
    latency_ms: Optional[float] = None
    error_message: Optional[str] = None
    last_error: Optional[str] = None
    last_connection_check: Optional[datetime] = None
    last_checked_at: Optional[datetime] = None
    last_telemetry_sync: Optional[datetime] = None
    resources_count: int = 0
    has_stored_credentials: bool = False
    masked_identity: Optional[str] = None
    auth_method: Optional[str] = None
    rotated_at: Optional[datetime] = None

    @model_validator(mode="before")
    @classmethod
    def sync_status_fields(cls, values: Any) -> Any:
        if isinstance(values, dict):
            if "account_name" in values and "display_name" not in values:
                values["display_name"] = values["account_name"]
            elif "display_name" in values and "account_name" not in values:
                values["account_name"] = values["display_name"]
            if "id" not in values and "account_id" in values:
                values["id"] = values["account_id"]
            if "last_checked_at" in values and "last_connection_check" not in values:
                values["last_connection_check"] = values["last_checked_at"]
            if "error_message" in values and "last_error" not in values:
                values["last_error"] = values["error_message"]
        return values


class CloudAccountCreateRequest(BaseModel):
    provider: CloudProviderType
    account_id: str
    display_name: Optional[str] = None
    account_name: Optional[str] = None
    region: str = "us-east-1"
    role_arn: Optional[str] = None
    oidc_role_arn: Optional[str] = None
    project_id: Optional[str] = None
    workload_identity_provider: Optional[str] = None
    subscription_id: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    enabled: bool = True
    enforcement_enabled: bool = False
    auth_method: Optional[str] = None
    credentials: Optional[Dict[str, Any]] = None  # Processed and encrypted into vault server-side
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CloudAccountUpdateRequest(BaseModel):
    display_name: Optional[str] = None
    account_name: Optional[str] = None
    region: Optional[str] = None
    role_arn: Optional[str] = None
    enabled: Optional[bool] = None
    enforcement_enabled: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None


class CloudCredentialRotateRequest(BaseModel):
    auth_method: Optional[str] = None
    credentials: Dict[str, Any] = Field(..., description="New credential payload to be encrypted in vault")


class CloudVaultInfoSchema(BaseModel):
    has_credentials: bool
    auth_method: str
    masked_identity: str
    key_version: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    rotated_at: Optional[str] = None

