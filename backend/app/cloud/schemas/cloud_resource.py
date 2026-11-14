"""
Cloud Network Resource Schemas
==============================
Defines data models for discovered VPCs, subnets, security groups, firewalls, and network interfaces.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, model_validator
from backend.app.cloud.schemas.cloud_account import CloudProviderType

CloudResourceType = Literal[
    "VPC",
    "VNET",
    "SUBNET",
    "GATEWAY",
    "SECURITY_GROUP",
    "FIREWALL_POLICY",
    "FIREWALL_RULE",
    "NSG",
    "NETWORK_INTERFACE",
    "FLOW_LOG_SUBSCRIPTION",
]


class CloudResourceSchema(BaseModel):
    id: Optional[str] = None
    resource_id: str
    cloud_account_id: Optional[str] = None
    account_id: str = "default"
    provider: CloudProviderType
    resource_type: str = "VPC"
    resource_name: Optional[str] = None
    name: str = ""
    region: str = "global"
    zone: Optional[str] = None
    cidr_block: Optional[str] = None
    vpc_id: Optional[str] = None
    parent_resource_id: Optional[str] = None
    state: str = "available"
    tags: Dict[str, str] = Field(default_factory=dict)
    extra_data: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    discovered_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    @model_validator(mode="before")
    @classmethod
    def sync_resource_fields(cls, values: Any) -> Any:
        if isinstance(values, dict):
            # Sync id and resource_id
            rid = values.get("resource_id") or values.get("id", "res-01")
            values["resource_id"] = rid
            if not values.get("id"):
                values["id"] = rid

            # Sync account_id and cloud_account_id
            aid = values.get("account_id") or values.get("cloud_account_id", "default")
            values["account_id"] = aid
            values["cloud_account_id"] = aid

            # Sync name and resource_name
            rname = values.get("name") or values.get("resource_name", rid)
            values["name"] = rname
            values["resource_name"] = rname

            # Sync discovered_at and created_at
            now = datetime.now(timezone.utc)
            if not values.get("created_at") and not values.get("discovered_at"):
                values["created_at"] = now
                values["discovered_at"] = now
            elif values.get("created_at") and not values.get("discovered_at"):
                values["discovered_at"] = values["created_at"]
            elif values.get("discovered_at") and not values.get("created_at"):
                values["created_at"] = values["discovered_at"]
        return values


class CloudInventorySummary(BaseModel):
    total_resources: int = 0
    total_vpcs: int = 0
    vpcs_count: int = 0
    total_subnets: int = 0
    subnets_count: int = 0
    total_security_groups: int = 0
    security_groups_count: int = 0
    total_gateways: int = 0
    gateways_count: int = 0
    firewall_rules_count: int = 0
    interfaces_count: int = 0
    by_provider: Dict[str, int] = Field(default_factory=dict)
    resources: List[CloudResourceSchema] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def sync_summary_counts(cls, values: Any) -> Any:
        if isinstance(values, dict):
            vpcs = values.get("total_vpcs", values.get("vpcs_count", 0))
            subnets = values.get("total_subnets", values.get("subnets_count", 0))
            sgs = values.get("total_security_groups", values.get("security_groups_count", 0))
            gws = values.get("total_gateways", values.get("gateways_count", 0))
            values["total_vpcs"] = vpcs
            values["vpcs_count"] = vpcs
            values["total_subnets"] = subnets
            values["subnets_count"] = subnets
            values["total_security_groups"] = sgs
            values["security_groups_count"] = sgs
            values["total_gateways"] = gws
            values["gateways_count"] = gws
            if "total_resources" not in values or values["total_resources"] == 0:
                values["total_resources"] = vpcs + subnets + sgs + gws
        return values
