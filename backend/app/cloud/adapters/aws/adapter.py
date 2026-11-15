"""
AWS Cloud Adapter
=================
Enterprise adapter for Amazon Web Services integrating STS identity validation,
named AWS CLI profiles, read-only VPC network topology discovery, VPC Flow Log telemetry,
and safe containment interfaces.
Strictly non-mutating in read-only mode.
"""

from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    from backend.app.cloud.adapters.aws.enforcement import AwsEnforcementProvider
    from backend.app.cloud.adapters.aws.identity import AwsIdentityProvider
    from backend.app.cloud.adapters.aws.telemetry import AwsTelemetryProvider
    from backend.app.cloud.interfaces.provider import BaseCloudProviderAdapter
    from backend.app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountStatusSchema,
        CloudCapabilitiesSchema,
    )
    from backend.app.cloud.schemas.cloud_resource import CloudResourceSchema
except ImportError:
    from app.cloud.adapters.aws.enforcement import AwsEnforcementProvider
    from app.cloud.adapters.aws.identity import AwsIdentityProvider
    from app.cloud.adapters.aws.telemetry import AwsTelemetryProvider
    from app.cloud.interfaces.provider import BaseCloudProviderAdapter
    from app.cloud.schemas.cloud_account import (
        CloudAccountConfigSchema,
        CloudAccountStatusSchema,
        CloudCapabilitiesSchema,
    )
    from app.cloud.schemas.cloud_resource import CloudResourceSchema

logger = logging.getLogger(__name__)


def _extract_name_tag(tags: Optional[List[Dict[str, str]]]) -> Tuple[str, Dict[str, str]]:
    """Extract standard 'Name' tag and tag mapping dictionary."""
    if not tags:
        return "", {}
    tag_map = {t.get("Key", ""): t.get("Value", "") for t in tags if "Key" in t}
    name = tag_map.get("Name", "")
    return name, tag_map


class AwsCloudAdapter(BaseCloudProviderAdapter):
    """Complete AWS Cloud Provider Adapter for read-only telemetry and topology."""

    def __init__(self, config: CloudAccountConfigSchema):
        super().__init__(config)
        resolved_profile = (
            getattr(config, "profile_name", None)
            or (config.metadata.get("profile_name") if config.metadata else None)
        )
        self.identity_provider = AwsIdentityProvider(
            account_id=self.account_id,
            role_arn=config.role_arn,
            region=self.region,
            external_id=config.external_id,
            profile_name=resolved_profile,
            oidc_role_arn=config.oidc_role_arn,
        )
        self.telemetry_provider = AwsTelemetryProvider(
            account_id=self.account_id,
            region=self.region,
        )
        # Pass identity provider to telemetry provider so it shares assumed credentials
        self.telemetry_provider.set_identity_provider(self.identity_provider)

        # Containment is strictly disabled for real AWS resources in this phase
        self.enforcement_provider = AwsEnforcementProvider(
            account_id=self.account_id,
            region=self.region,
            enabled=False,  # Enforcement strictly disabled
        )

    def validate_configuration(self) -> Tuple[bool, str]:
        if not self.config.enabled:
            return False, "AWS integration is disabled in configuration"
        if not self.region:
            return False, "AWS region is required"
        return True, "AWS configuration parameters are syntactically valid"

    def check_connection(self) -> Dict[str, Any]:
        """Verify AWS connectivity and identity using STS."""
        is_valid, msg = self.validate_configuration()
        if not is_valid:
            return {
                "provider": "AWS",
                "status": "NOT_CONFIGURED",
                "message": msg,
                "latency_ms": None,
                "caller_identity": None,
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }

        start_time = time.perf_counter()
        caller_identity = self.identity_provider.get_caller_identity()
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        id_status = caller_identity.get("status")
        if id_status == "VERIFIED":
            status_str = "CONNECTED"
            message = "AWS STS authentication verified successfully"
            if caller_identity.get("account"):
                self.account_id = caller_identity["account"]
        elif id_status == "ROLE_ASSUME_FAILED":
            status_str = "AUTHENTICATION_FAILED"
            message = f"STS AssumeRole failed: {caller_identity.get('error')}"
        elif id_status == "NOT_CONFIGURED":
            status_str = "NOT_CONFIGURED"
            message = caller_identity.get("error", "No AWS credentials located.")
        else:
            status_str = "CONFIGURED"
            message = caller_identity.get("error", "AWS adapter configured in standby mode.")

        return {
            "provider": "AWS",
            "status": status_str,
            "message": message,
            "latency_ms": round(max(elapsed_ms, 0.5), 2),
            "caller_identity": caller_identity,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_capabilities(self) -> CloudCapabilitiesSchema:
        return CloudCapabilitiesSchema(
            read_inventory=True,
            read_flow_logs=True,
            read_telemetry_streaming=False,
            write_containment=False,  # Strictly read-only
            write_firewall_rules=False,
            supports_oidc_federation=True,
            supports_workload_identity=False,
            supports_private_endpoints=True,
            supports_flow_logs_v2=True,
        )

    def list_network_resources(self) -> List[CloudResourceSchema]:
        """
        Discover real AWS network topology (VPC, Subnets, Route Tables, Security Groups, NACLs, Gateways, Flow Logs).
        Uses pagination, handles rate limits and partial permissions gracefully.
        Returns empty list with informative logging if not authenticated.
        """
        session, diag = self.identity_provider.get_boto3_session()
        if session is None:
            logger.info(
                "AWS resource discovery omitted: authentication not established (%s)",
                diag.get("status"),
            )
            return []

        resources: List[CloudResourceSchema] = []
        now = datetime.now(timezone.utc)
        discovered_gw_ids = set()

        try:
            ec2 = session.client("ec2", region_name=self.region)

            # 1. Discover VPCs
            try:
                vpc_paginator = ec2.get_paginator("describe_vpcs")
                for page in vpc_paginator.paginate():
                    for vpc in page.get("Vpcs", []):
                        vpc_id = vpc["VpcId"]
                        name, tags = _extract_name_tag(vpc.get("Tags"))
                        resources.append(
                            CloudResourceSchema(
                                resource_id=vpc_id,
                                account_id=self.account_id,
                                provider="AWS",
                                resource_type="VPC",
                                name=name or vpc_id,
                                cidr_block=vpc.get("CidrBlock"),
                                region=self.region,
                                state=vpc.get("State", "available"),
                                tags=tags,
                                extra_data={
                                    "is_default": vpc.get("IsDefault", False),
                                    "dhcp_options_id": vpc.get("DhcpOptionsId"),
                                    "cidr_associations": [
                                        c.get("CidrBlock")
                                        for c in vpc.get("CidrBlockAssociationSet", [])
                                    ],
                                },
                                created_at=now,
                            )
                        )
            except Exception as e:
                logger.warning("Error discovering VPCs in region %s: %s", self.region, e)

            # 2. Discover Subnets
            try:
                subnet_paginator = ec2.get_paginator("describe_subnets")
                for page in subnet_paginator.paginate():
                    for subnet in page.get("Subnets", []):
                        subnet_id = subnet["SubnetId"]
                        name, tags = _extract_name_tag(subnet.get("Tags"))
                        resources.append(
                            CloudResourceSchema(
                                resource_id=subnet_id,
                                account_id=self.account_id,
                                provider="AWS",
                                resource_type="SUBNET",
                                name=name or subnet_id,
                                cidr_block=subnet.get("CidrBlock"),
                                region=self.region,
                                zone=subnet.get("AvailabilityZone"),
                                vpc_id=subnet.get("VpcId"),
                                state=subnet.get("State", "available"),
                                tags=tags,
                                extra_data={
                                    "available_ip_count": subnet.get("AvailableIpAddressCount"),
                                    "default_for_az": subnet.get("DefaultForAz", False),
                                },
                                created_at=now,
                            )
                        )
            except Exception as e:
                logger.warning("Error discovering subnets in region %s: %s", self.region, e)

            # 3. Discover Route Tables
            try:
                rt_paginator = ec2.get_paginator("describe_route_tables")
                for page in rt_paginator.paginate():
                    for rt in page.get("RouteTables", []):
                        rt_id = rt["RouteTableId"]
                        name, tags = _extract_name_tag(rt.get("Tags"))
                        routes_summary = []
                        for r in rt.get("Routes", []):
                            gw = r.get("GatewayId") or r.get("NatGatewayId")
                            routes_summary.append({
                                "destination": r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock"),
                                "target": gw,
                                "state": r.get("State"),
                            })
                            # Track referenced gateways for fallback discovery
                            if gw and (gw.startswith("igw-") or gw.startswith("nat-")):
                                discovered_gw_ids.add((gw, rt.get("VpcId"), "INTERNET_GATEWAY" if gw.startswith("igw-") else "NAT_GATEWAY"))

                        resources.append(
                            CloudResourceSchema(
                                resource_id=rt_id,
                                account_id=self.account_id,
                                provider="AWS",
                                resource_type="ROUTE_TABLE",
                                name=name or rt_id,
                                vpc_id=rt.get("VpcId"),
                                region=self.region,
                                state="active",
                                tags=tags,
                                extra_data={
                                    "routes_count": len(rt.get("Routes", [])),
                                    "associations_count": len(rt.get("Associations", [])),
                                    "routes": routes_summary,
                                },
                                created_at=now,
                            )
                        )
            except Exception as e:
                logger.warning("Error discovering route tables in region %s: %s", self.region, e)

            # 4. Discover Security Groups
            try:
                sg_paginator = ec2.get_paginator("describe_security_groups")
                for page in sg_paginator.paginate():
                    for sg in page.get("SecurityGroups", []):
                        sg_id = sg["GroupId"]
                        name, tags = _extract_name_tag(sg.get("Tags"))
                        resources.append(
                            CloudResourceSchema(
                                resource_id=sg_id,
                                account_id=self.account_id,
                                provider="AWS",
                                resource_type="SECURITY_GROUP",
                                name=sg.get("GroupName") or name or sg_id,
                                vpc_id=sg.get("VpcId"),
                                region=self.region,
                                state="active",
                                tags=tags,
                                extra_data={
                                    "description": sg.get("Description", ""),
                                    "ingress_rules_count": len(sg.get("IpPermissions", [])),
                                    "egress_rules_count": len(sg.get("IpPermissionsEgress", [])),
                                },
                                created_at=now,
                            )
                        )
            except Exception as e:
                logger.warning("Error discovering security groups in region %s: %s", self.region, e)

            # 5. Discover Network ACLs
            try:
                nacl_paginator = ec2.get_paginator("describe_network_acls")
                for page in nacl_paginator.paginate():
                    for nacl in page.get("NetworkAcls", []):
                        nacl_id = nacl["NetworkAclId"]
                        name, tags = _extract_name_tag(nacl.get("Tags"))
                        resources.append(
                            CloudResourceSchema(
                                resource_id=nacl_id,
                                account_id=self.account_id,
                                provider="AWS",
                                resource_type="NETWORK_ACL",
                                name=name or nacl_id,
                                vpc_id=nacl.get("VpcId"),
                                region=self.region,
                                state="active",
                                tags=tags,
                                extra_data={
                                    "is_default": nacl.get("IsDefault", False),
                                    "entries_count": len(nacl.get("Entries", [])),
                                },
                                created_at=now,
                            )
                        )
            except Exception as e:
                logger.warning("Error discovering network ACLs in region %s: %s", self.region, e)

            # 6. Discover Internet Gateways (with graceful permission fallback)
            direct_igws_found = set()
            try:
                igw_paginator = ec2.get_paginator("describe_internet_gateways")
                for page in igw_paginator.paginate():
                    for igw in page.get("InternetGateways", []):
                        igw_id = igw["InternetGatewayId"]
                        direct_igws_found.add(igw_id)
                        name, tags = _extract_name_tag(igw.get("Tags"))
                        attachments = igw.get("Attachments", [])
                        vpc_id = attachments[0].get("VpcId") if attachments else None
                        state = attachments[0].get("State", "available") if attachments else "detached"
                        resources.append(
                            CloudResourceSchema(
                                resource_id=igw_id,
                                account_id=self.account_id,
                                provider="AWS",
                                resource_type="GATEWAY",
                                name=name or igw_id,
                                vpc_id=vpc_id,
                                region=self.region,
                                state=state,
                                tags=tags,
                                extra_data={"gateway_type": "INTERNET_GATEWAY", "attachments": attachments},
                                created_at=now,
                            )
                        )
            except Exception as e:
                logger.info("Direct describe_internet_gateways call omitted or unpermitted (%s); inspecting route table associations.", e)

            # Fallback: Add any gateways referenced in active route tables that were not already discovered
            for gw_id, vpc_id, gw_type in discovered_gw_ids:
                if gw_id not in direct_igws_found:
                    resources.append(
                        CloudResourceSchema(
                            resource_id=gw_id,
                            account_id=self.account_id,
                            provider="AWS",
                            resource_type="GATEWAY",
                            name=f"{gw_type.replace('_', ' ').title()} ({gw_id})",
                            vpc_id=vpc_id,
                            region=self.region,
                            state="attached",
                            tags={"Origin": "RouteTableReference"},
                            extra_data={"gateway_type": gw_type, "discovered_via": "route_table"},
                            created_at=now,
                        )
                    )

            # 7. Discover NAT Gateways (with graceful permission fallback)
            try:
                nat_paginator = ec2.get_paginator("describe_nat_gateways")
                for page in nat_paginator.paginate():
                    for nat in page.get("NatGateways", []):
                        nat_id = nat["NatGatewayId"]
                        name, tags = _extract_name_tag(nat.get("Tags"))
                        resources.append(
                            CloudResourceSchema(
                                resource_id=nat_id,
                                account_id=self.account_id,
                                provider="AWS",
                                resource_type="GATEWAY",
                                name=name or nat_id,
                                vpc_id=nat.get("VpcId"),
                                region=self.region,
                                state=nat.get("State", "available"),
                                tags=tags,
                                extra_data={"gateway_type": "NAT_GATEWAY", "subnet_id": nat.get("SubnetId")},
                                created_at=now,
                            )
                        )
            except Exception as e:
                logger.info("Direct describe_nat_gateways call omitted or unpermitted (%s).", e)

            # 8. Discover VPC Flow Logs
            try:
                fl_paginator = ec2.get_paginator("describe_flow_logs")
                for page in fl_paginator.paginate():
                    for fl in page.get("FlowLogs", []):
                        fl_id = fl["FlowLogId"]
                        name, tags = _extract_name_tag(fl.get("Tags"))
                        resources.append(
                            CloudResourceSchema(
                                resource_id=fl_id,
                                account_id=self.account_id,
                                provider="AWS",
                                resource_type="FLOW_LOG_SUBSCRIPTION",
                                name=name or fl_id,
                                vpc_id=fl.get("ResourceId") if fl.get("ResourceId", "").startswith("vpc-") else None,
                                region=self.region,
                                state=fl.get("FlowLogStatus", "ACTIVE"),
                                tags=tags,
                                extra_data={
                                    "traffic_type": fl.get("TrafficType"),
                                    "destination_type": fl.get("LogDestinationType"),
                                    "destination": fl.get("LogDestination"),
                                    "log_format": fl.get("LogFormat"),
                                    "deliver_logs_status": fl.get("DeliverLogsStatus"),
                                },
                                created_at=now,
                            )
                        )
            except Exception as e:
                logger.warning("Error discovering flow logs in region %s: %s", self.region, e)

        except Exception as e:
            logger.error("Failed to discover AWS network resources: %s", e)

        return resources

    def get_flow_log_subscriptions(self) -> List[Dict[str, Any]]:
        """Query and return active VPC Flow Log subscriptions."""
        session, diag = self.identity_provider.get_boto3_session()
        if session is None:
            return []
        try:
            ec2 = session.client("ec2", region_name=self.region)
            resp = ec2.describe_flow_logs()
            subscriptions = []
            for fl in resp.get("FlowLogs", []):
                subscriptions.append({
                    "flow_log_id": fl.get("FlowLogId"),
                    "resource_id": fl.get("ResourceId"),
                    "traffic_type": fl.get("TrafficType"),
                    "destination_type": fl.get("LogDestinationType"),
                    "destination": fl.get("LogDestination"),
                    "status": fl.get("FlowLogStatus"),
                    "deliver_status": fl.get("DeliverLogsStatus"),
                    "log_format": fl.get("LogFormat"),
                })
            return subscriptions
        except Exception as e:
            logger.warning("Error fetching flow log subscriptions: %s", e)
            return []

    def get_health(self) -> Dict[str, Any]:
        conn = self.check_connection()
        is_healthy = conn["status"] in ("CONNECTED", "CONFIGURED")
        caller_id = conn.get("caller_identity") or {}
        return {
            "provider": "AWS",
            "healthy": is_healthy,
            "status": conn["status"],
            "region": self.region,
            "account_id": self.account_id,
            "role": caller_id.get("role"),
            "arn": caller_id.get("arn"),
            "telemetry_ready": is_healthy,
            "enforcement_ready": False,  # Strictly read-only
            "checked_at": conn["checked_at"],
        }

    def get_identity_provider(self) -> AwsIdentityProvider:
        return self.identity_provider

    def get_telemetry_provider(self) -> AwsTelemetryProvider:
        return self.telemetry_provider

    def get_enforcement_provider(self) -> AwsEnforcementProvider:
        return self.enforcement_provider
