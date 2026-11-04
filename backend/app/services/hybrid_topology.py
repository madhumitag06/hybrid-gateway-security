"""
Hybrid Network Topology & Zone Classification Service
======================================================
Classifies IP addresses and bidirectional flow sessions across hybrid environments:
- ON_PREMISE (Local on-prem subnets)
- AWS_VPC (AWS cloud virtual private clouds)
- INTERNET (External unclassified networks)

Determines cross-plane traffic direction for telemetry enrichment and policy context.
"""

import ipaddress
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field
from backend.app.config import settings

NetworkZone = Literal["ON_PREMISE", "AWS_VPC", "INTERNET"]
TrafficDirection = Literal[
    "ON_PREM_TO_CLOUD",
    "CLOUD_TO_ON_PREM",
    "INTRA_CLOUD",
    "INTRA_ON_PREM",
    "INGRESS_EXTERNAL",
    "EGRESS_EXTERNAL",
    "EXTERNAL_TO_EXTERNAL",
]


class HybridNodeConfig(BaseModel):
    service: str
    role: str
    ip_address: str
    subnet: str
    zone: str
    ports: List[int] = Field(default_factory=list)
    state_provenance: str = "CONFIGURED_TOPOLOGY"


class HybridTopologySummary(BaseModel):
    """
    Topology telemetry model representing configured network zones and the virtual hybrid-cloud lab.
    """
    on_prem_cidrs: List[str]
    aws_vpc_cidrs: List[str]
    aws_region: str
    telemetry_mode: str
    is_cloud_read_only: bool = True
    cloud_firewall_modification_enabled: bool = False
    environment_representation: str = "SIMULATED_AWS_VPC_HYBRID_LAB"
    virtual_lab_subnet_onprem: str = "10.10.10.0/24"
    virtual_lab_subnet_cloud: str = "10.20.10.0/24"
    virtual_gateway_ip_onprem: str = "10.10.10.2"
    virtual_gateway_ip_cloud: str = "10.20.10.2"
    lab_enforcement_enabled: bool = False
    onprem_nodes: List[HybridNodeConfig] = Field(default_factory=list)
    gateway_nodes: List[HybridNodeConfig] = Field(default_factory=list)
    cloud_nodes: List[HybridNodeConfig] = Field(default_factory=list)


class NetworkZoneClassifier:
    """
    Deterministic CIDR-based zone classifier with caching and robust error handling.
    """

    @classmethod
    def is_ip_in_cidrs(cls, ip_str: str, cidr_list: List[str]) -> bool:
        """Checks whether an IP address belongs to any of the specified CIDR blocks."""
        if not ip_str or not cidr_list:
            return False
        try:
            target_ip = ipaddress.ip_address(ip_str.strip())
            for cidr in cidr_list:
                network = ipaddress.ip_network(cidr.strip(), strict=False)
                if target_ip in network:
                    return True
        except ValueError:
            return False
        return False

    @classmethod
    def classify_ip(
        cls,
        ip_str: str,
        on_prem_cidrs: Optional[List[str]] = None,
        aws_vpc_cidrs: Optional[List[str]] = None,
    ) -> NetworkZone:
        """
        Classifies an IP address into ON_PREMISE, AWS_VPC, or INTERNET.
        """
        on_prem = on_prem_cidrs if on_prem_cidrs is not None else settings.on_prem_cidrs
        aws_vpc = aws_vpc_cidrs if aws_vpc_cidrs is not None else settings.aws_vpc_cidrs

        # Check AWS VPC first
        if cls.is_ip_in_cidrs(ip_str, aws_vpc):
            return "AWS_VPC"

        # Check On-Premises
        if cls.is_ip_in_cidrs(ip_str, on_prem):
            return "ON_PREMISE"

        return "INTERNET"

    @classmethod
    def classify_direction(
        cls,
        src_ip: str,
        dst_ip: str,
        on_prem_cidrs: Optional[List[str]] = None,
        aws_vpc_cidrs: Optional[List[str]] = None,
    ) -> TrafficDirection:
        """
        Determines the cross-plane communication direction between two IP addresses.
        """
        src_zone = cls.classify_ip(src_ip, on_prem_cidrs, aws_vpc_cidrs)
        dst_zone = cls.classify_ip(dst_ip, on_prem_cidrs, aws_vpc_cidrs)

        if src_zone == "ON_PREMISE" and dst_zone == "AWS_VPC":
            return "ON_PREM_TO_CLOUD"
        elif src_zone == "AWS_VPC" and dst_zone == "ON_PREMISE":
            return "CLOUD_TO_ON_PREM"
        elif src_zone == "AWS_VPC" and dst_zone == "AWS_VPC":
            return "INTRA_CLOUD"
        elif src_zone == "ON_PREMISE" and dst_zone == "ON_PREMISE":
            return "INTRA_ON_PREM"
        elif src_zone == "INTERNET" and dst_zone in ["ON_PREMISE", "AWS_VPC"]:
            return "INGRESS_EXTERNAL"
        elif src_zone in ["ON_PREMISE", "AWS_VPC"] and dst_zone == "INTERNET":
            return "EGRESS_EXTERNAL"
        else:
            return "EXTERNAL_TO_EXTERNAL"

    @classmethod
    def get_topology_summary(cls) -> HybridTopologySummary:
        """
        Returns the active configuration, virtual lab node inventory, and security boundary status.
        """
        onprem_nodes = [
            HybridNodeConfig(
                service="onprem-client",
                role="Employee Workstation Client",
                ip_address="10.10.10.10",
                subnet="10.10.10.0/24",
                zone="ON_PREMISE",
                ports=[],
            ),
            HybridNodeConfig(
                service="onprem-web",
                role="Private Internal Web Application",
                ip_address="10.10.10.20",
                subnet="10.10.10.0/24",
                zone="ON_PREMISE",
                ports=[8080],
            ),
            HybridNodeConfig(
                service="onprem-workload",
                role="Private Internal Server Workload",
                ip_address="10.10.10.30",
                subnet="10.10.10.0/24",
                zone="ON_PREMISE",
                ports=[8090],
            ),
            HybridNodeConfig(
                service="traffic-generator",
                role="Controlled Lab Scenario Generator",
                ip_address="10.10.10.50",
                subnet="10.10.10.0/24",
                zone="ON_PREMISE",
                ports=[],
            ),
        ]

        gateway_nodes = [
            HybridNodeConfig(
                service="lab-router",
                role="Virtual Hybrid Network Router & Firewall (IPv4 Forwarding + tcpdump)",
                ip_address="10.10.10.2 / 10.20.10.2",
                subnet="10.10.10.0/24 ↔ 10.20.10.0/24",
                zone="GATEWAY",
                ports=[8099],
            ),
            HybridNodeConfig(
                service="gateway-api",
                role="Adaptive AI Security Gateway Control Plane (FastAPI + RandomForest + SHAP)",
                ip_address="10.30.10.10",
                subnet="10.30.10.0/24",
                zone="GATEWAY",
                ports=[8000],
            ),
            HybridNodeConfig(
                service="telemetry-sensor",
                role="PCAP Capture & Simulated AWS VPC Flow Log v2 Adapter",
                ip_address="10.30.10.20",
                subnet="10.30.10.0/24",
                zone="GATEWAY",
                ports=[],
            ),
        ]

        cloud_nodes = [
            HybridNodeConfig(
                service="cloud-client",
                role="Simulated Cloud VPC Client Workload",
                ip_address="10.20.10.10",
                subnet="10.20.10.0/24",
                zone="AWS_VPC",
                ports=[],
            ),
            HybridNodeConfig(
                service="cloud-web",
                role="Simulated Cloud VPC Web Application",
                ip_address="10.20.10.20",
                subnet="10.20.10.0/24",
                zone="AWS_VPC",
                ports=[80, 443],
            ),
            HybridNodeConfig(
                service="cloud-db",
                role="Simulated Cloud VPC Private Database Service",
                ip_address="10.20.10.30",
                subnet="10.20.10.0/24",
                zone="AWS_VPC",
                ports=[5432],
            ),
            HybridNodeConfig(
                service="cloud-workload",
                role="Simulated Cloud VPC Multi-Port Target Workload",
                ip_address="10.20.10.40",
                subnet="10.20.10.0/24",
                zone="AWS_VPC",
                ports=[80, 443, 8000, 8080, 8443, 9000],
            ),
        ]

        return HybridTopologySummary(
            on_prem_cidrs=settings.on_prem_cidrs,
            aws_vpc_cidrs=settings.aws_vpc_cidrs,
            aws_region=settings.aws_region,
            telemetry_mode=settings.aws_telemetry_mode,
            is_cloud_read_only=True,
            cloud_firewall_modification_enabled=False,
            environment_representation="SIMULATED_AWS_VPC_HYBRID_LAB",
            virtual_lab_subnet_onprem="10.10.10.0/24",
            virtual_lab_subnet_cloud="10.20.10.0/24",
            virtual_gateway_ip_onprem="10.10.10.2",
            virtual_gateway_ip_cloud="10.20.10.2",
            lab_enforcement_enabled=getattr(settings, "lab_enforcement_enabled", False),
            onprem_nodes=onprem_nodes,
            gateway_nodes=gateway_nodes,
            cloud_nodes=cloud_nodes,
        )
