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
from typing import List, Literal, Optional
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


class HybridTopologySummary(BaseModel):
    """
    Topology telemetry model representing configured network zones.
    """
    on_prem_cidrs: List[str]
    aws_vpc_cidrs: List[str]
    aws_region: str
    telemetry_mode: str
    is_cloud_read_only: bool = True
    cloud_firewall_modification_enabled: bool = False


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
        Returns the active configuration and security boundary status.
        """
        return HybridTopologySummary(
            on_prem_cidrs=settings.on_prem_cidrs,
            aws_vpc_cidrs=settings.aws_vpc_cidrs,
            aws_region=settings.aws_region,
            telemetry_mode=settings.aws_telemetry_mode,
            is_cloud_read_only=True,
            cloud_firewall_modification_enabled=False,
        )
