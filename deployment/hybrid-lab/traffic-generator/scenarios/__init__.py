"""
Bounded Hybrid-Cloud Traffic Generation Scenarios
=================================================
All traffic is strictly restricted to isolated lab subnets (10.10.10.0/24 and 10.20.10.0/24).
"""

import ipaddress

ALLOWED_LAB_NETWORKS = [
    ipaddress.ip_network("10.10.10.0/24"),
    ipaddress.ip_network("10.20.10.0/24"),
]


def assert_lab_ip(ip_str: str) -> None:
    """
    Safety guardrail: Raises ValueError if an IP address is outside the isolated
    Docker hybrid lab subnets (10.10.10.0/24 and 10.20.10.0/24).
    """
    addr = ipaddress.ip_address(ip_str.strip())
    if addr.is_loopback or not any(addr in net for net in ALLOWED_LAB_NETWORKS):
        raise ValueError(
            f"Safety violation: Target/Source IP '{ip_str}' is outside isolated lab subnets "
            "(10.10.10.0/24, 10.20.10.0/24)."
        )

