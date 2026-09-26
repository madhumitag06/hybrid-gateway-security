"""
Unit Tests for Hybrid Network Topology and Zone Classifier
===========================================================
Validates CIDR classification, zone boundary isolation, and traffic direction detection.
"""

from backend.app.services.hybrid_topology import NetworkZoneClassifier


def test_classify_on_prem_ip():
    """Verify on-premise IP ranges are classified as ON_PREMISE."""
    assert NetworkZoneClassifier.classify_ip("192.168.1.100") == "ON_PREMISE"
    assert NetworkZoneClassifier.classify_ip("10.0.5.20") == "ON_PREMISE"


def test_classify_aws_vpc_ip():
    """Verify AWS VPC subnets are classified as AWS_VPC."""
    assert NetworkZoneClassifier.classify_ip("10.100.1.50") == "AWS_VPC"
    assert NetworkZoneClassifier.classify_ip("172.31.10.4") == "AWS_VPC"


def test_classify_internet_external_ip():
    """Verify external public IPs are classified as INTERNET."""
    assert NetworkZoneClassifier.classify_ip("8.8.8.8") == "INTERNET"
    assert NetworkZoneClassifier.classify_ip("198.51.100.22") == "INTERNET"
    assert NetworkZoneClassifier.classify_ip("203.0.113.88") == "INTERNET"


def test_classify_traffic_direction():
    """Verify cross-plane direction detection between zones."""
    # On-Prem -> AWS VPC
    assert NetworkZoneClassifier.classify_direction("192.168.1.50", "10.100.1.10") == "ON_PREM_TO_CLOUD"

    # AWS VPC -> On-Prem
    assert NetworkZoneClassifier.classify_direction("10.100.1.10", "192.168.1.50") == "CLOUD_TO_ON_PREM"

    # AWS VPC -> AWS VPC
    assert NetworkZoneClassifier.classify_direction("10.100.1.10", "10.100.2.20") == "INTRA_CLOUD"

    # On-Prem -> On-Prem
    assert NetworkZoneClassifier.classify_direction("192.168.1.50", "192.168.2.60") == "INTRA_ON_PREM"

    # Internet -> AWS VPC
    assert NetworkZoneClassifier.classify_direction("203.0.113.5", "10.100.1.10") == "INGRESS_EXTERNAL"

    # AWS VPC -> Internet
    assert NetworkZoneClassifier.classify_direction("10.100.1.10", "203.0.113.5") == "EGRESS_EXTERNAL"


def test_custom_cidr_overrides():
    """Verify custom CIDR parameters override defaults safely."""
    custom_on_prem = ["10.20.0.0/16"]
    custom_aws_vpc = ["10.30.0.0/16"]

    assert NetworkZoneClassifier.classify_ip("10.20.1.1", on_prem_cidrs=custom_on_prem, aws_vpc_cidrs=custom_aws_vpc) == "ON_PREMISE"
    assert NetworkZoneClassifier.classify_ip("10.30.1.1", on_prem_cidrs=custom_on_prem, aws_vpc_cidrs=custom_aws_vpc) == "AWS_VPC"
    assert NetworkZoneClassifier.classify_ip("192.168.1.1", on_prem_cidrs=custom_on_prem, aws_vpc_cidrs=custom_aws_vpc) == "INTERNET"


def test_invalid_ip_handling():
    """Verify invalid or malformed IP strings fall back safely to INTERNET."""
    assert NetworkZoneClassifier.classify_ip("invalid-ip-string") == "INTERNET"
    assert NetworkZoneClassifier.classify_ip("") == "INTERNET"
    assert NetworkZoneClassifier.classify_direction("not-an-ip", "10.100.1.1") == "INGRESS_EXTERNAL"
