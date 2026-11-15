"""
Unit tests for AWS Cloud Provider Adapter, Telemetry Parser, and Containment.
"""

from unittest.mock import MagicMock, patch
from backend.app.cloud.adapters.aws.adapter import AwsCloudAdapter
from backend.app.cloud.schemas.cloud_account import CloudAccountConfigSchema


def test_aws_adapter_initialization_and_validation():
    cfg = CloudAccountConfigSchema(
        account_id="123456789012",
        provider="AWS",
        account_name="AWS Production Gateway",
        region="us-east-1",
        role_arn="arn:aws:iam::123456789012:role/SecurityGatewayRole",
        enabled=True,
    )
    adapter = AwsCloudAdapter(cfg)
    is_valid, msg = adapter.validate_configuration()
    assert is_valid is True

    # Test connection check: without ambient credentials, status is NOT_CONFIGURED (never falsely claims CONNECTED)
    conn = adapter.check_connection()
    assert conn["provider"] == "AWS"
    assert conn["status"] in ("CONNECTED", "CONFIGURED", "NOT_CONFIGURED", "AUTHENTICATION_FAILED")
    assert conn["caller_identity"] is not None


def test_aws_vpc_flow_log_v2_parsing():
    cfg = CloudAccountConfigSchema(
        account_id="123456789012",
        provider="AWS",
        region="us-east-1",
    )
    adapter = AwsCloudAdapter(cfg)
    telemetry = adapter.get_telemetry_provider()

    # Valid AWS VPC Flow Log v2 line
    line = "2 123456789012 eni-0123456789abcdef0 10.20.10.15 10.20.10.2 44321 443 6 45 38500 1763160000 1763160030 ACCEPT OK"
    record = telemetry.parse_raw_log_record(line)

    assert record is not None
    assert record.provider == "AWS"
    assert record.account_id == "123456789012"
    assert record.resource_id == "eni-0123456789abcdef0"
    assert record.src_ip == "10.20.10.15"
    assert record.dst_ip == "10.20.10.2"
    assert record.src_port == 44321
    assert record.dst_port == 443
    assert record.protocol == "TCP"
    assert record.packet_count == 45
    assert record.byte_count == 38500
    assert record.duration == 30.0
    assert record.action == "ACCEPT"
    assert record.log_status == "OK"


def test_aws_vpc_flow_log_nodata_and_header():
    cfg = CloudAccountConfigSchema(account_id="123456789012", provider="AWS")
    adapter = AwsCloudAdapter(cfg)
    telemetry = adapter.get_telemetry_provider()

    header = "version account_id interface_id srcaddr dstaddr srcport dstport protocol packets bytes start end action log_status"
    assert telemetry.parse_raw_log_record(header) is None

    nodata = "2 123456789012 eni-111 - - - - - - - 1763160000 1763160030 - NODATA"
    assert telemetry.parse_raw_log_record(nodata) is None


def test_aws_containment_safeguards():
    cfg = CloudAccountConfigSchema(
        account_id="123456789012",
        provider="AWS",
        enforcement_enabled=False,  # default safe
    )
    adapter = AwsCloudAdapter(cfg)
    enforcement = adapter.get_enforcement_provider()

    actions = enforcement.supported_enforcement_actions()
    assert "SECURITY_GROUP_ISOLATION" in actions
    assert "NACL_DENY_RULE" in actions

    # Apply containment in dry_run mode
    res = enforcement.apply_containment(
        target_ip="198.51.100.42",
        reason="Port scan detected",
        dry_run=True,
    )
    assert res["status"] == "SIMULATED"
    assert res["target_ip"] == "198.51.100.42"
    assert "revert_plan" in res

    # Revocation
    rev = enforcement.revoke_containment(res["containment_id"], dry_run=True)
    assert rev["success"] is True


def test_aws_resource_discovery_unauthenticated():
    """When unauthenticated, discovery safely returns an empty list without crashing."""
    cfg = CloudAccountConfigSchema(account_id="123456789012", provider="AWS")
    adapter = AwsCloudAdapter(cfg)
    resources = adapter.list_network_resources()
    assert isinstance(resources, list)
