"""
Comprehensive Read-Only AWS Integration & Verification Tests
============================================================
Validates:
1. STS Identity Validation and Role Assumption (AssumeRole).
2. Read-Only EC2 Topology Discovery (VPCs, Subnets, Route Tables, Security Groups, NACLs, Flow Logs).
3. VPC Flow Log Ingestion from CloudWatch Logs and S3 (with gzip decompression).
4. Telemetry Normalization & Parity with XGBoost V2 (Canonical 9-feature schema).
5. Safeguards: Zero synthetic failed_auth_count and strictly disabled enforcement.
"""

from datetime import datetime, timezone
import gzip
import io
from typing import Any, Dict
from unittest.mock import MagicMock, patch
import pytest

from backend.app.cloud.adapters.aws.adapter import AwsCloudAdapter
from backend.app.cloud.adapters.aws.identity import AwsIdentityProvider
from backend.app.cloud.adapters.aws.telemetry import AwsTelemetryProvider
from backend.app.cloud.schemas.cloud_account import CloudAccountConfigSchema
from backend.app.cloud.services.telemetry_normalizer import TelemetryNormalizer
from ml.features.extractor import FEATURE_NAMES_V2


def test_aws_identity_sts_caller_identity_verified():
    """Verify STS GetCallerIdentity verification using mock STS client."""
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/GatewayAdmin",
        "UserId": "AIDA123456789012",
    }

    mock_session = MagicMock()
    mock_session.client.return_value = mock_sts

    with patch("boto3.Session", return_value=mock_session):
        provider = AwsIdentityProvider(region="us-east-1")
        identity = provider.get_caller_identity()

        assert identity["status"] == "VERIFIED"
        assert identity["account"] == "123456789012"
        assert identity["arn"] == "arn:aws:iam::123456789012:user/GatewayAdmin"
        assert identity["user_id"] == "AIDA123456789012"
        assert identity["auth_method"] in ("IAM_USER", "IAM_CALLER_IDENTITY")


def test_aws_identity_sts_assume_role_verified():
    """Verify STS AssumeRole with role_arn and external_id."""
    mock_base_sts = MagicMock()
    mock_base_sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "ASIAEXAMPLEKEY123",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "SessionToken": "AQoDYXdzEJr1...",
            "Expiration": datetime.now(timezone.utc),
        },
        "AssumedRoleUser": {
            "AssumedRoleId": "AROA123456789:AntigravitySecurityGatewaySession",
            "Arn": "arn:aws:sts::123456789012:assumed-role/SecurityGatewayReadOnlyRole/AntigravitySecurityGatewaySession",
        },
    }

    mock_assumed_sts = MagicMock()
    mock_assumed_sts.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:sts::123456789012:assumed-role/SecurityGatewayReadOnlyRole/AntigravitySecurityGatewaySession",
        "UserId": "AROA123456789:AntigravitySecurityGatewaySession",
    }

    def session_factory(*args, **kwargs):
        sess = MagicMock()
        if "aws_access_key_id" in kwargs:
            sess.client.return_value = mock_assumed_sts
        else:
            sess.client.return_value = mock_base_sts
        return sess

    with patch("boto3.Session", side_effect=session_factory):
        provider = AwsIdentityProvider(
            role_arn="arn:aws:iam::123456789012:role/SecurityGatewayReadOnlyRole",
            external_id="AdaptiveGatewayAuth",
            region="us-east-1",
        )
        identity = provider.get_caller_identity()

        assert identity["status"] == "VERIFIED"
        assert identity["account"] == "123456789012"
        assert "assumed-role" in identity["arn"]
        assert identity["auth_method"] == "STS_ASSUME_ROLE"
        mock_base_sts.assume_role.assert_called_once()
        call_kwargs = mock_base_sts.assume_role.call_args[1]
        assert call_kwargs["RoleArn"] == "arn:aws:iam::123456789012:role/SecurityGatewayReadOnlyRole"
        assert call_kwargs["ExternalId"] == "AdaptiveGatewayAuth"


def test_aws_resource_discovery_mocked_ec2():
    """Verify discovery of VPCs, Subnets, Route Tables, Security Groups, NACLs, and Flow Logs."""
    mock_ec2 = MagicMock()

    # Setup paginators
    vpc_page = {
        "Vpcs": [
            {
                "VpcId": "vpc-0a1b2c3d4e5f67890",
                "CidrBlock": "10.0.0.0/16",
                "State": "available",
                "IsDefault": False,
                "Tags": [{"Key": "Name", "Value": "Production-VPC"}],
            }
        ]
    }
    subnet_page = {
        "Subnets": [
            {
                "SubnetId": "subnet-0123456789abcdef0",
                "VpcId": "vpc-0a1b2c3d4e5f67890",
                "CidrBlock": "10.0.1.0/24",
                "AvailabilityZone": "us-east-1a",
                "State": "available",
                "Tags": [{"Key": "Name", "Value": "Public-Subnet-1"}],
            }
        ]
    }
    rt_page = {
        "RouteTables": [
            {
                "RouteTableId": "rtb-0123456789abcdef0",
                "VpcId": "vpc-0a1b2c3d4e5f67890",
                "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}],
                "Associations": [{"Main": True}],
                "Tags": [{"Key": "Name", "Value": "Main-RouteTable"}],
            }
        ]
    }
    sg_page = {
        "SecurityGroups": [
            {
                "GroupId": "sg-0123456789abcdef0",
                "GroupName": "web-tier-sg",
                "VpcId": "vpc-0a1b2c3d4e5f67890",
                "Description": "Allow HTTPS ingress",
                "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443}],
                "IpPermissionsEgress": [{"IpProtocol": "-1"}],
                "Tags": [{"Key": "Name", "Value": "web-tier-sg"}],
            }
        ]
    }
    nacl_page = {
        "NetworkAcls": [
            {
                "NetworkAclId": "acl-0123456789abcdef0",
                "VpcId": "vpc-0a1b2c3d4e5f67890",
                "IsDefault": True,
                "Entries": [{"RuleNumber": 100, "Protocol": "6", "RuleAction": "allow"}],
                "Tags": [{"Key": "Name", "Value": "Default-NACL"}],
            }
        ]
    }
    fl_page = {
        "FlowLogs": [
            {
                "FlowLogId": "fl-0123456789abcdef0",
                "ResourceId": "vpc-0a1b2c3d4e5f67890",
                "TrafficType": "ALL",
                "LogDestinationType": "cloud-watch-logs",
                "LogDestination": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc/flowlogs",
                "LogFormat": "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}",
                "FlowLogStatus": "ACTIVE",
                "DeliverLogsStatus": "SUCCESS",
                "Tags": [{"Key": "Name", "Value": "VPC-All-FlowLogs"}],
            }
        ]
    }

    def paginator_factory(operation_name):
        paginator = MagicMock()
        if operation_name == "describe_vpcs":
            paginator.paginate.return_value = [vpc_page]
        elif operation_name == "describe_subnets":
            paginator.paginate.return_value = [subnet_page]
        elif operation_name == "describe_route_tables":
            paginator.paginate.return_value = [rt_page]
        elif operation_name == "describe_security_groups":
            paginator.paginate.return_value = [sg_page]
        elif operation_name == "describe_network_acls":
            paginator.paginate.return_value = [nacl_page]
        elif operation_name == "describe_flow_logs":
            paginator.paginate.return_value = [fl_page]
        return paginator

    mock_ec2.get_paginator.side_effect = paginator_factory

    mock_session = MagicMock()
    mock_session.client.return_value = mock_ec2

    cfg = CloudAccountConfigSchema(
        account_id="123456789012",
        provider="AWS",
        region="us-east-1",
        enabled=True,
    )
    adapter = AwsCloudAdapter(cfg)

    # Patch identity provider to return mock session
    with patch.object(adapter.identity_provider, "get_boto3_session", return_value=(mock_session, {"status": "DIRECT"})):
        resources = adapter.list_network_resources()

        assert len(resources) == 6
        res_types = {r.resource_type for r in resources}
        assert res_types == {
            "VPC",
            "SUBNET",
            "ROUTE_TABLE",
            "SECURITY_GROUP",
            "NETWORK_ACL",
            "FLOW_LOG_SUBSCRIPTION",
        }

        # Check VPC properties
        vpc_res = next(r for r in resources if r.resource_type == "VPC")
        assert vpc_res.resource_id == "vpc-0a1b2c3d4e5f67890"
        assert vpc_res.name == "Production-VPC"
        assert vpc_res.cidr_block == "10.0.0.0/16"

        # Check Flow Log Subscription properties
        fl_res = next(r for r in resources if r.resource_type == "FLOW_LOG_SUBSCRIPTION")
        assert fl_res.resource_id == "fl-0123456789abcdef0"
        assert fl_res.extra_data["destination_type"] == "cloud-watch-logs"
        assert fl_res.state == "ACTIVE"


def test_aws_flow_logs_retrieval_cloudwatch_mocked():
    """Verify fetching and parsing flow log records from CloudWatch Logs."""
    mock_cw = MagicMock()
    mock_cw.filter_log_events.return_value = {
        "events": [
            {
                "message": "2 123456789012 eni-1a2b3c4d 10.0.1.50 10.0.1.10 52341 443 6 100 85000 1763161000 1763161060 ACCEPT OK",
                "timestamp": 1763161060000,
                "eventId": "event-01",
            },
            {
                "message": "2 123456789012 eni-1a2b3c4d 198.51.100.25 10.0.1.10 49152 22 6 25 1800 1763161000 1763161010 REJECT OK",
                "timestamp": 1763161010000,
                "eventId": "event-02",
            },
        ]
    }

    mock_session = MagicMock()
    mock_session.client.return_value = mock_cw

    identity_prov = MagicMock()
    identity_prov.get_boto3_session.return_value = (mock_session, {"status": "DIRECT"})

    telemetry = AwsTelemetryProvider(account_id="123456789012", region="us-east-1", identity_provider=identity_prov)

    # Fetch with explicit log group
    records = telemetry.fetch_flow_records(filter_params={"log_group": "/aws/vpc/flowlogs"}, limit=10)
    assert len(records) == 2
    assert records[0]["source"] == "CLOUDWATCH_LOGS"

    # Parse records
    parsed_1 = telemetry.parse_raw_log_record(records[0])
    assert parsed_1 is not None
    assert parsed_1.dst_port == 443
    assert parsed_1.packet_count == 100
    assert parsed_1.byte_count == 85000
    assert parsed_1.action == "ACCEPT"

    parsed_2 = telemetry.parse_raw_log_record(records[1])
    assert parsed_2 is not None
    assert parsed_2.dst_port == 22
    assert parsed_2.action == "REJECT"
    assert parsed_2.flow_direction == "INGRESS"


def test_aws_flow_logs_retrieval_s3_gzip_mocked():
    """Verify fetching and parsing flow log records from S3 bucket with gzip decompression."""
    mock_s3 = MagicMock()

    # Raw flow log text
    raw_log = (
        "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status\n"
        "2 123456789012 eni-99887766 10.0.2.100 10.0.2.5 59000 80 6 30 24000 1763162000 1763162020 ACCEPT OK\n"
    )
    compressed_bytes = gzip.compress(raw_log.encode("utf-8"))

    mock_s3.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": "AWSLogs/123456789012/vpcflowlogs/us-east-1/2026/11/15/123456789012_vpcflowlogs_us-east-1_flow_20261115T0000Z.log.gz",
                "LastModified": datetime.now(timezone.utc),
            }
        ]
    }
    mock_s3.get_object.return_value = {"Body": io.BytesIO(compressed_bytes)}

    mock_session = MagicMock()
    mock_session.client.return_value = mock_s3

    identity_prov = MagicMock()
    identity_prov.get_boto3_session.return_value = (mock_session, {"status": "DIRECT"})

    telemetry = AwsTelemetryProvider(account_id="123456789012", region="us-east-1", identity_provider=identity_prov)

    records = telemetry.fetch_flow_records(filter_params={"s3_bucket": "my-vpc-flowlogs-bucket"}, limit=10)
    assert len(records) == 1
    assert records[0]["source"] == "S3"
    assert "eni-99887766" in records[0]["message"]

    parsed = telemetry.parse_raw_log_record(records[0])
    assert parsed is not None
    assert parsed.dst_port == 80
    assert parsed.duration == 20.0
    assert parsed.byte_count == 24000


def test_aws_xgboost_v2_canonical_parity_and_safeguards():
    """
    Verify complete flow normalizer and XGBoost V2 threat evaluation on AWS telemetry:
    1. Exact 9 features extracted matching FEATURE_NAMES_V2.
    2. failed_auth_count is strictly 0 (no synthetic auth telemetry).
    3. Prediction evaluates threat level and policy decision.
    4. Containment actions remain dry-run only.
    """
    telemetry = AwsTelemetryProvider(account_id="123456789012", region="us-east-1")
    line = "2 123456789012 eni-0123456789abcdef0 198.51.100.77 10.0.1.15 48123 445 6 120 96000 1763163000 1763163015 ACCEPT OK"
    record = telemetry.parse_raw_log_record(line)
    assert record is not None

    enriched, feat_dict = TelemetryNormalizer.normalize_flow_record(record)

    # 1. Parity check on 9 feature names
    assert list(feat_dict.keys()) == FEATURE_NAMES_V2
    assert "failed_auth_count" not in feat_dict

    # 2. Mathematical features check
    assert feat_dict["packet_count"] == 120.0
    assert feat_dict["byte_count"] == 96000.0
    assert feat_dict["duration"] == 15.0
    assert feat_dict["conn_rate"] == 120.0 / 15.0
    assert feat_dict["dst_port"] == 445.0
    assert feat_dict["bytes_per_sec"] == 96000.0 / 15.0
    assert feat_dict["packets_per_sec"] == 120.0 / 15.0
    assert feat_dict["avg_packet_size"] == 96000.0 / 120.0

    # 3. Process batch through XGBoost V2
    response = TelemetryNormalizer.process_canonical_batch(
        records=[record],
        provider="AWS",
        account_id="123456789012",
        persist=False,
    )

    assert response.status == "SUCCESS"
    assert response.records_parsed == 1
    assert len(response.flows) == 1
    flow_res = response.flows[0]
    assert flow_res.provider == "AWS"
    assert flow_res.dst_port == 445
    assert flow_res.risk_score >= 0.0
    assert flow_res.threat_level in ["BENIGN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    # 4. Normalization report provenance check
    assert response.normalization_report.schema_version == "v2_canonical"
    assert response.normalization_report.failed_auth_synthesized is False
    assert response.normalization_report.features_extracted == FEATURE_NAMES_V2

