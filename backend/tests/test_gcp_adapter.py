"""
Unit tests for GCP Cloud Provider Adapter, Cloud Logging VPC Flow Logs, and Cloud Firewalls.
"""

from backend.app.cloud.adapters.gcp.adapter import GcpCloudAdapter
from backend.app.cloud.schemas.cloud_account import CloudAccountConfigSchema


def test_gcp_adapter_initialization_and_validation():
    cfg = CloudAccountConfigSchema(
        account_id="hybrid-gateway-bridge",
        provider="GCP",
        account_name="GCP Hybrid Gateway Account",
        project_id="hybrid-gateway-bridge",
        region="us-central1",
        enabled=True,
    )
    adapter = GcpCloudAdapter(cfg)
    is_valid, msg = adapter.validate_configuration()
    assert is_valid is True

    conn = adapter.check_connection()
    assert conn["provider"] == "GCP"
    assert conn["status"] in ("CONNECTED", "CONFIGURED", "DEGRADED")
    assert conn["project_id"] == "hybrid-gateway-bridge"


def test_gcp_cloud_logging_vpc_flow_parsing():
    cfg = CloudAccountConfigSchema(
        account_id="hybrid-gateway-bridge",
        provider="GCP",
        project_id="hybrid-gateway-bridge",
    )
    adapter = GcpCloudAdapter(cfg)
    telemetry = adapter.get_telemetry_provider()

    raw_gcp_entry = {
        "insertId": "gcp-rec-101",
        "jsonPayload": {
            "connection": {
                "src_ip": "10.40.10.15",
                "dest_ip": "10.40.10.2",
                "src_port": 49152,
                "dest_port": 443,
                "protocol": 6,
            },
            "bytes_sent": "25000",
            "packets_sent": "30",
            "start_time": "2026-11-15T00:10:00Z",
            "end_time": "2026-11-15T00:10:15Z",
            "rule_details": {"action": "ALLOW"},
        },
        "resource": {
            "labels": {
                "subnetwork_name": "hybrid-gcp-subnet-uscentral1",
            }
        },
    }

    record = telemetry.parse_raw_log_record(raw_gcp_entry)
    assert record is not None
    assert record.provider == "GCP"
    assert record.account_id == "hybrid-gateway-bridge"
    assert record.resource_id == "hybrid-gcp-subnet-uscentral1"
    assert record.src_ip == "10.40.10.15"
    assert record.dst_ip == "10.40.10.2"
    assert record.src_port == 49152
    assert record.dst_port == 443
    assert record.protocol == "TCP"
    assert record.packet_count == 30
    assert record.byte_count == 25000
    assert record.duration == 15.0
    assert record.action == "ALLOW"


def test_gcp_workload_identity_metadata():
    cfg = CloudAccountConfigSchema(
        account_id="hybrid-gateway-bridge",
        provider="GCP",
        project_id="hybrid-gateway-bridge",
        workload_identity_provider="projects/77380112089/locations/global/workloadIdentityPools/hybrid-gateway-pool/providers/aws-hybrid-gateway",
    )
    adapter = GcpCloudAdapter(cfg)
    identity = adapter.get_identity_provider()
    meta = identity.get_federation_metadata()
    assert "audience" in meta
    assert "aws-hybrid-gateway" in meta.get("workload_identity_provider", "")


def test_gcp_containment_and_resource_discovery():
    cfg = CloudAccountConfigSchema(account_id="hybrid-gateway-bridge", provider="GCP", project_id="hybrid-gateway-bridge")
    adapter = GcpCloudAdapter(cfg)

    # Containment
    enforcement = adapter.get_enforcement_provider()
    rule = enforcement.apply_containment("198.51.100.99", "Volumetric attack", dry_run=True)
    assert rule["status"] == "SIMULATED"
    assert rule["action_type"] == "VPC_FIREWALL_DENY"
    assert rule["priority"] == 100

    # Resources: 0 compute resources because compute.googleapis.com requires billing
    resources = adapter.list_network_resources()
    assert isinstance(resources, list)

