"""
Unit tests for Azure Cloud Provider Adapter, NSG Flow Logs V1/V2, and NSG Rules.
"""

from backend.app.cloud.adapters.azure.adapter import AzureCloudAdapter
from backend.app.cloud.schemas.cloud_account import CloudAccountConfigSchema


def test_azure_adapter_initialization_and_validation():
    cfg = CloudAccountConfigSchema(
        account_id="sub-azure-enterprise-prod",
        provider="AZURE",
        account_name="Azure Production Enterprise",
        subscription_id="sub-azure-enterprise-prod",
        tenant_id="tenant-entra-id-01",
        region="eastus",
        enabled=True,
    )
    adapter = AzureCloudAdapter(cfg)
    is_valid, msg = adapter.validate_configuration()
    assert is_valid is True

    conn = adapter.check_connection()
    assert conn["provider"] == "AZURE"
    assert conn["status"] in ("CONNECTED", "CONFIGURED")
    assert conn["caller_identity"] is not None


def test_azure_nsg_flow_log_v2_parsing():
    cfg = CloudAccountConfigSchema(
        account_id="sub-azure-enterprise-prod",
        provider="AZURE",
    )
    adapter = AzureCloudAdapter(cfg)
    telemetry = adapter.get_telemetry_provider()

    # V2 flow tuple: time,src_ip,dst_ip,src_port,dst_port,protocol,direction,decision,state,pkts_s2d,bytes_s2d,pkts_d2s,bytes_d2s
    tuple_str = "1586542485,10.50.10.15,10.50.10.2,49200,443,T,I,A,B,10,6500,15,9800"
    raw_record = {
        "tuple": tuple_str,
        "resourceId": "/subscriptions/sub-01/resourceGroups/rg-hybrid/providers/Microsoft.Network/networkSecurityGroups/nsg-hybrid",
    }

    record = telemetry.parse_raw_log_record(raw_record)
    assert record is not None
    assert record.provider == "AZURE"
    assert record.resource_id == "nsg-hybrid"
    assert record.src_ip == "10.50.10.15"
    assert record.dst_ip == "10.50.10.2"
    assert record.src_port == 49200
    assert record.dst_port == 443
    assert record.protocol == "TCP"
    assert record.action == "ACCEPT"
    assert record.packet_count == 25  # 10 + 15
    assert record.byte_count == 16300  # 6500 + 9800


def test_azure_containment_and_resource_discovery():
    cfg = CloudAccountConfigSchema(account_id="sub-azure-enterprise-prod", provider="AZURE")
    adapter = AzureCloudAdapter(cfg)

    # Containment
    enforcement = adapter.get_enforcement_provider()
    rule = enforcement.apply_containment("203.0.113.88", "Ransomware C2 probe", dry_run=True)
    assert rule["status"] == "SIMULATED"
    assert rule["action_type"] == "NSG_SECURITY_RULE_DENY"
    assert rule["priority"] == 100

    # Resources
    resources = adapter.list_network_resources()
    types = {r.resource_type for r in resources}
    assert "VNET" in types
    assert "SUBNET" in types
    assert "NSG" in types

