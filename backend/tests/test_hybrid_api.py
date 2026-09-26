"""
Integration Tests for Hybrid Cloud & AWS Telemetry REST API
============================================================
Tests hybrid topology endpoints, sample fixture ingestion, and direct VPC log submission.
"""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_get_hybrid_topology_endpoint():
    """Verify GET /api/v1/hybrid/topology returns configured CIDR subnets."""
    response = client.get("/api/v1/hybrid/topology")
    assert response.status_code == 200
    data = response.json()

    assert "on_prem_cidrs" in data
    assert len(data["on_prem_cidrs"]) > 0
    assert "aws_vpc_cidrs" in data
    assert len(data["aws_vpc_cidrs"]) > 0
    assert data["is_cloud_read_only"] is True
    assert data["cloud_firewall_modification_enabled"] is False


def test_get_telemetry_status_endpoint():
    """Verify GET /api/v1/hybrid/telemetry-status returns active telemetry mode."""
    response = client.get("/api/v1/hybrid/telemetry-status")
    assert response.status_code == 200
    data = response.json()

    assert data["telemetry_mode"] == "AWS_FIXTURE"
    assert data["is_read_only"] is True


def test_list_and_ingest_sample_fixture_endpoint():
    """Verify listing and executing benchmark VPC flow log fixtures via API."""
    # List samples
    list_resp = client.get("/api/v1/hybrid/samples")
    assert list_resp.status_code == 200
    samples = list_resp.json()
    assert len(samples) >= 3

    sample_id = samples[0]["sample_id"]

    # Ingest fixture
    ingest_resp = client.post(f"/api/v1/hybrid/samples/{sample_id}/ingest?persist=true")
    assert ingest_resp.status_code == 200
    data = ingest_resp.json()

    assert data["telemetry_source"] == "AWS_VPC_FLOW_LOG_FIXTURE"
    assert data["is_fixture"] is True
    assert data["total_records_parsed"] > 0
    assert data["total_flows_aggregated"] > 0
    assert len(data["results"]) > 0

    first_result = data["results"][0]
    assert "source_zone" in first_result
    assert "traffic_direction" in first_result
    assert first_result["failed_auth_count"] == 0
    assert "prediction" in first_result


def test_ingest_direct_raw_vpc_logs_endpoint():
    """Verify direct submission of raw VPC flow log lines."""
    raw_lines = (
        "2 123456789012 eni-01 192.168.1.100 10.100.1.10 5000 80 6 20 2000 1710000000 1710000005 ACCEPT OK\n"
        "2 123456789012 eni-01 192.168.1.100 10.100.1.10 5001 80 6 30 3000 1710000005 1710000010 ACCEPT OK\n"
    )
    response = client.post(
        "/api/v1/hybrid/ingest-vpc-logs",
        json={
            "raw_log_content": raw_lines,
            "is_fixture": False,
            "persist": False,
            "source_label": "direct_api_test.log",
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert data["telemetry_source"] == "AWS_VPC_FLOW_LOG"
    assert data["is_fixture"] is False
    assert data["total_records_parsed"] == 2
    assert data["total_flows_aggregated"] == 1
