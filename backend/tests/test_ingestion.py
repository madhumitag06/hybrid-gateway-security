"""
Phase 4 Traffic Ingestion & Flow Capture Test Suite
===================================================
Tests PCAP parsing, bidirectional flow aggregation, feature extraction,
Phase 1 ThreatPredictor integration, and PostgreSQL persistence.
"""

import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.ingest import PcapIngestionResponse, IngestionStatusResponse
from backend.app.services.flow_aggregator import FlowAggregator, PacketRecord
from backend.app.services.ingestion_service import IngestionService
from backend.app.services.sample_pcap_generator import SAMPLE_DIR, ensure_sample_pcaps


@pytest.fixture(scope="module", autouse=True)
def setup_samples():
    """Ensure sample PCAP files exist before running tests."""
    ensure_sample_pcaps()


# ==========================================
# 1. Flow Aggregator Unit Tests
# ==========================================

def test_flow_aggregator_bidirectional_session():
    """
    Verify that packets sent in both directions between two endpoints are correctly
    aggregated into a single bidirectional flow session with summed metrics.
    """
    aggregator = FlowAggregator(inactivity_timeout=10.0, max_flow_duration=30.0)

    # Packet 1: Client -> Server
    p1 = PacketRecord(
        timestamp=100.0,
        src_ip="192.168.1.50",
        dst_ip="10.100.0.1",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        length_bytes=100,
    )
    aggregator.add_packet(p1)

    # Packet 2: Server -> Client (reverse direction of same session)
    p2 = PacketRecord(
        timestamp=100.5,
        src_ip="10.100.0.1",
        dst_ip="192.168.1.50",
        src_port=443,
        dst_port=50000,
        protocol="TCP",
        length_bytes=500,
    )
    aggregator.add_packet(p2)

    completed = aggregator.flush_all()
    assert len(completed) == 1, "Should combine bidirectional packets into 1 session"
    session = completed[0]
    assert session.packet_count == 2
    assert session.byte_count == 600
    assert pytest.approx(session.duration, 0.001) == 0.5

    # Feature extraction check
    flow_input, src_ip, dst_ip = aggregator.extract_features(session)
    assert src_ip == "192.168.1.50"
    assert dst_ip == "10.100.0.1"
    assert flow_input.dst_port == 443
    assert flow_input.packet_count == 2
    assert flow_input.byte_count == 600
    assert flow_input.failed_auth_count == 0  # Conservative honest limitation


def test_flow_aggregator_unique_dst_ports_tracking():
    """
    Verify that scanning multiple destination ports increments the unique_dst_ports count.
    """
    aggregator = FlowAggregator()

    for idx, dport in enumerate([80, 443, 22, 8080, 3389]):
        p = PacketRecord(
            timestamp=100.0 + idx * 0.01,
            src_ip="192.168.1.77",
            dst_ip="10.100.4.12",
            src_port=60000 + idx,
            dst_port=dport,
            protocol="TCP",
            length_bytes=64,
        )
        aggregator.add_packet(p)

    sessions = aggregator.flush_all()
    assert len(sessions) == 5

    # Check that each flow sees all 5 probed destination ports for the source IP
    for s in sessions:
        flow_input, src, dst = aggregator.extract_features(s)
        assert flow_input.unique_dst_ports == 5


def test_flow_aggregator_inactivity_timeout():
    """
    Verify that an inactive session is flushed when a new packet arrives after the inactivity timeout.
    """
    aggregator = FlowAggregator(inactivity_timeout=5.0)

    p1 = PacketRecord(
        timestamp=100.0,
        src_ip="192.168.1.10",
        dst_ip="10.100.1.1",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        length_bytes=100,
    )
    aggregator.add_packet(p1)

    # Packet 2 arrives 10 seconds later (exceeds 5.0s timeout)
    p2 = PacketRecord(
        timestamp=110.0,
        src_ip="192.168.1.10",
        dst_ip="10.100.1.1",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        length_bytes=200,
    )
    flushed = aggregator.add_packet(p2)

    assert flushed is not None, "Previous session should have been flushed due to inactivity"
    assert flushed.packet_count == 1
    assert flushed.byte_count == 100

    all_sessions = aggregator.flush_all()
    assert len(all_sessions) == 2


# ==========================================
# 2. Ingestion Service & PCAP Parsing Tests
# ==========================================

def test_ingest_benign_pcap_service():
    """
    Verify end-to-end parsing of benign HTTPS PCAP fixture without persistence.
    """
    pcap_path = SAMPLE_DIR / "benign_web.pcap"
    response = IngestionService.ingest_pcap_file(pcap_path, "benign_web.pcap", persist=False)

    assert isinstance(response, PcapIngestionResponse)
    assert response.source_type == "PCAP_INGESTION"
    assert response.is_demo is False
    assert response.metrics.packets_processed > 0
    assert response.flows_evaluated == 1
    assert response.results[0].prediction.attack_type == "BENIGN"
    assert response.results[0].prediction.risk_score < 40


def test_ingest_port_scan_pcap_service():
    """
    Verify end-to-end parsing and high risk detection for port scan PCAP fixture.
    """
    pcap_path = SAMPLE_DIR / "port_scan.pcap"
    response = IngestionService.ingest_pcap_file(pcap_path, "port_scan.pcap", persist=False)

    assert response.flows_evaluated >= 20
    assert response.high_risk_flows_count > 0
    # First flow should be identified as port scan with high risk
    first_pred = response.results[0].prediction
    assert first_pred.attack_type == "PORT_SCAN"
    assert first_pred.risk_score >= 70
    assert first_pred.action_recommendation in ["Restrict", "Block"]


def test_ingest_traffic_spike_pcap_service():
    """
    Verify end-to-end parsing and classification of volumetric traffic spike PCAP.
    """
    pcap_path = SAMPLE_DIR / "traffic_spike.pcap"
    response = IngestionService.ingest_pcap_file(pcap_path, "traffic_spike.pcap", persist=False)

    assert response.flows_evaluated >= 1
    pred = response.results[0].prediction
    assert pred.attack_type == "TRAFFIC_SPIKE"
    assert pred.risk_score >= 70


def test_ingest_empty_pcap_raises_error(tmp_path):
    """
    Verify that an empty (0 byte) PCAP file raises a 400 Bad Request error.
    """
    empty_file = tmp_path / "empty.pcap"
    empty_file.write_bytes(b"")

    with pytest.raises(Exception) as exc_info:
        IngestionService.ingest_pcap_file(empty_file, "empty.pcap", persist=False)
    assert "empty" in str(exc_info.value).lower()


def test_ingest_corrupted_pcap_raises_error(tmp_path):
    """
    Verify that a corrupted non-PCAP file raises an unprocessable entity error.
    """
    corrupt_file = tmp_path / "corrupt.pcap"
    corrupt_file.write_bytes(b"THIS_IS_NOT_A_VALID_PCAP_HEADER_DATA_1234567890")

    with pytest.raises(Exception) as exc_info:
        IngestionService.ingest_pcap_file(corrupt_file, "corrupt.pcap", persist=False)
    assert "packet stream" in str(exc_info.value).lower() or "failed" in str(exc_info.value).lower()


# ==========================================
# 3. FastAPI Ingestion Endpoints Tests
# ==========================================

def test_api_get_ingestion_status():
    """
    Test GET /api/v1/ingest/status.
    """
    client = TestClient(app)
    response = client.get("/api/v1/ingest/status")
    assert response.status_code == 200
    data = response.json()
    assert data["engine_status"] == "ONLINE"
    assert data["active_mode"] == "PCAP_INGESTION_PRIMARY"
    assert "pcap" in data["supported_formats"]
    assert data["max_upload_size_mb"] == 15


def test_api_list_samples():
    """
    Test GET /api/v1/ingest/samples.
    """
    client = TestClient(app)
    response = client.get("/api/v1/ingest/samples")
    assert response.status_code == 200
    samples = response.json()
    assert len(samples) >= 3
    filenames = [s["filename"] for s in samples]
    assert "benign_web.pcap" in filenames
    assert "port_scan.pcap" in filenames
    assert "traffic_spike.pcap" in filenames


def test_api_ingest_sample_endpoint_and_persist():
    """
    Test POST /api/v1/ingest/samples/{filename} with persistence to PostgreSQL.
    """
    client = TestClient(app)
    response = client.post("/api/v1/ingest/samples/benign_web.pcap?persist=true")
    assert response.status_code == 200
    data = response.json()
    assert data["source_type"] == "PCAP_INGESTION"
    assert data["is_demo"] is False
    assert data["flows_evaluated"] >= 1
    assert data["results"][0]["persisted_event_id"] is not None

    event_id = data["results"][0]["persisted_event_id"]

    # Verify event is queryable via GET /api/v1/events/{id}
    evt_resp = client.get(f"/api/v1/events/{event_id}")
    assert evt_resp.status_code == 200
    evt_data = evt_resp.json()
    assert evt_data["id"] == event_id
    assert evt_data["is_demo"] is False
    assert evt_data["source"] == "192.168.1.50"
    assert evt_data["destination"] == "10.100.0.1"


def test_api_upload_pcap_multipart():
    """
    Test POST /api/v1/ingest/pcap multipart upload.
    """
    client = TestClient(app)
    pcap_path = SAMPLE_DIR / "port_scan.pcap"
    pcap_bytes = pcap_path.read_bytes()

    files = {"file": ("uploaded_portscan.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}
    data = {"persist": "false"}

    response = client.post("/api/v1/ingest/pcap", files=files, data=data)
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["filename"] == "uploaded_portscan.pcap"
    assert res_json["flows_evaluated"] >= 20
    assert res_json["high_risk_flows_count"] > 0


def test_api_upload_invalid_extension():
    """
    Test that uploading an invalid file extension (e.g., .txt) is rejected with 400.
    """
    client = TestClient(app)
    files = {"file": ("malicious.exe", io.BytesIO(b"MZ_EXECUTABLE_DATA"), "application/octet-stream")}
    response = client.post("/api/v1/ingest/pcap", files=files, data={"persist": "false"})
    assert response.status_code == 400
    assert "invalid file extension" in response.json()["detail"].lower()
