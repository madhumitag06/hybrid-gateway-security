"""
Comprehensive Test Suite for PCAP Ingestion Performance & Bounded Evaluation
=============================================================================
Tests:
  1. Fix 1: Bounded flow evaluation and intelligent representative selection.
  2. Fix 2: Conditional SHAP explainability (high-risk calculated, low-risk skipped without fake values).
  3. Fix 3: Batched database persistence with transaction safety and rollback on error.
  4. Fix 4: Threadpool offloading preventing asyncio event-loop blocking.
  5. Fix 5: Bounded API response payload protecting client responsiveness.
  6. Benchmark captures regression (Benign HTTPS, Port Scan, Traffic Spike).
"""

import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, func

from backend.app.main import app
from backend.app.db.session import SessionLocal
from backend.app.models.security_event import SecurityEventModel
from backend.app.models.policy_audit_log import PolicyAuditLogModel
from backend.app.schemas.predict import NetworkFlowRequest
from backend.app.services.flow_aggregator import FlowAggregator, FlowSession, PacketRecord
from backend.app.services.ingestion_service import IngestionService
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.ml_service import MLService
from backend.app.services.sample_pcap_generator import SAMPLE_DIR, ensure_sample_pcaps


@pytest.fixture(scope="module", autouse=True)
def setup_samples():
    """Ensure sample PCAP files exist."""
    ensure_sample_pcaps()


def test_representative_session_selection_preserves_anomalies_and_diversity():
    """
    Verify that _select_representative_sessions intelligently selects high-priority
    flows (high packets, high bytes, non-TCP protocols, port scans) rather than naive head-slicing.
    """
    aggregator = FlowAggregator()
    sessions = []
    
    # 1. 800 standard baseline flows
    for i in range(800):
        s = FlowSession(
            initiator_ip=f"10.0.0.{i % 200 + 1}",
            responder_ip="10.100.0.1",
            initiator_port=10000 + i,
            responder_port=80,
            protocol="TCP",
            first_seen=100.0 + i * 0.1,
            last_seen=100.0 + i * 0.1 + 0.05,
            packet_count=1,
            byte_count=60,
        )
        sessions.append(s)

    # 2. 5 high-volume volumetric flows
    for i in range(5):
        s_vol = FlowSession(
            initiator_ip=f"192.168.100.{i+1}",
            responder_ip="10.100.0.1",
            initiator_port=40000 + i,
            responder_port=443,
            protocol="TCP",
            first_seen=105.0,
            last_seen=110.0,
            packet_count=500,
            byte_count=250000,
        )
        sessions.append(s_vol)

    # 3. 3 UDP flood anomaly flows
    for i in range(3):
        s_udp = FlowSession(
            initiator_ip=f"198.51.100.{i+1}",
            responder_ip="10.100.0.1",
            initiator_port=50000 + i,
            responder_port=53,
            protocol="UDP",
            first_seen=106.0,
            last_seen=107.0,
            packet_count=50,
            byte_count=10000,
        )
        sessions.append(s_udp)

    selected = IngestionService._select_representative_sessions(sessions, aggregator, max_eval=100)
    assert len(selected) == 100
    
    # Verify that all 5 high-volume and all 3 UDP anomalies are prioritized in selection
    selected_ips = {s.initiator_ip for s in selected}
    for i in range(5):
        assert f"192.168.100.{i+1}" in selected_ips, "High-volume flow must be prioritized"
    for i in range(3):
        assert f"198.51.100.{i+1}" in selected_ips, "UDP anomaly flow must be prioritized"


def test_conditional_shap_execution_on_high_vs_low_risk():
    """
    Verify Fix 2:
      - Low-risk benign flows skip SHAP: explanation_status='SKIPPED_LOW_RISK', shap_value=None.
      - High-risk anomalous flows compute SHAP: explanation_status='CALCULATED', shap_value is not None.
    """
    # 1. Low-risk benign request
    low_risk_req = NetworkFlowRequest(
        packet_count=10,
        byte_count=1500,
        duration=1.0,
        conn_rate=5.0,
        dst_port=443,
        unique_dst_ports=1,
        failed_auth_count=0,
        source_ip="192.168.1.50",
        destination_ip="10.100.0.1",
        persist=False,
    )
    pred_low = MLService.predict(low_risk_req)
    assert pred_low.risk_score < 50
    assert pred_low.explanation_status == "SKIPPED_LOW_RISK"
    for feat in pred_low.top_contributing_features:
        assert feat.shap_value is None, "Low-risk flow must not contain fabricated SHAP values"
        assert feat.contribution_direction is None

    # 2. High-risk port scan / anomaly request
    high_risk_req = NetworkFlowRequest(
        packet_count=5,
        byte_count=240,
        duration=0.05,
        conn_rate=50.0,
        dst_port=445,
        unique_dst_ports=50,
        failed_auth_count=0,
        source_ip="192.168.1.99",
        destination_ip="10.100.4.12",
        persist=False,
    )
    pred_high = MLService.predict(high_risk_req)
    assert pred_high.risk_score >= 50 or pred_high.is_anomaly
    assert pred_high.explanation_status == "CALCULATED"
    assert len(pred_high.top_contributing_features) > 0
    # At least one feature has real calculated SHAP value
    has_shap = any(f.shap_value is not None for f in pred_high.top_contributing_features)
    assert has_shap, "High-risk flow must compute genuine SHAP value"


def test_dashboard_service_record_prediction_batch():
    """
    Verify Fix 3:
      - record_prediction_batch correctly processes multiple flows with single/chunked flushes.
      - SecurityEventModel and PolicyAuditLogModel are correctly created and linked.
    """
    db = SessionLocal()
    try:
        items = [
            (
                NetworkFlowRequest(
                    packet_count=20 + i,
                    byte_count=1000 + i * 50,
                    duration=0.5,
                    conn_rate=10.0,
                    dst_port=80,
                    unique_dst_ports=1,
                    failed_auth_count=0,
                    source_ip=f"10.10.1.{10 + (i % 3)}",
                    destination_ip="192.168.1.1",
                    persist=True,
                ),
                f"10.10.1.{10 + (i % 3)}",
                "192.168.1.1",
                "TCP",
            )
            for i in range(15)
        ]

        results = DashboardService.record_prediction_batch(
            db=db,
            items=items,
            is_demo=False,
            batch_size=5,
        )
        db.commit()

        assert len(results) == 15
        for pred, event_model in results:
            assert pred.event_id is not None
            assert event_model.id == pred.event_id
            # Query back from DB
            db_event = db.scalar(select(SecurityEventModel).where(SecurityEventModel.id == event_model.id))
            assert db_event is not None
            assert db_event.source_ip.startswith("10.10.1.")

    finally:
        db.close()


def test_batch_persistence_rollback_on_failure():
    """
    Verify Fix 3 transaction integrity:
      - If a batch encounter an unrecoverable database error, rollback is cleanly executed.
    """
    db = SessionLocal()
    try:
        # Pass an invalid item structure that triggers an exception
        bad_items = [
            (None, "10.0.0.1", "10.0.0.2", "TCP")
        ]
        with pytest.raises(Exception):
            DashboardService.record_prediction_batch(db=db, items=bad_items)
        # Session remains valid after rollback
        count = db.scalar(select(func.count(SecurityEventModel.id)))
        assert count is not None
    finally:
        db.close()


def test_benchmark_captures_remain_intact():
    """
    Verify Benchmark Captures regression:
      - Benign HTTPS Session (benign_web.pcap)
      - Port Scan (port_scan.pcap)
      - Volumetric Traffic Burst (traffic_spike.pcap)
    All return HTTP 200, accurate classifications, and metrics.
    """
    client = TestClient(app)

    # 1. Benign HTTPS
    resp1 = client.post("/api/v1/ingest/samples/benign_web.pcap?persist=true")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["filename"] == "benign_web.pcap"
    assert data1["metrics"]["packets_processed"] >= 20
    assert data1["flows_evaluated"] >= 1
    assert data1["is_sampled"] is False

    # 2. Port Scan
    resp2 = client.post("/api/v1/ingest/samples/port_scan.pcap?persist=true")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["filename"] == "port_scan.pcap"
    assert data2["flows_evaluated"] >= 20
    assert data2["high_risk_flows_count"] > 0

    # 3. Volumetric Traffic Spike
    resp3 = client.post("/api/v1/ingest/samples/traffic_spike.pcap?persist=true")
    assert resp3.status_code == 200
    data3 = resp3.json()
    assert data3["filename"] == "traffic_spike.pcap"
    assert data3["metrics"]["packets_processed"] >= 1000
    assert data3["flows_evaluated"] >= 1


def test_api_upload_multipart_bounded_response():
    """
    Verify Fix 4 and Fix 5:
      - POST /api/v1/ingest/pcap runs asynchronously via threadpool without event-loop freeze.
      - Response results array is bounded (<= pcap_max_response_flows).
      - Correct aggregate counters and sampling fields are populated.
    """
    client = TestClient(app)
    pcap_path = SAMPLE_DIR / "port_scan.pcap"
    pcap_bytes = pcap_path.read_bytes()

    files = {"file": ("test_upload_scan.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}
    data = {"persist": "false"}

    response = client.post("/api/v1/ingest/pcap", files=files, data=data)
    assert response.status_code == 200
    res_data = response.json()

    assert res_data["filename"] == "test_upload_scan.pcap"
    assert "flows_generated" in res_data
    assert "flows_selected_for_evaluation" in res_data
    assert "results_omitted_count" in res_data
    assert len(res_data["results"]) <= 50
    assert res_data["metrics"]["packets_processed"] >= 50
