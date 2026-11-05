"""
Production-Grade Feature Pipeline V2 & XGBoost V2 Test Suite
============================================================
Tests:
- Feature calculations and mathematical parity
- Missing authentication telemetry handling
- Zero-auth SSH observable burst safeguards
- Benign SSH session false-positive resistance
- Rolling 60s unique destination-port tracking in HostPortTracker
- Port-scan detection
- Connection-rate consistency
- Window expiration and duplicate flow handling
- Memory bounds and LRU host eviction
- Training/inference feature parity
- XGBoost V2 prediction through ThreatPredictor
- SHAP V2 TreeExplainer compatibility
- Policy safeguards and API response compatibility
"""

import time
import numpy as np
import pytest

from backend.app.schemas.predict import NetworkFlowRequest, PredictionResponse
from backend.app.services.explainability_service import ExplainabilityService
from backend.app.services.flow_aggregator import FlowAggregator, HostPortTracker, PacketRecord
from backend.app.services.policy_engine import PolicyEngine, SSHProbeTracker
from ml.features.extractor import (
    FEATURE_NAMES_V1,
    FEATURE_NAMES_V2,
    FeatureExtractor,
    NetworkFlowInput,
    calculate_conn_rate,
)
from ml.models.predict import ThreatPredictor


# ==============================================================================
# 1. Feature Calculations & Mathematical Parity Tests
# ==============================================================================
def test_feature_parity_v2_calculation():
    """Verify exact numerical parity between raw formulas and FeatureExtractor V2."""
    pkt_count = 20
    byte_count = 3000
    duration = 1.5
    dst_port = 443
    unique_ports = 1

    expected_conn_rate = calculate_conn_rate(packet_count=pkt_count, duration=duration)
    assert round(expected_conn_rate, 2) == round(20.0 / 1.5, 2)

    flow = NetworkFlowInput(
        packet_count=pkt_count,
        byte_count=byte_count,
        duration=duration,
        conn_rate=expected_conn_rate,
        dst_port=dst_port,
        unique_dst_ports=unique_ports,
        failed_auth_count=0,
    )

    vec_v2 = FeatureExtractor.extract_v2_from_flow(flow)[0]
    assert len(vec_v2) == 9
    assert vec_v2[0] == 20.0  # packet_count
    assert vec_v2[1] == 3000.0  # byte_count
    assert vec_v2[2] == 1.5  # duration
    assert round(vec_v2[3], 2) == round(expected_conn_rate, 2)  # conn_rate
    assert vec_v2[4] == 443.0  # dst_port
    assert vec_v2[5] == 1.0  # unique_dst_ports
    assert vec_v2[6] == 2000.0  # bytes_per_sec (3000 / 1.5)
    assert round(vec_v2[7], 2) == round(20 / 1.5, 2)  # packets_per_sec
    assert vec_v2[8] == 150.0  # avg_packet_size (3000 / 20)


def test_conn_rate_shared_formula():
    """Verify calculate_conn_rate behaves identically across boundary conditions."""
    # Sub-second duration
    rate_sub = calculate_conn_rate(packet_count=10, duration=0.05)
    assert rate_sub == 200.0

    # Large duration
    rate_large = calculate_conn_rate(packet_count=10, duration=100.0)
    assert rate_large == 0.1

    # Stateful window
    rate_window = calculate_conn_rate(
        packet_count=10, duration=1.0, host_connection_count=30, window_seconds=15.0
    )
    assert rate_window == 2.0


# ==============================================================================
# 2. HostPortTracker (Rolling 60s Window, Eviction, Thread-Safety)
# ==============================================================================
def test_host_port_tracker_rolling_window_expiration():
    """Verify that ports targeted outside the 60-second window are expired."""
    tracker = HostPortTracker(window_seconds=2.0)
    host = "192.168.1.10"

    t0 = 1000.0
    tracker.record_destination_port(host, 80, timestamp=t0)
    tracker.record_destination_port(host, 443, timestamp=t0 + 0.5)
    tracker.record_destination_port(host, 8080, timestamp=t0 + 1.0)

    # Within window: 3 unique ports
    assert tracker.get_unique_dst_ports(host, current_time=t0 + 1.5) == 3

    # At t0 + 2.6: port 80 and 443 expired (>2.0s), only port 8080 remains
    assert tracker.get_unique_dst_ports(host, current_time=t0 + 2.6) == 1

    # At t0 + 3.5: all expired; returns safe default 1
    assert tracker.get_unique_dst_ports(host, current_time=t0 + 3.5) == 1


def test_host_port_tracker_duplicate_ports():
    """Verify multiple packets to the same destination port are deduplicated."""
    tracker = HostPortTracker(window_seconds=60.0)
    host = "10.0.0.5"

    for _ in range(50):
        tracker.record_destination_port(host, 443, timestamp=100.0)

    assert tracker.get_unique_dst_ports(host, current_time=100.5) == 1


def test_host_port_tracker_memory_bounds_lru_eviction():
    """Verify that host tracker respects max_hosts and evicts oldest idle hosts."""
    tracker = HostPortTracker(window_seconds=60.0, max_hosts=5)

    # Add 5 hosts at t=100
    for i in range(5):
        tracker.record_destination_port(f"host_{i}", 80, timestamp=100.0 + i)

    assert len(tracker.host_last_seen) == 5

    # Add 6th host; host_0 (oldest at t=100.0) must be evicted
    tracker.record_destination_port("host_5", 80, timestamp=110.0)
    assert len(tracker.host_last_seen) == 5
    assert "host_0" not in tracker.host_last_seen
    assert "host_5" in tracker.host_last_seen


def test_flow_aggregator_bidirectional_port_isolation():
    """Verify that responder reply packets do not pollute the initiator's target port count."""
    fa = FlowAggregator(port_scan_window_seconds=60.0)

    # Client (initiator) sends SYN to server port 80
    p1 = PacketRecord(timestamp=10.0, src_ip="192.168.1.100", dst_ip="10.0.0.1", src_port=50000, dst_port=80, protocol="TCP", length_bytes=60)
    fa.add_packet(p1)

    # Server replies from port 80 to client ephemeral port 50000
    p2 = PacketRecord(timestamp=10.1, src_ip="10.0.0.1", dst_ip="192.168.1.100", src_port=80, dst_port=50000, protocol="TCP", length_bytes=60)
    fa.add_packet(p2)

    # Server 10.0.0.1 should NOT be tracked as targeting client's port 50000
    assert fa.host_tracker.get_unique_dst_ports("10.0.0.1", current_time=10.2) == 1
    # Client targeted 1 port (80)
    assert fa.host_tracker.get_unique_dst_ports("192.168.1.100", current_time=10.2) == 1


# ==============================================================================
# 3. Policy Safeguards & Zero-Auth SSH Handling
# ==============================================================================
def test_zero_auth_ssh_safeguard_progression():
    """Verify that repeated SSH probes with zero failed_auth_count trigger graduated safeguards."""
    pred_low = PredictionResponse(
        threat_level="LOW",
        attack_type="BENIGN",
        confidence=0.95,
        risk_score=10,
        action_recommendation="Allow",
        is_anomaly=False,
        class_probabilities={"BENIGN": 0.95, "BRUTE_FORCE": 0.02, "PORT_SCAN": 0.01, "SUSPICIOUS_TRANSFER": 0.01, "TRAFFIC_SPIKE": 0.01},
        top_contributing_features=[],
    )

    attacker_ip = "198.51.100.99"
    PolicyEngine.ssh_tracker.reset_host(attacker_ip)

    # Attempts 1-2: Normal Allow
    d1 = PolicyEngine.evaluate(pred_low, source_ip=attacker_ip, destination_ip="10.0.0.1", dst_port=22)
    assert d1.policy_action == "Allow"

    d2 = PolicyEngine.evaluate(pred_low, source_ip=attacker_ip, destination_ip="10.0.0.1", dst_port=22)
    assert d2.policy_action == "Allow"

    # Attempt 3: MONITOR threshold reached
    d3 = PolicyEngine.evaluate(pred_low, source_ip=attacker_ip, destination_ip="10.0.0.1", dst_port=22)
    assert d3.policy_action == "Monitor"
    assert d3.rule_name == "OBSERVABLE_SSH_BURST_MONITOR"

    # Attempts 4-5
    for _ in range(2):
        PolicyEngine.evaluate(pred_low, source_ip=attacker_ip, destination_ip="10.0.0.1", dst_port=22)

    # Attempt 6: RESTRICT threshold reached
    d6 = PolicyEngine.evaluate(pred_low, source_ip=attacker_ip, destination_ip="10.0.0.1", dst_port=22)
    assert d6.policy_action == "Restrict"
    assert d6.rule_name == "OBSERVABLE_SSH_BURST_RESTRICT"
    assert d6.enforcement_required is True

    # Attempts 7-11
    for _ in range(5):
        PolicyEngine.evaluate(pred_low, source_ip=attacker_ip, destination_ip="10.0.0.1", dst_port=22)

    # Attempt 12: BLOCK quarantine threshold reached
    d12 = PolicyEngine.evaluate(pred_low, source_ip=attacker_ip, destination_ip="10.0.0.1", dst_port=22)
    assert d12.policy_action == "Block"
    assert d12.rule_name == "OBSERVABLE_SSH_BURST_BLOCK"
    assert d12.enforcement_required is True


def test_benign_ssh_session_never_blocked():
    """Verify that a legitimate established SSH session (large byte transfer) is not counted as a probe."""
    pred_benign = PredictionResponse(
        threat_level="LOW",
        attack_type="BENIGN",
        confidence=0.99,
        risk_score=5,
        action_recommendation="Allow",
        is_anomaly=False,
        class_probabilities={"BENIGN": 0.99, "BRUTE_FORCE": 0.0, "PORT_SCAN": 0.0, "SUSPICIOUS_TRANSFER": 0.0, "TRAFFIC_SPIKE": 0.01},
        top_contributing_features=[],
    )

    admin_ip = "192.168.1.50"
    PolicyEngine.ssh_tracker.reset_host(admin_ip)

    # 15 sessions from admin with large payloads (e.g. 50KB interactive session / SCP)
    for _ in range(15):
        decision = PolicyEngine.evaluate(
            pred_benign, source_ip=admin_ip, destination_ip="10.0.0.1", dst_port=22, byte_count=50000
        )
        assert decision.policy_action == "Allow"
        assert decision.rule_name == "BASELINE_TRAFFIC_ALLOW"


# ==============================================================================
# 4. ThreatPredictor & XGBoost V2 Integration Tests
# ==============================================================================
def test_threat_predictor_v2_artifacts():
    """Verify that ThreatPredictor loads the V2 candidate and uses the 9-feature schema."""
    tp = ThreatPredictor(artifacts_dir="ml/models/candidates/bigdata_v2")
    assert tp.feature_schema == FEATURE_NAMES_V2
    assert len(tp.feature_schema) == 9
    assert "failed_auth_count" not in tp.feature_schema
    assert tp.model is not None

    # Test flow without failed_auth_count dependency
    flow = NetworkFlowInput(
        packet_count=10,
        byte_count=1000,
        duration=1.0,
        conn_rate=10.0,
        dst_port=443,
        unique_dst_ports=1,
        failed_auth_count=0,
    )
    out = tp.predict_flow(flow)
    assert out.attack_type in ["BENIGN", "PORT_SCAN", "BRUTE_FORCE", "TRAFFIC_SPIKE", "SUSPICIOUS_TRANSFER"]
    assert 0 <= out.risk_score <= 100
    assert out.confidence >= 0.0
    assert len(out.class_probabilities) == 5


def test_explainability_service_v2_compatibility():
    """Verify that ExplainabilityService computes SHAP values on V2 9-feature schema without error."""
    tp = ThreatPredictor(artifacts_dir="ml/models/candidates/bigdata_v2")
    es = ExplainabilityService(predictor=tp)

    flow = NetworkFlowInput(
        packet_count=4500,
        byte_count=4500000,
        duration=2.0,
        conn_rate=150.0,
        dst_port=80,
        unique_dst_ports=1,
        failed_auth_count=0,
    )

    exp = es.explain_flow(flow, predicted_class="TRAFFIC_SPIKE", top_n=3)
    assert len(exp) == 3
    for item in exp:
        assert item["feature"] in FEATURE_NAMES_V2
        assert "shap_value" in item
        assert "description" in item


def test_network_flow_request_api_compatibility():
    """Verify that NetworkFlowRequest works with both legacy inputs and V2."""
    # Input with failed_auth_count (from legacy clients or frontend)
    req1 = NetworkFlowRequest(
        packet_count=20,
        byte_count=1200,
        duration=1.0,
        conn_rate=20.0,
        dst_port=80,
        unique_dst_ports=1,
        failed_auth_count=5,
    )
    assert req1.failed_auth_count == 5

    # Input without failed_auth_count (uses default 0)
    req2 = NetworkFlowRequest(
        packet_count=20,
        byte_count=1200,
        duration=1.0,
        conn_rate=20.0,
        dst_port=80,
        unique_dst_ports=1,
    )
    assert req2.failed_auth_count == 0
