"""
Automated Hardening and Guardrail Test Suite
===========================================
Validates:
1. Docker Lab Router Safety Guardrails (Protected IPs, invalid addresses, management plane).
2. Host Namespace Isolation Protection Logic (iptables-init safety checks).
3. ML Feature Extractor Edge Cases (NaN, Inf, Zero Duration, Safe Division).
4. Confidence Gating (< 0.60 -> Monitor, no active rule).
5. End-to-End Decision Traceability in SecurityEventModel.flow_features.
"""

import math
import numpy as np
import pytest
from pydantic import ValidationError

import importlib.util
from pathlib import Path
import pytest
from sqlalchemy.orm import Session

from backend.app.db.session import SessionLocal
from backend.app.schemas.predict import NetworkFlowRequest, PredictionResponse
from backend.app.services.policy_engine import PolicyEngine
from backend.app.services.dashboard_service import DashboardService
from ml.features.extractor import FeatureExtractor, NetworkFlowInput


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _load_router_agent_module():
    router_agent_path = (
        Path(__file__).resolve().parent.parent.parent
        / "deployment"
        / "hybrid-lab"
        / "router"
        / "router_agent.py"
    )
    spec = importlib.util.spec_from_file_location("lab_router_agent", router_agent_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


router_agent = _load_router_agent_module()
is_valid_lab_target = router_agent.is_valid_lab_target
_build_rule_spec = router_agent._build_rule_spec
PROTECTED_IPS = router_agent.PROTECTED_IPS


# ==============================================================================
# 1. Router Safety & Network Guardrails
# ==============================================================================

def test_router_rejects_protected_and_management_ips():
    """Verify that router safety logic strictly rejects protected and management IPs."""
    # Management subnet IPs
    assert not is_valid_lab_target("10.30.10.1")
    assert not is_valid_lab_target("10.30.10.2")
    assert not is_valid_lab_target("10.30.10.50")

    # Gateway and router IPs
    for ip in PROTECTED_IPS:
        assert not is_valid_lab_target(ip)

    # Broadcast, network and special addresses
    assert not is_valid_lab_target("0.0.0.0")
    assert not is_valid_lab_target("127.0.0.1")
    assert not is_valid_lab_target("10.10.10.0")    # On-prem network ID
    assert not is_valid_lab_target("10.10.10.255")  # On-prem broadcast
    assert not is_valid_lab_target("10.20.10.0")    # Cloud network ID
    assert not is_valid_lab_target("10.20.10.255")  # Cloud broadcast
    assert not is_valid_lab_target("224.0.0.1")     # Multicast
    assert not is_valid_lab_target("255.255.255.255") # Broadcast

    # Completely out-of-scope non-lab subnets
    assert not is_valid_lab_target("8.8.8.8")
    assert not is_valid_lab_target("192.168.1.1")
    assert not is_valid_lab_target("172.17.0.1")


def test_router_accepts_valid_lab_workload_ips():
    """Verify that legitimate lab workload IPs are accepted."""
    assert is_valid_lab_target("10.10.10.10")  # App Server
    assert is_valid_lab_target("10.10.10.20")  # Database
    assert is_valid_lab_target("10.10.10.30")  # Workstation
    assert is_valid_lab_target("10.10.10.50")  # Attacker
    assert is_valid_lab_target("10.20.10.10")  # Cloud Web API
    assert is_valid_lab_target("10.20.10.20")  # Cloud S3 Bucket


def test_router_rule_spec_normalization():
    """Verify that Block rules are host-wide and Restrict bounds ports between 1 and 65535."""
    # Block action forces host-wide drop (effective_port=None)
    rule_block = _build_rule_spec("10.10.10.50", "Block", 443)
    assert rule_block is not None
    assert "--dport" not in rule_block
    assert rule_block == ["-s", "10.10.10.50", "-j", "DROP"]

    # Restrict action binds port properly
    rule_restrict = _build_rule_spec("10.10.10.30", "Restrict", 8080)
    assert rule_restrict is not None
    assert rule_restrict == ["-s", "10.10.10.30", "-p", "tcp", "--dport", "8080", "-j", "DROP"]

    # Restrict action with out-of-range port safely clamps to standard fallback port 8080
    rule_bad_port = _build_rule_spec("10.10.10.30", "Restrict", 99999)
    assert rule_bad_port is not None
    assert rule_bad_port == ["-s", "10.10.10.30", "-p", "tcp", "--dport", "8080", "-j", "DROP"]


# ==============================================================================
# 2. ML Feature Extraction & Edge Cases
# ==============================================================================

def test_ml_zero_duration_safe_handling():
    """Verify that zero duration does not raise ZeroDivisionError and bounds conn_rate."""
    flow = NetworkFlowInput(
        packet_count=100,
        byte_count=50000,
        duration=0.0,  # Zero duration
        conn_rate=0.0,
        dst_port=80,
    )
    features = FeatureExtractor.extract_from_flow(flow)
    assert features.shape == (1, 10)
    assert not np.isnan(features).any()
    assert not np.isinf(features).any()
    # Check that bytes_per_sec and packets_per_sec were safely computed
    assert features[0, 7] > 0  # bytes_per_sec > 0
    assert features[0, 8] > 0  # packets_per_sec > 0


def test_ml_nan_inf_input_rejection():
    """Verify that NaN and Inf are rejected by Pydantic validation."""
    with pytest.raises(ValidationError):
        NetworkFlowInput(
            packet_count=10,
            byte_count=1000,
            duration=float("nan"),
            conn_rate=1.0,
            dst_port=80,
        )

    with pytest.raises(ValidationError):
        NetworkFlowInput(
            packet_count=10,
            byte_count=1000,
            duration=float("inf"),
            conn_rate=1.0,
            dst_port=80,
        )


def test_ml_extreme_values_bounded():
    """Verify that extreme packet/byte counts remain finite in feature extraction."""
    flow = NetworkFlowInput(
        packet_count=10_000_000,
        byte_count=10_000_000_000,
        duration=0.001,
        conn_rate=100_000.0,
        dst_port=443,
    )
    features = FeatureExtractor.extract_from_flow(flow)
    assert np.all(np.isfinite(features))


# ==============================================================================
# 3. Confidence Gating & Policy Decisions
# ==============================================================================

def test_confidence_gating_below_threshold():
    """Verify that low confidence (< 0.60) forces policy downgrade to Monitor."""
    # Even with high risk score, low confidence must NOT block traffic
    prediction = PredictionResponse(
        attack_type="PORT_SCAN",
        confidence=0.45,  # Below 0.60 threshold
        risk_score=85,
        threat_level="HIGH",
        action_recommendation="Restrict",
        is_anomaly=True,
        class_probabilities={
            "BENIGN": 0.30,
            "PORT_SCAN": 0.45,
            "BRUTE_FORCE": 0.10,
            "TRAFFIC_SPIKE": 0.10,
            "SUSPICIOUS_TRANSFER": 0.05,
        },
        top_contributing_features=[],
    )

    decision = PolicyEngine.evaluate(
        prediction=prediction,
        source_ip="10.10.10.50",
        destination_ip="10.20.10.10",
        dst_port=80,
        protocol="TCP",
    )

    # Must be downgraded to Monitor due to low confidence
    assert decision.policy_action == "Monitor"
    assert decision.enforcement_required is False
    assert decision.rule_name == "CONFIDENCE_GATING_MONITOR"
    assert "below operating threshold" in decision.reason.lower()


# ==============================================================================
# 4. Decision Traceability in SecurityEventModel
# ==============================================================================

def test_decision_traceability_features(db_session):
    """Verify that record_prediction stores full lifecycle trace in flow_features."""
    flow_req = NetworkFlowRequest(
        packet_count=50,
        byte_count=3500,
        duration=0.5,
        conn_rate=100.0,
        dst_port=22,
        unique_dst_ports=1,
        failed_auth_count=5,
        source_ip="10.10.10.30",
        destination_ip="10.20.10.20",
        persist=True,
    )

    pred_resp, event_model = DashboardService.record_prediction(
        db=db_session,
        flow_request=flow_req,
        source_ip="10.10.10.30",
        destination_ip="10.20.10.20",
    )
    assert pred_resp is not None
    assert event_model is not None

    ff = event_model.flow_features
    assert isinstance(ff, dict)
    assert "policy_decision" in ff
    assert "enforcement_required" in ff
    assert "policy_reason" in ff
    assert "router_synced" in ff
    assert "explanation_status" in ff
    assert event_model.status in ["Enforced", "Applied", "Simulated", "Monitoring", "Allowed"]
