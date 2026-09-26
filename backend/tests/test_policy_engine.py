"""
Unit Tests for Policy Decision Engine and Static Baseline Engine
================================================================
"""

import pytest
from backend.app.schemas.predict import ContributingFeatureSchema, NetworkFlowRequest, PredictionResponse
from backend.app.services.policy_engine import PolicyEngine
from backend.app.services.static_policy_engine import StaticPolicyEngine


@pytest.fixture
def sample_benign_pred():
    return PredictionResponse(
        risk_score=10,
        threat_level="LOW",
        attack_type="BENIGN",
        confidence=0.98,
        action_recommendation="Allow",
        is_anomaly=False,
        class_probabilities={"BENIGN": 0.98, "PORT_SCAN": 0.01},
        top_contributing_features=[],
    )


@pytest.fixture
def sample_port_scan_pred():
    return PredictionResponse(
        risk_score=95,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        confidence=0.95,
        action_recommendation="Block",
        is_anomaly=True,
        class_probabilities={"PORT_SCAN": 0.95, "BENIGN": 0.05},
        top_contributing_features=[
            ContributingFeatureSchema(
                feature="unique_dst_ports",
                value=75.0,
                deviation_z_score=4.2,
                description="Elevated unique destination port count",
            )
        ],
    )


@pytest.fixture
def sample_traffic_spike_pred():
    return PredictionResponse(
        risk_score=85,
        threat_level="HIGH",
        attack_type="TRAFFIC_SPIKE",
        confidence=0.90,
        action_recommendation="Restrict",
        is_anomaly=True,
        class_probabilities={"TRAFFIC_SPIKE": 0.90, "BENIGN": 0.10},
        top_contributing_features=[],
    )


def test_policy_engine_benign_allow(sample_benign_pred):
    """Verify LOW threat level maps deterministically to Allow."""
    decision = PolicyEngine.evaluate(
        prediction=sample_benign_pred,
        source_ip="192.168.1.50",
        destination_ip="10.100.0.1",
        dst_port=443,
    )
    assert decision.policy_action == "Allow"
    assert decision.enforcement_required is False
    assert decision.suggested_ttl_seconds == 0


def test_policy_engine_high_risk_port_scan_quarantine(sample_port_scan_pred):
    """Verify HIGH threat PORT_SCAN maps to Block with 300s quarantine TTL."""
    decision = PolicyEngine.evaluate(
        prediction=sample_port_scan_pred,
        source_ip="192.168.1.77",
        destination_ip="10.100.4.12",
        dst_port=8080,
    )
    assert decision.policy_action == "Block"
    assert decision.enforcement_required is True
    assert decision.suggested_ttl_seconds == 300
    assert "PORT_SCAN" in decision.rule_name


def test_policy_engine_traffic_spike_rate_limit(sample_traffic_spike_pred):
    """Verify TRAFFIC_SPIKE maps to Restrict (rate limit) action."""
    decision = PolicyEngine.evaluate(
        prediction=sample_traffic_spike_pred,
        source_ip="198.51.100.9",
        destination_ip="10.100.1.44",
        dst_port=80,
    )
    assert decision.policy_action == "Restrict"
    assert decision.enforcement_required is True
    assert "VOLUMETRIC" in decision.rule_name


def test_policy_engine_management_allowlist_protection(sample_port_scan_pred):
    """Verify that an IP in the management allowlist is never blocked."""
    # Loopback IP 127.0.0.1 is in default allowlist
    decision = PolicyEngine.evaluate(
        prediction=sample_port_scan_pred,
        source_ip="127.0.0.1",
        destination_ip="10.100.4.12",
        dst_port=8080,
    )
    assert decision.policy_action == "Allow"
    assert decision.enforcement_required is False
    assert "ALLOWLIST" in decision.rule_name


def test_policy_engine_confidence_gating():
    """Verify low confidence anomaly (< 0.60) is downgraded to Monitor."""
    low_conf_pred = PredictionResponse(
        risk_score=75,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        confidence=0.45,  # Low confidence
        action_recommendation="Block",
        is_anomaly=True,
        class_probabilities={"PORT_SCAN": 0.45, "BENIGN": 0.40},
        top_contributing_features=[],
    )
    decision = PolicyEngine.evaluate(
        prediction=low_conf_pred,
        source_ip="192.168.1.99",
        destination_ip="10.100.4.12",
        dst_port=8080,
    )
    assert decision.policy_action == "Monitor"
    assert decision.enforcement_required is False
    assert "CONFIDENCE_GATING" in decision.rule_name


def test_static_policy_engine_prohibited_port():
    """Verify StaticPolicyEngine blocks prohibited ports like SMB 445."""
    flow = NetworkFlowRequest(
        packet_count=10, byte_count=1000, duration=1.0, conn_rate=2.0, dst_port=445
    )
    action, rule = StaticPolicyEngine.evaluate(flow, source_ip="192.168.1.20", dst_port=445)
    assert action == "Block"
    assert "PROHIBITED" in rule


def test_static_vs_adaptive_comparison(sample_port_scan_pred):
    """Verify comparison between static and adaptive engines reports decision divergence neutrally."""
    # Stealth port scan: 2 packets, port 8080 (not a prohibited port, packet count < 2000)
    stealth_flow = NetworkFlowRequest(
        packet_count=2,
        byte_count=120,
        duration=0.5,
        conn_rate=15.0,
        dst_port=8080,
        unique_dst_ports=75,
        failed_auth_count=0,
    )
    adaptive_decision = PolicyEngine.evaluate(
        prediction=sample_port_scan_pred,
        source_ip="192.168.1.77",
        destination_ip="10.100.4.12",
        dst_port=8080,
    )
    comparison = StaticPolicyEngine.compare_with_adaptive(
        flow=stealth_flow,
        source_ip="192.168.1.77",
        dst_port=8080,
        adaptive_decision=adaptive_decision,
        flow_id="test-flow-01",
    )
    assert comparison.static_decision == "Allow"
    assert comparison.adaptive_decision == "Block"
    assert comparison.decision_divergence is True
    assert "multi-feature correlation" in comparison.divergence_rationale
