"""
Inference and Threat Classification Test Suite
==============================================
Validates that the genuinely trained ML model correctly classifies distinct traffic patterns,
calculates derived risk scores from model class probability estimates, and handles edge cases.
"""

import pytest
from pydantic import ValidationError

from ml.features.extractor import NetworkFlowInput
from ml.models.predict import ThreatPredictor


@pytest.fixture(scope="module")
def predictor() -> ThreatPredictor:
    """Initialize ThreatPredictor using trained artifacts."""
    return ThreatPredictor()


def test_benign_traffic_inference(predictor: ThreatPredictor):
    """
    Test 1: Standard HTTPS flow with normal packet sizes and zero authentication errors.
    Expectation: Classified as BENIGN with LOW risk tier (risk score < 40) and 'Allow' action.
    """
    benign_flow = NetworkFlowInput(
        packet_count=25,
        byte_count=15000,
        duration=2.5,
        conn_rate=2.0,
        dst_port=443,
        unique_dst_ports=1,
        failed_auth_count=0,
    )
    result = predictor.predict_flow(benign_flow)

    assert result.attack_type == "BENIGN"
    assert not result.is_anomaly
    assert result.risk_score < 40
    assert result.threat_level == "LOW"
    assert result.action_recommendation == "Allow"
    assert result.confidence > 0.5
    assert "BENIGN" in result.class_probabilities


def test_port_scan_detection(predictor: ThreatPredictor):
    """
    Test 2: Fast horizontal port scanning pattern (many unique destination ports, fast connection rate).
    Expectation: Classified as PORT_SCAN with elevated risk (>= 40) and 'Restrict' or 'Block' action.
    """
    scan_flow = NetworkFlowInput(
        packet_count=2,
        byte_count=120,
        duration=0.08,
        conn_rate=120.0,
        dst_port=8080,
        unique_dst_ports=75,
        failed_auth_count=0,
    )
    result = predictor.predict_flow(scan_flow)

    assert result.attack_type == "PORT_SCAN"
    assert result.is_anomaly
    assert result.risk_score >= 40
    assert result.threat_level in ["MEDIUM", "HIGH"]
    assert result.action_recommendation in ["Monitor", "Restrict", "Block"]
    assert result.confidence > 0.5


def test_brute_force_detection(predictor: ThreatPredictor):
    """
    Test 3: Repeated authentication failures targeting SSH (port 22).
    Expectation: Classified as BRUTE_FORCE with elevated risk (>= 40) and action recommendation.
    """
    brute_force_flow = NetworkFlowInput(
        packet_count=35,
        byte_count=8500,
        duration=1.8,
        conn_rate=18.0,
        dst_port=22,
        unique_dst_ports=1,
        failed_auth_count=12,
    )
    result = predictor.predict_flow(brute_force_flow)

    assert result.attack_type == "BRUTE_FORCE"
    assert result.is_anomaly
    assert result.risk_score >= 40
    assert result.threat_level in ["MEDIUM", "HIGH"]
    assert result.action_recommendation in ["Restrict", "Block"]
    assert result.confidence > 0.5


def test_traffic_spike_detection(predictor: ThreatPredictor):
    """
    Test 4: High volume traffic spike / flood attempt with massive byte and packet counts.
    Expectation: Classified as TRAFFIC_SPIKE with elevated risk (>= 40).
    """
    spike_flow = NetworkFlowInput(
        packet_count=4500,
        byte_count=4_500_000,
        duration=4.0,
        conn_rate=60.0,
        dst_port=80,
        unique_dst_ports=1,
        failed_auth_count=0,
    )
    result = predictor.predict_flow(spike_flow)

    assert result.attack_type == "TRAFFIC_SPIKE"
    assert result.is_anomaly
    assert result.risk_score >= 40
    assert result.threat_level in ["MEDIUM", "HIGH"]


def test_suspicious_transfer_detection(predictor: ThreatPredictor):
    """
    Test 5: Large data transfer on non-standard administrative port (e.g. 8443).
    Expectation: Classified as SUSPICIOUS_TRANSFER with elevated risk.
    """
    exfil_flow = NetworkFlowInput(
        packet_count=1200,
        byte_count=1_600_000,
        duration=120.0,
        conn_rate=3.0,
        dst_port=8443,
        unique_dst_ports=1,
        failed_auth_count=0,
    )
    result = predictor.predict_flow(exfil_flow)

    assert result.attack_type == "SUSPICIOUS_TRANSFER"
    assert result.is_anomaly
    assert result.risk_score >= 40


def test_input_validation_failure():
    """
    Test 6: Validates that invalid network flow attributes (e.g. invalid port, negative values)
    trigger strict Pydantic validation errors.
    """
    with pytest.raises(ValidationError):
        NetworkFlowInput(
            packet_count=-10,  # Invalid: negative
            byte_count=500,
            duration=1.0,
            conn_rate=1.0,
            dst_port=70000,  # Invalid: port > 65535
        )


def test_batch_prediction_consistency(predictor: ThreatPredictor):
    """
    Test 7: Validates that batch inference maintains 1:1 order and identical output
    to individual flow predictions.
    """
    flows = [
        NetworkFlowInput(
            packet_count=20,
            byte_count=12000,
            duration=1.5,
            conn_rate=2.0,
            dst_port=443,
            unique_dst_ports=1,
            failed_auth_count=0,
        ),
        NetworkFlowInput(
            packet_count=3,
            byte_count=150,
            duration=0.05,
            conn_rate=150.0,
            dst_port=21,
            unique_dst_ports=50,
            failed_auth_count=0,
        ),
    ]

    batch_results = predictor.predict_batch(flows)
    single_results = [predictor.predict_flow(f) for f in flows]

    assert len(batch_results) == 2
    for b_res, s_res in zip(batch_results, single_results):
        assert b_res.attack_type == s_res.attack_type
        assert b_res.risk_score == s_res.risk_score
        assert b_res.confidence == s_res.confidence
