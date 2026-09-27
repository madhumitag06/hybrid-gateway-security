"""
Unit Tests for Explainability Service & SHAP TreeExplainer
==========================================================
Verifies TreeExplainer initialization, multiclass output structure, mathematical
additive consistency, deterministic reproducibility, feature ordering, and resilient fallback.
"""

import numpy as np
import pytest

from backend.app.schemas.predict import NetworkFlowRequest
from backend.app.services.explainability_service import ExplainabilityService
from ml.features.extractor import FEATURE_NAMES, FeatureExtractor, NetworkFlowInput
from ml.models.predict import ThreatPredictor


@pytest.fixture(scope="module")
def predictor():
    return ThreatPredictor()


@pytest.fixture(scope="module")
def explain_svc(predictor):
    return ExplainabilityService(predictor)


def test_tree_explainer_initialization(explain_svc):
    """Verify that SHAP TreeExplainer initializes successfully on model.joblib."""
    assert explain_svc._explainer is not None
    assert explain_svc.predictor.model is not None


def test_feature_names_and_ordering_consistency():
    """Verify exact 10-feature ordering matches FEATURE_NAMES."""
    expected = [
        "packet_count",
        "byte_count",
        "duration",
        "conn_rate",
        "dst_port",
        "unique_dst_ports",
        "failed_auth_count",
        "bytes_per_sec",
        "packets_per_sec",
        "avg_packet_size",
    ]
    assert FEATURE_NAMES == expected
    assert len(FEATURE_NAMES) == 10


def test_shap_multiclass_output_and_finite_values(explain_svc, predictor):
    """Verify that compute_shap_attributions returns finite floats for all classes."""
    flow = NetworkFlowInput(
        packet_count=20,
        byte_count=1200,
        duration=1.0,
        conn_rate=20.0,
        dst_port=443,
        unique_dst_ports=1,
        failed_auth_count=0,
    )
    raw_vec = FeatureExtractor.extract_from_flow(flow)[0]
    X_scaled = predictor.scaler.transform([raw_vec])

    for c_name in predictor.classes:
        attributions, base_val, all_base_vals = explain_svc.compute_shap_attributions(
            X_scaled, c_name
        )
        assert len(attributions) == 10
        assert np.all(np.isfinite(attributions)), "All SHAP values must be finite numbers"
        assert np.isfinite(base_val), "Base value must be a finite float"
        assert c_name in all_base_vals


def test_shap_additive_consistency(explain_svc, predictor):
    """
    Verify additive consistency:
    sum(phi_i(c)) + base_value(c) == model_output_probability(c) (+- tolerance)
    """
    sample_flows = [
        {"packet_count": 25, "byte_count": 15000, "duration": 2.5, "conn_rate": 2.0, "dst_port": 443, "unique_dst_ports": 1, "failed_auth_count": 0},
        {"packet_count": 2, "byte_count": 120, "duration": 0.08, "conn_rate": 120.0, "dst_port": 8080, "unique_dst_ports": 75, "failed_auth_count": 0},
        {"packet_count": 35, "byte_count": 8500, "duration": 1.8, "conn_rate": 18.0, "dst_port": 22, "unique_dst_ports": 1, "failed_auth_count": 12},
    ]

    for flow_dict in sample_flows:
        flow = NetworkFlowInput(**flow_dict)
        raw_vec = FeatureExtractor.extract_from_flow(flow)[0]
        X_scaled = predictor.scaler.transform([raw_vec])
        model_probs = predictor.model.predict_proba(X_scaled)[0]

        for idx, c_name in enumerate(predictor.classes):
            attributions, base_val, _ = explain_svc.compute_shap_attributions(X_scaled, c_name)
            reconstructed_prob = float(np.sum(attributions) + base_val)
            expected_prob = float(model_probs[idx])
            assert abs(reconstructed_prob - expected_prob) < 1e-3, (
                f"Additive consistency violation for class {c_name}: "
                f"sum={reconstructed_prob:.5f}, expected={expected_prob:.5f}"
            )


def test_deterministic_explanation_reproducibility(explain_svc):
    """Verify that identical feature inputs yield deterministic, identical SHAP attributions."""
    flow = {
        "packet_count": 100,
        "byte_count": 64000,
        "duration": 5.0,
        "conn_rate": 20.0,
        "dst_port": 80,
        "unique_dst_ports": 1,
        "failed_auth_count": 0,
    }
    exp1 = explain_svc.explain_flow(flow, "BENIGN", top_n=5)
    exp2 = explain_svc.explain_flow(flow, "BENIGN", top_n=5)

    assert len(exp1) == len(exp2)
    for f1, f2 in zip(exp1, exp2):
        assert f1["feature"] == f2["feature"]
        assert f1["shap_value"] == f2["shap_value"]
        assert f1["contribution_direction"] == f2["contribution_direction"]


def test_failed_auth_count_vpc_provenance_handling(explain_svc):
    """
    Verify that when failed_auth_count=0 (e.g. for VPC Flow Logs),
    SHAP computes valid mathematical attributions and full explanation includes provenance note.
    """
    flow = {
        "packet_count": 50,
        "byte_count": 4000,
        "duration": 1.0,
        "conn_rate": 50.0,
        "dst_port": 80,
        "unique_dst_ports": 1,
        "failed_auth_count": 0,
    }
    full_exp = explain_svc.get_full_explanation(
        flow_input=flow,
        predicted_class="BENIGN",
        risk_score=10,
        confidence=0.95,
        policy_action="Allow",
        policy_rule_name="BASELINE_TRAFFIC_ALLOW",
        enforcement_status="Allowed",
    )

    auth_feat = next(f for f in full_exp["feature_attributions"] if f["feature"] == "failed_auth_count")
    assert auth_feat["value"] == 0.0
    assert np.isfinite(auth_feat["shap_value"])
    assert "L7 authentication is unavailable" in auth_feat["description"]
    assert "disclaimer" in full_exp
    assert "causality" in full_exp["disclaimer"].lower()
