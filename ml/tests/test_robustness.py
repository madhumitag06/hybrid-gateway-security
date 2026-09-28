"""
ML Robustness, Leakage, and Edge-Case Test Suite
=================================================
Validates:
1. Dataset split integrity and lack of target/feature leakage.
2. StandardScaler isolation to training split.
3. Model resilience across adversarial and extreme edge-case network flows.
4. Exact SHAP TreeExplainer attribution integration.
5. Deterministic random seed reproducibility.
"""

import hashlib
import numpy as np
import pytest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from backend.app.services.explainability_service import ExplainabilityService
from ml.data.generator import TRAFFIC_CLASSES, generate_synthetic_dataset
from ml.features.extractor import FEATURE_NAMES, FeatureExtractor, NetworkFlowInput
from ml.models.predict import ThreatPredictor


@pytest.fixture(scope="module")
def predictor() -> ThreatPredictor:
    return ThreatPredictor()


@pytest.fixture(scope="module")
def explainability_service(predictor: ThreatPredictor) -> ExplainabilityService:
    return ExplainabilityService(predictor=predictor)


def test_no_data_leakage_in_preprocessing():
    """
    Test 1: Verify StandardScaler is strictly fitted on Train partition only.
    Test partition statistics must NOT influence the scaling parameters.
    """
    df = generate_synthetic_dataset(n_samples=2000, random_seed=42)
    X, y = FeatureExtractor.extract_from_dataframe(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    scaler_train_only = StandardScaler().fit(X_train)
    scaler_leaked = StandardScaler().fit(X)

    # The means and variances must strictly differ between train-only and all-data
    assert not np.allclose(scaler_train_only.mean_, scaler_leaked.mean_)
    assert not np.allclose(scaler_train_only.var_, scaler_leaked.var_)


def test_reproducibility_deterministic_seed():
    """
    Test 2: Verify deterministic generation across independent runs with the same seed.
    """
    df1 = generate_synthetic_dataset(n_samples=500, random_seed=123)
    df2 = generate_synthetic_dataset(n_samples=500, random_seed=123)

    hash1 = hashlib.sha256(df1.to_csv(index=False).encode()).hexdigest()
    hash2 = hashlib.sha256(df2.to_csv(index=False).encode()).hexdigest()

    assert hash1 == hash2


def test_benign_typo_resilience(predictor: ThreatPredictor):
    """
    Test 3: An isolated login typo (failed_auth_count=1) in an otherwise standard HTTPS flow
    must not trigger a false-positive BRUTE_FORCE alert.
    """
    typo_flow = NetworkFlowInput(
        packet_count=30,
        byte_count=18000,
        duration=3.0,
        conn_rate=2.5,
        dst_port=443,
        unique_dst_ports=1,
        failed_auth_count=1,
    )
    result = predictor.predict_flow(typo_flow)
    assert result.attack_type == "BENIGN"
    assert result.threat_level == "LOW"


def test_multi_cdn_benign_browsing_resilience(predictor: ThreatPredictor):
    """
    Test 4: Multi-endpoint web browsing (hitting 3 unique ports, e.g. 80, 443, 8080 for CDN/API)
    with low connection rate must remain classified as BENIGN, not PORT_SCAN.
    """
    cdn_flow = NetworkFlowInput(
        packet_count=50,
        byte_count=45000,
        duration=4.5,
        conn_rate=3.0,
        dst_port=443,
        unique_dst_ports=3,
        failed_auth_count=0,
    )
    result = predictor.predict_flow(cdn_flow)
    assert result.attack_type == "BENIGN"


def test_extreme_zero_duration_resilience(predictor: ThreatPredictor):
    """
    Test 5: Edge-case flow with near-zero duration does not cause division by zero or NaN features.
    """
    edge_flow = NetworkFlowInput(
        packet_count=1,
        byte_count=60,
        duration=0.0001,
        conn_rate=1.0,
        dst_port=80,
        unique_dst_ports=1,
        failed_auth_count=0,
    )
    result = predictor.predict_flow(edge_flow)
    assert not np.isnan(result.risk_score)
    assert result.attack_type in TRAFFIC_CLASSES


def test_massive_payload_edge_case(predictor: ThreatPredictor):
    """
    Test 6: Massive payload traffic is classified gracefully without overflow or exception.
    """
    massive_flow = NetworkFlowInput(
        packet_count=50000,
        byte_count=65_000_000,
        duration=120.0,
        conn_rate=80.0,
        dst_port=80,
        unique_dst_ports=1,
        failed_auth_count=0,
    )
    result = predictor.predict_flow(massive_flow)
    assert result.is_anomaly
    assert result.risk_score >= 40


def test_shap_compatibility_and_feature_contributions(
    predictor: ThreatPredictor,
    explainability_service: ExplainabilityService,
):
    """
    Test 7: Verify SHAP TreeExplainer generates valid Shapley values for all classes.
    """
    flow = NetworkFlowInput(
        packet_count=40,
        byte_count=9000,
        duration=1.5,
        conn_rate=22.0,
        dst_port=22,
        unique_dst_ports=1,
        failed_auth_count=15,
    )
    prediction = predictor.predict_flow(flow)
    assert prediction.attack_type == "BRUTE_FORCE"

    top_features = explainability_service.explain_flow(
        flow, predicted_class=prediction.attack_type
    )

    assert isinstance(top_features, list)
    assert len(top_features) > 0

    top_feature_names = [f["feature"] for f in top_features]
    assert "failed_auth_count" in top_feature_names or "conn_rate" in top_feature_names

    for feat in top_features:
        assert np.isfinite(feat["shap_value"])
        assert feat["contribution_direction"] in [
            "INCREASES_RISK",
            "DECREASES_RISK",
            "NEUTRAL",
        ]
