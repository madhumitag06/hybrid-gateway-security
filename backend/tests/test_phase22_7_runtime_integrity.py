"""
Phase 22.7 — Runtime Inference Integrity and Infinite Loop Regression Suite
===========================================================================
Validates that:
1. Opening Live Network and fetching presets does not create inference records.
2. Reading inference history does not create inference records.
3. One deliberate analysis request creates exactly one logical record in the database.
4. Repeated history refreshes do not create additional records.
5. Duplicate request handling is safe and idempotent.
6. Live Network and health endpoints report the actual loaded model identity (XGBoost V2).
7. XGBoost V2 feature schema matches the authoritative nine-feature schema.
8. Model inference errors are not silently replaced with hardcoded predictions.
9. Probability labels correspond to the actual model output.
10. No production demo fixtures are returned as real predictions.
"""

from typing import Dict, Any
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.main import app
from backend.app.db.session import SessionLocal
from backend.app.models.security_event import SecurityEventModel
from backend.app.services.ml_service import MLService
from ml.features.extractor import FEATURE_NAMES_V2, NetworkFlowInput, FeatureExtractor
from ml.models.predict import ThreatPredictor


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_01_fetching_presets_does_not_create_inference(client: TestClient, db_session: Session):
    """
    Opening Live Network and fetching scenario presets must be purely read-only
    and never create an inference record or persist to PostgreSQL.
    """
    initial_count = db_session.query(SecurityEventModel).count()

    response = client.get("/api/v1/predict/presets")
    assert response.status_code == 200
    data = response.json()
    assert "PORT_SCAN" in data
    assert "BENIGN_HTTPS" in data

    final_count = db_session.query(SecurityEventModel).count()
    assert final_count == initial_count, "Fetching presets must not create any database records."


def test_02_reading_inference_history_does_not_create_inference(client: TestClient, db_session: Session):
    """
    Querying historical security events must be purely read-only
    and never trigger model inference or database persistence.
    """
    initial_count = db_session.query(SecurityEventModel).count()

    response = client.get("/api/v1/events?limit=10")
    assert response.status_code == 200

    final_count = db_session.query(SecurityEventModel).count()
    assert final_count == initial_count, "Reading event history must not create any database records."


def test_03_one_deliberate_analysis_creates_exactly_one_record(client: TestClient, db_session: Session):
    """
    One deliberate user analysis request must create exactly one logical record.
    """
    initial_count = db_session.query(SecurityEventModel).count()

    payload = {
        "packet_count": 2,
        "byte_count": 120,
        "duration": 0.08,
        "conn_rate": 120.0,
        "dst_port": 8080,
        "unique_dst_ports": 75,
        "failed_auth_count": 0,
        "persist": True,
    }

    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["attack_type"] == "PORT_SCAN"
    assert res_data["risk_score"] == 92
    assert res_data["event_id"] is not None

    final_count = db_session.query(SecurityEventModel).count()
    assert final_count == initial_count + 1, "Exactly one event record must be inserted per analysis request."


def test_04_repeated_history_refreshes_do_not_create_additional_records(client: TestClient, db_session: Session):
    """
    Simulating 10 consecutive history refreshes must not increase the database event count.
    """
    initial_count = db_session.query(SecurityEventModel).count()

    for _ in range(10):
        res = client.get("/api/v1/events?limit=5")
        assert res.status_code == 200

    final_count = db_session.query(SecurityEventModel).count()
    assert final_count == initial_count, "Repeated history refreshes must not accumulate duplicate records."


def test_05_duplicate_request_handling_is_safe(client: TestClient, db_session: Session):
    """
    Consecutive rapid requests with the same flow vector must return valid, deterministic
    predictions without triggering unhandled exceptions or state corruption.
    """
    payload = {
        "packet_count": 25,
        "byte_count": 15000,
        "duration": 2.5,
        "conn_rate": 2.0,
        "dst_port": 443,
        "unique_dst_ports": 1,
        "failed_auth_count": 0,
        "persist": False,  # Ephemeral / read-only analysis
    }

    r1 = client.post("/api/v1/predict", json=payload)
    r2 = client.post("/api/v1/predict", json=payload)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["attack_type"] == r2.json()["attack_type"] == "BENIGN"
    assert r1.json()["risk_score"] == r2.json()["risk_score"]


def test_06_live_network_reports_actual_loaded_model_identity(client: TestClient):
    """
    Health and prediction endpoints must explicitly report the active XGBoost V2 model identity,
    confirming that the backend does not report stale Random Forest metadata.
    """
    # 1. Verify health endpoint reports XGBoost V2
    health_res = client.get("/api/health")
    assert health_res.status_code == 200
    health_data = health_res.json()
    assert health_data["model_loaded"] is True
    assert health_data["model_type"] == "XGBClassifier"
    assert "XGBoost" in health_data["model_name"]
    assert health_data["active_model_version"] == "candidate_xgboost_v2"
    assert health_data["feature_count"] == 9

    # 2. Verify prediction response contains model_name and model_version
    pred_res = client.post(
        "/api/v1/predict",
        json={
            "packet_count": 2,
            "byte_count": 120,
            "duration": 0.08,
            "conn_rate": 120.0,
            "dst_port": 8080,
            "unique_dst_ports": 75,
            "persist": False,
        },
    )
    assert pred_res.status_code == 200
    pred_data = pred_res.json()
    assert pred_data["model_version"] == "candidate_xgboost_v2"
    assert "XGBoost" in pred_data["model_name"]


def test_07_xgboost_v2_feature_schema_matches_authoritative_nine_features():
    """
    Inspect the active XGBoost V2 model predictor directly and assert that its feature
    schema strictly matches the canonical 9-feature schema without failed_auth_count.
    """
    predictor = MLService.get_predictor("candidate_xgboost_v2")
    assert predictor.feature_schema == FEATURE_NAMES_V2, (
        f"Schema mismatch: expected {FEATURE_NAMES_V2}, got {predictor.feature_schema}"
    )
    assert len(predictor.feature_schema) == 9
    assert "failed_auth_count" not in predictor.feature_schema


def test_08_model_inference_errors_are_not_silently_replaced_with_hardcoded_predictions(client: TestClient):
    """
    Passing invalid or unprocessable data must fail fast with HTTP 422 or 500,
    rather than silently falling back to a hardcoded mock prediction.
    """
    # Negative packet count violates schema validation (ge=0 or ge=1)
    response = client.post(
        "/api/v1/predict",
        json={
            "packet_count": -5,
            "byte_count": 100,
            "duration": 1.0,
            "conn_rate": 1.0,
            "dst_port": 80,
            "unique_dst_ports": 1,
            "persist": False,
        },
    )
    assert response.status_code == 422, "Invalid input must raise 422 validation error, not return mock predictions."


def test_09_probability_labels_correspond_to_actual_model_output():
    """
    Validate that class probability distribution originates from real XGBClassifier output,
    covers all 5 classes, and sums to 1.0 within normal floating-point tolerance.
    """
    predictor = MLService.get_predictor("candidate_xgboost_v2")
    flow_input = NetworkFlowInput(
        packet_count=2,
        byte_count=120,
        duration=0.08,
        conn_rate=120.0,
        dst_port=8080,
        unique_dst_ports=75,
        failed_auth_count=0,
    )

    pred_output = predictor.predict_flow(flow_input)
    probs = pred_output.class_probabilities

    expected_classes = {"BENIGN", "PORT_SCAN", "BRUTE_FORCE", "TRAFFIC_SPIKE", "SUSPICIOUS_TRANSFER"}
    assert set(probs.keys()) == expected_classes

    total_prob = sum(probs.values())
    assert abs(total_prob - 1.0) < 0.01, f"Probabilities must sum to ~1.0, got {total_prob}"

    # For the known PORT_SCAN vector, PORT_SCAN probability must dominate
    assert pred_output.attack_type == "PORT_SCAN"
    assert probs["PORT_SCAN"] > 0.80, f"PORT_SCAN probability should be > 0.80, got {probs['PORT_SCAN']}"


def test_10_no_production_demo_fixtures_returned_as_real_predictions(client: TestClient):
    """
    Verify that varying feature inputs produce varying ML outputs, proving that
    predictions are computed by the real model rather than static demo fixtures.
    """
    # 1. Port scan vector
    r_scan = client.post(
        "/api/v1/predict",
        json={
            "packet_count": 2,
            "byte_count": 120,
            "duration": 0.08,
            "conn_rate": 120.0,
            "dst_port": 8080,
            "unique_dst_ports": 75,
            "persist": False,
        },
    )
    # 2. Volumetric traffic spike vector (matching active XGBoost V2 calibration)
    r_spike = client.post(
        "/api/v1/predict",
        json={
            "packet_count": 4,
            "byte_count": 0,
            "duration": 0.001,
            "conn_rate": 500.0,
            "dst_port": 61083,
            "unique_dst_ports": 1,
            "failed_auth_count": 0,
            "bytes_per_sec": 0.0,
            "packets_per_sec": 4000.0,
            "avg_packet_size": 0.0,
            "persist": False,
        },
    )
    # 3. Benign HTTPS vector
    r_benign = client.post(
        "/api/v1/predict",
        json={
            "packet_count": 25,
            "byte_count": 15000,
            "duration": 2.5,
            "conn_rate": 2.0,
            "dst_port": 443,
            "unique_dst_ports": 1,
            "persist": False,
        },
    )

    assert r_scan.status_code == 200
    assert r_spike.status_code == 200
    assert r_benign.status_code == 200

    data_scan = r_scan.json()
    data_spike = r_spike.json()
    data_benign = r_benign.json()

    assert data_scan["attack_type"] == "PORT_SCAN"
    assert data_spike["attack_type"] == "TRAFFIC_SPIKE"
    assert data_benign["attack_type"] == "BENIGN"

    assert data_scan["risk_score"] != data_benign["risk_score"]
    assert data_spike["risk_score"] != data_benign["risk_score"]
    assert data_scan["class_probabilities"] != data_spike["class_probabilities"]
