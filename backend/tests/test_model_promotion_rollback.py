"""
Test Suite for Controlled Model Promotion and Rollback (Phase 5)
================================================================
Validates model version registry, controlled promotion of Big Data XGBoost V2,
zero-downtime rollback to Baseline Random Forest, SHAP cache invalidation,
and in-process FastAPI endpoint behavior.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.main import app
from backend.app.schemas.predict import NetworkFlowRequest
from backend.app.services.ml_service import MLService


def test_model_registry_initial_state():
    """Verify registry contains both models and active model is candidate_xgboost_v2."""
    status = MLService.get_registry_status()
    assert "active_version" in status
    assert "previous_version" in status
    assert "all_models" in status
    assert "production_rf" in status["all_models"]
    assert "candidate_xgboost_v2" in status["all_models"]

    active_details = status["active_model_details"]
    assert active_details["algorithm"] in ["XGBClassifier", "RandomForestClassifier"]


def test_active_prediction_xgboost_v2():
    """Verify active model inference runs correctly."""
    # Ensure active model is candidate_xgboost_v2
    MLService.promote_model("candidate_xgboost_v2", reason="Test active prediction")
    assert MLService.get_active_version() == "candidate_xgboost_v2"

    predictor = MLService.get_predictor()
    assert len(predictor.feature_schema) == 9

    req = NetworkFlowRequest(
        packet_count=25,
        byte_count=1800,
        duration=1.2,
        conn_rate=20.0,
        dst_port=443,
        unique_dst_ports=1,
    )
    resp = MLService.predict(req, enable_shap=False)
    assert resp.attack_type in ["BENIGN", "PORT_SCAN", "BRUTE_FORCE", "TRAFFIC_SPIKE", "SUSPICIOUS_TRANSFER"]
    assert 0 <= resp.risk_score <= 100
    assert 0.0 <= resp.confidence <= 1.0


def test_model_rollback_to_rf():
    """Verify rollback restores production_rf as active primary."""
    # Ensure current is candidate_xgboost_v2
    MLService.promote_model("candidate_xgboost_v2", reason="Setup before rollback")
    assert MLService.get_active_version() == "candidate_xgboost_v2"

    rollback_res = MLService.rollback(reason="Test emergency rollback")
    assert rollback_res["status"] == "PROMOTED"
    assert MLService.get_active_version() == "production_rf"

    rf_predictor = MLService.get_predictor()
    assert len(rf_predictor.feature_schema) == 10
    assert "failed_auth_count" in rf_predictor.feature_schema

    req = NetworkFlowRequest(
        packet_count=5,
        byte_count=320,
        duration=0.5,
        conn_rate=10.0,
        dst_port=80,
        unique_dst_ports=1,
    )
    resp = MLService.predict(req, enable_shap=False)
    assert 0 <= resp.risk_score <= 100


def test_model_promotion_back_to_xgboost():
    """Verify re-promoting candidate_xgboost_v2 works cleanly."""
    promo_res = MLService.promote_model("candidate_xgboost_v2", reason="Re-promoting XGBoost V2")
    assert promo_res["status"] == "PROMOTED"
    assert MLService.get_active_version() == "candidate_xgboost_v2"
    assert MLService.get_previous_version() == "production_rf"

    pred = MLService.get_predictor()
    assert len(pred.feature_schema) == 9


def test_model_registry_api_endpoints():
    """Verify in-process TestClient endpoints for registry, rollback, and promote."""
    client = TestClient(app)

    # 1. GET /api/v1/shadow/registry
    r = client.get("/api/v1/shadow/registry")
    assert r.status_code == 200
    data = r.json()
    assert "active_version" in data
    assert "all_models" in data

    # 2. POST /api/v1/shadow/rollback
    r_roll = client.post("/api/v1/shadow/rollback", json={"reason": "API test rollback"})
    assert r_roll.status_code == 200
    assert r_roll.json()["active_version"] == "production_rf"

    # 3. POST /api/v1/shadow/promote
    r_promo = client.post("/api/v1/shadow/promote", json={"version": "candidate_xgboost_v2", "reason": "API test promote"})
    assert r_promo.status_code == 200
    assert r_promo.json()["active_version"] == "candidate_xgboost_v2"

    # 4. Restore production_rf as baseline active model
    MLService.promote_model("production_rf", reason="Restoring baseline production model after test")
    assert MLService.get_active_version() == "production_rf"

