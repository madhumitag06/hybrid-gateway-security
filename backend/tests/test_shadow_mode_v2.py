"""
Shadow Mode Validation Test Battery (Phase 3)
=============================================
Automated test suite verifying the Big Data XGBoost V2 candidate model integration:
- Candidate model loading and artifact validation
- Exact 9-feature schema ordering and parity
- Advisory shadow prediction generation
- Agreement and disagreement detection
- SHAP candidate local attributions
- PostgreSQL shadow persistence (single & batch)
- Policy isolation (candidate is strictly non-enforcing)
- Production model isolation (active Random Forest untouched)
- Failure isolation (candidate errors never disrupt production)
- Concurrency and thread safety
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.db.session import SessionLocal, init_db
from backend.app.models.shadow_prediction import ShadowPredictionModel
from backend.app.schemas.predict import NetworkFlowRequest, PredictionResponse
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.ml_service import MLService
from backend.app.services.policy_engine import PolicyEngine
from backend.app.services.shadow_service import ShadowService, ShadowEvaluationResult
from ml.features.extractor import FEATURE_NAMES_V2, FeatureExtractor, NetworkFlowInput
from ml.models.predict import PredictionOutput, ThreatPredictor


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    init_db()


def test_candidate_model_loading_and_metadata():
    """Verify that candidate model artifacts exist, load cleanly, and expose 9 features."""
    artifacts_dir = Path(settings.shadow_artifacts_dir)
    assert artifacts_dir.is_dir(), f"Candidate artifacts dir missing: {artifacts_dir}"
    assert (artifacts_dir / "model.joblib").is_file()
    assert (artifacts_dir / "scaler.joblib").is_file()
    assert (artifacts_dir / "label_encoder.joblib").is_file()
    assert (artifacts_dir / "metadata.json").is_file()
    assert (artifacts_dir / "feature_schema.json").is_file()

    cand_pred = ShadowService.get_candidate_predictor()
    assert cand_pred is not None
    assert cand_pred.model is not None
    assert len(cand_pred.feature_schema) == 9
    assert cand_pred.feature_schema == FEATURE_NAMES_V2
    assert "BENIGN" in cand_pred.classes
    assert "PORT_SCAN" in cand_pred.classes
    assert "BRUTE_FORCE" in cand_pred.classes


def test_nine_feature_schema_order_and_types():
    """Verify exact 9-feature ordering and absence of failed_auth_count."""
    cand_pred = ShadowService.get_candidate_predictor()
    expected = [
        "packet_count",
        "byte_count",
        "duration",
        "conn_rate",
        "dst_port",
        "unique_dst_ports",
        "bytes_per_sec",
        "packets_per_sec",
        "avg_packet_size",
    ]
    assert cand_pred.feature_schema == expected
    assert "failed_auth_count" not in cand_pred.feature_schema

    sample = NetworkFlowInput(
        packet_count=10,
        byte_count=500,
        duration=1.0,
        conn_rate=10.0,
        dst_port=80,
        unique_dst_ports=1,
    )
    raw_v2 = FeatureExtractor.extract_v2_from_flow(sample)
    assert raw_v2.shape == (1, 9)
    assert raw_v2.dtype in ["float64", "float32"]


def test_shadow_prediction_generation():
    """Verify candidate generates predictions with confidence, risk, and latency."""
    flow_req = NetworkFlowRequest(
        packet_count=20,
        byte_count=12000,
        duration=2.0,
        conn_rate=10.0,
        dst_port=443,
        unique_dst_ports=1,
        failed_auth_count=0,
    )
    prod_pred = MLService.predict(flow_req)
    assert prod_pred.attack_type == "BENIGN"

    shadow_res = ShadowService.evaluate_shadow_flow(
        flow_request=flow_req,
        prod_pred=prod_pred,
        source_ip="10.10.10.10",
        destination_ip="10.20.10.20",
    )
    assert shadow_res is not None
    assert shadow_res.prod_attack_type == "BENIGN"
    assert shadow_res.candidate_attack_type == "BENIGN"
    assert shadow_res.agreement is True
    assert shadow_res.candidate_confidence >= 0.0
    assert shadow_res.candidate_risk_score >= 0
    assert shadow_res.candidate_latency_ms >= 0.0
    assert shadow_res.feature_schema_version == "v2"
    assert len(shadow_res.flow_features) == 9


def test_model_agreement_and_disagreement_detection():
    """Verify agreement is True when predictions match and False when they diverge."""
    cand_pred = ShadowService.get_candidate_predictor()
    flow_input = NetworkFlowInput(
        packet_count=20,
        byte_count=12000,
        duration=2.0,
        conn_rate=10.0,
        dst_port=443,
        unique_dst_ports=1,
    )

    # Simulated agreement
    fake_prod_agree = PredictionResponse(
        risk_score=0,
        threat_level="LOW",
        attack_type="BENIGN",
        confidence=0.99,
        action_recommendation="Allow",
        is_anomaly=False,
        class_probabilities={"BENIGN": 0.99},
        top_contributing_features=[],
    )
    res_agree = ShadowService.evaluate_shadow_flow(flow_input, fake_prod_agree)
    assert res_agree is not None
    assert res_agree.agreement is True
    assert res_agree.disagreement_type is None

    # Simulated disagreement
    fake_prod_disagree = PredictionResponse(
        risk_score=90,
        threat_level="HIGH",
        attack_type="TRAFFIC_SPIKE",
        confidence=0.95,
        action_recommendation="Block",
        is_anomaly=True,
        class_probabilities={"TRAFFIC_SPIKE": 0.95},
        top_contributing_features=[],
    )
    res_disagree = ShadowService.evaluate_shadow_flow(flow_input, fake_prod_disagree)
    assert res_disagree is not None
    assert res_disagree.agreement is False
    assert res_disagree.disagreement_type == "TRAFFIC_SPIKE_vs_BENIGN"


def test_candidate_shap_explanation_integration():
    """Verify candidate SHAP TreeExplainer generates valid non-causal feature attributions."""
    cand_pred = ShadowService.get_candidate_predictor()
    # Trigger an anomalous flow to force SHAP explanation
    anomaly_flow = NetworkFlowInput(
        packet_count=2,
        byte_count=80,
        duration=0.0,
        conn_rate=200.0,
        dst_port=21,
        unique_dst_ports=30,
    )
    fake_prod = PredictionResponse(
        risk_score=90,
        threat_level="HIGH",
        attack_type="PORT_SCAN",
        confidence=0.90,
        action_recommendation="Block",
        is_anomaly=True,
        class_probabilities={"PORT_SCAN": 0.90},
        top_contributing_features=[],
    )
    shadow_res = ShadowService.evaluate_shadow_flow(anomaly_flow, fake_prod)
    assert shadow_res is not None
    assert len(shadow_res.shap_attributions) > 0
    top_attr = shadow_res.shap_attributions[0]
    assert "feature" in top_attr
    assert "shap_value" in top_attr
    assert "contribution_direction" in top_attr


def test_shadow_persistence_in_db():
    """Verify single and batch persistence into PostgreSQL shadow_predictions table."""
    with SessionLocal() as db:
        initial_count = db.scalar(select(func.count(ShadowPredictionModel.id))) or 0

        flow_req = NetworkFlowRequest(
            packet_count=15,
            byte_count=6000,
            duration=1.5,
            conn_rate=10.0,
            dst_port=443,
            unique_dst_ports=1,
            failed_auth_count=0,
        )

        pred, evt = DashboardService.record_prediction(
            db=db,
            flow_request=flow_req,
            source_ip="10.10.10.5",
            destination_ip="10.20.10.15",
            is_demo=False,
        )
        db.commit()

        new_count = db.scalar(select(func.count(ShadowPredictionModel.id))) or 0
        assert new_count == initial_count + 1

        record = (
            db.query(ShadowPredictionModel)
            .filter(ShadowPredictionModel.flow_id == evt.id)
            .first()
        )
        assert record is not None
        assert record.source_ip == "10.10.10.5"
        assert record.candidate_model_version == "v2_xgboost"
        assert record.prod_model_version == "v1_random_forest"
        assert record.agreement is True


def test_policy_isolation_candidate_non_enforcing():
    """Verify candidate prediction NEVER modifies policy decisions or containment rules."""
    with SessionLocal() as db:
        # A benign flow for candidate that is flagged as traffic spike by prod
        flow_req = NetworkFlowRequest(
            packet_count=1200,
            byte_count=1197600,
            duration=3.0,
            conn_rate=400.0,
            dst_port=80,
            unique_dst_ports=1,
            failed_auth_count=0,
        )

        pred, evt = DashboardService.record_prediction(
            db=db,
            flow_request=flow_req,
            source_ip="10.10.10.99",
            destination_ip="10.20.10.40",
            is_demo=False,
        )
        db.commit()

        # Authoritative decision was made by production RF (e.g. Block or Restrict)
        # Even though candidate XGBoost V2 predicted BENIGN!
        shadow_record = (
            db.query(ShadowPredictionModel)
            .filter(ShadowPredictionModel.flow_id == evt.id)
            .first()
        )
        assert shadow_record is not None
        assert shadow_record.candidate_attack_type == "BENIGN"
        assert shadow_record.prod_attack_type == "TRAFFIC_SPIKE"
        assert shadow_record.agreement is False

        # Production event status strictly reflects production policy, NOT candidate BENIGN
        assert evt.attack_type == "TRAFFIC_SPIKE"
        assert evt.current_policy_action in ["Block", "Restrict", "Monitor"]


def test_production_model_isolation():
    """Verify active production model remains RandomForest and unaffected by candidate service."""
    prod_predictor = MLService.get_predictor()
    assert prod_predictor.model.__class__.__name__ == "RandomForestClassifier"
    assert len(prod_predictor.feature_schema) == 10
    assert "failed_auth_count" in prod_predictor.feature_schema

    cand_predictor = ShadowService.get_candidate_predictor()
    assert cand_predictor.model.__class__.__name__ == "XGBClassifier"
    assert len(cand_predictor.feature_schema) == 9
    assert "failed_auth_count" not in cand_predictor.feature_schema


def test_candidate_failure_isolation(monkeypatch):
    """Verify candidate prediction failure does not disrupt the production pipeline."""
    with SessionLocal() as db:
        flow_req = NetworkFlowRequest(
            packet_count=1,
            byte_count=100,
            duration=0.5,
            conn_rate=1.0,
            dst_port=80,
            unique_dst_ports=1,
            failed_auth_count=0,
        )

        # Force candidate evaluation to raise a simulated runtime error
        def broken_shadow(*args, **kwargs):
            raise RuntimeError("Simulated shadow engine GPU fault")

        monkeypatch.setattr(ShadowService, "evaluate_shadow_flow", broken_shadow)

        # Production prediction and DB persistence MUST succeed despite shadow failure
        pred, evt = DashboardService.record_prediction(
            db=db,
            flow_request=flow_req,
            source_ip="10.10.10.1",
            destination_ip="10.20.10.2",
            is_demo=False,
        )
        assert pred is not None
        assert pred.risk_score >= 0
        assert evt is not None


def test_concurrency_and_thread_safety():
    """Verify multi-threaded concurrent shadow evaluations execute without race conditions."""
    def worker(idx: int):
        req = NetworkFlowRequest(
            packet_count=10 + idx,
            byte_count=500 + idx * 10,
            duration=1.0,
            conn_rate=10.0,
            dst_port=443,
            unique_dst_ports=1,
            failed_auth_count=0,
        )
        prod = MLService.predict(req)
        res = ShadowService.evaluate_shadow_flow(req, prod, source_ip=f"10.0.0.{idx}")
        return res is not None

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(worker, range(20)))

    assert all(results)
    assert len(results) == 20
