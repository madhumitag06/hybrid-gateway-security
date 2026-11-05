"""
Test Suite for PCAP Ingestion Persistence & Adaptive ML Learning Pipeline
==========================================================================
Validates:
1. PCAP ingestion persistence in PostgreSQL (pcap_ingestions).
2. Latest ingestion and history API endpoints.
3. Automated flow feedback record generation in adaptive_flow_feedbacks.
4. Analyst feedback actions (CONFIRM, CORRECT, EXCLUDE, RESET).
5. Versioned dataset preparation (schema validation, NaN/Inf checks, sample gates).
6. Isolated candidate retraining in ml/models/candidates/ without active model modification.
7. Controlled candidate promotion and safety rollback.
"""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.db.session import SessionLocal, engine
from backend.app.db.base import Base
from backend.app.main import app
from backend.app.models.pcap_ingestion import PcapIngestionModel
from backend.app.models.adaptive_learning import AdaptiveFlowFeedbackModel, AdaptiveTrainingRunModel
from backend.app.services.ingestion_service import IngestionService
from backend.app.services.adaptive_learning_service import AdaptiveLearningService
from backend.app.services.ml_service import MLService
from backend.app.services.sample_pcap_generator import ensure_sample_pcaps, SAMPLE_DIR


client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_environment():
    """Ensure database tables exist and sample PCAPs are generated."""
    Base.metadata.create_all(bind=engine)
    ensure_sample_pcaps()
    # Reset ML service to baseline state
    MLService.promote_model("production_rf", reason="Test suite setup")
    yield
    MLService.promote_model("production_rf", reason="Test suite teardown")


def test_pcap_ingestion_persistence():
    """Verify PCAP ingestion records are persisted to PostgreSQL and retrievable."""
    sample_file = "port_scan.pcap"
    resp = client.post(f"/api/v1/ingest/samples/{sample_file}?persist=true")
    assert resp.status_code == 200, f"Failed sample ingestion: {resp.text}"
    data = resp.json()
    assert data["filename"] == sample_file
    assert data["flows_evaluated"] > 0

    # 1. Test GET /api/v1/ingest/latest
    latest_resp = client.get("/api/v1/ingest/latest")
    assert latest_resp.status_code == 200
    latest_data = latest_resp.json()
    assert latest_data["status"] in ["FOUND", "success"]
    assert latest_data["ingestion"] is not None
    assert latest_data["ingestion"]["filename"] == sample_file
    assert latest_data["ingestion"]["flows_evaluated"] == data["flows_evaluated"]

    # 2. Test GET /api/v1/ingest/history
    hist_resp = client.get("/api/v1/ingest/history?page=1&page_size=10")
    assert hist_resp.status_code == 200
    hist_data = hist_resp.json()
    assert hist_data["total"] >= 1
    assert any(ing["filename"] == sample_file for ing in hist_data["ingestions"])

    # 3. Test GET /api/v1/ingest/history/{ingestion_id}
    ing_id = latest_data["ingestion"]["id"]
    detail_resp = client.get(f"/api/v1/ingest/history/{ing_id}")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.json()
    fetched_id = detail_data.get("ingestion", {}).get("id") if "ingestion" in detail_data else detail_data.get("id")
    assert fetched_id == ing_id


def test_adaptive_telemetry_and_feedback():
    """Verify flow feedbacks are automatically seeded and analyst review operates cleanly."""
    # Check telemetry
    tel_resp = client.get("/api/v1/adaptive/telemetry")
    assert tel_resp.status_code == 200
    tel_data = tel_resp.json()
    assert tel_data["total_extracted_flows"] > 0
    assert tel_data["unverified_flow_count"] > 0

    # List feedbacks
    fb_list_resp = client.get("/api/v1/adaptive/feedbacks?page=1&page_size=10")
    assert fb_list_resp.status_code == 200
    records = fb_list_resp.json()["records"]
    assert len(records) > 0

    target_record = records[0]
    rec_id = target_record["id"]

    # 1. Submit CONFIRM
    confirm_resp = client.post(
        "/api/v1/adaptive/feedback",
        json={
            "feedback_id": rec_id,
            "action": "CONFIRM",
            "reviewer": "test_analyst",
        },
    )
    assert confirm_resp.status_code == 200
    conf_data = confirm_resp.json()
    assert conf_data["feedback_status"] == "CONFIRMED"
    assert conf_data["verified_label"] == target_record["predicted_class"]
    assert conf_data["is_training_eligible"] is True

    # 2. Submit CORRECT
    correct_resp = client.post(
        "/api/v1/adaptive/feedback",
        json={
            "feedback_id": rec_id,
            "action": "CORRECT",
            "verified_label": "PORT_SCAN",
            "reviewer": "test_analyst",
        },
    )
    assert correct_resp.status_code == 200
    corr_data = correct_resp.json()
    assert corr_data["feedback_status"] == "CORRECTED"
    assert corr_data["verified_label"] == "PORT_SCAN"

    # 3. Submit EXCLUDE
    exclude_resp = client.post(
        "/api/v1/adaptive/feedback",
        json={
            "feedback_id": rec_id,
            "action": "EXCLUDE",
            "reviewer": "test_analyst",
        },
    )
    assert exclude_resp.status_code == 200
    assert exclude_resp.json()["feedback_status"] == "EXCLUDED"
    assert exclude_resp.json()["is_training_eligible"] is False

    # 4. Submit RESET
    reset_resp = client.post(
        "/api/v1/adaptive/feedback",
        json={
            "feedback_id": rec_id,
            "action": "RESET",
            "reviewer": "test_analyst",
        },
    )
    assert reset_resp.status_code == 200
    assert reset_resp.json()["feedback_status"] == "UNVERIFIED"


def test_adaptive_dataset_and_retraining_safety():
    """Verify versioned training dataset preparation and isolated candidate retraining."""
    db = SessionLocal()
    try:
        # Seed 6 verified feedbacks to exceed min_samples threshold
        sample_records = db.query(AdaptiveFlowFeedbackModel).limit(6).all()
        for i, rec in enumerate(sample_records):
            rec.feedback_status = "CONFIRMED"
            rec.verified_label = "BRUTE_FORCE" if i % 2 == 0 else "BENIGN"
            rec.is_training_eligible = True
        db.commit()
    finally:
        db.close()

    # 1. Prepare training dataset
    prep_resp = client.post("/api/v1/adaptive/dataset/prepare?min_samples=5")
    assert prep_resp.status_code == 200
    prep_data = prep_resp.json()
    assert prep_data["eligible"] is True
    assert len(prep_data["features_used"]) == 9
    assert prep_data["valid_samples"] >= 5

    # 2. Trigger isolated candidate training
    import time
    cand_ver = f"test_cand_{int(time.time() * 1000)}"
    train_resp = client.post(
        "/api/v1/adaptive/train",
        json={
            "candidate_version": cand_ver,
            "created_by": "test_operator",
        },
    )
    assert train_resp.status_code == 200, f"Train failed: {train_resp.text}"
    train_data = train_resp.json()
    assert train_data["candidate_version"] == cand_ver
    assert train_data["status"] == "COMPLETED"
    assert train_data["training_metrics"]["accuracy"] > 0.0

    # Verify active model was NOT overwritten
    active_ver = MLService.get_active_version()
    assert active_ver == "production_rf" or active_ver == "candidate_xgboost_v2"
    assert active_ver != cand_ver

    # 3. Controlled Promotion
    run_id = train_data["id"]
    promote_resp = client.post(
        "/api/v1/adaptive/promote",
        json={"run_id": run_id, "approved_by": "test_operator"},
    )
    assert promote_resp.status_code == 200
    assert MLService.get_active_version() == cand_ver

    # 4. Controlled Rollback
    rollback_resp = client.post(
        "/api/v1/adaptive/rollback",
        json={"reason": "Testing rollback to standby"},
    )
    assert rollback_resp.status_code == 200
    assert MLService.get_active_version() != cand_ver
