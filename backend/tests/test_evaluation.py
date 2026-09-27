"""
Unit & Integration Tests for Evaluation & Benchmarking Suite
============================================================
Validates scenario dataset generation, multi-class confusion matrix, precision/recall/F1,
FPR/FNR metrics, Traditional Static Policy Baseline vs Adaptive Policy Engine divergence,
over/under-blocking rates, borderline confidence gating, and evaluation REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.evaluation import CLASSES, EvaluationRunRequest
from backend.app.services.evaluation.comparative_service import ComparativeEvaluationService
from backend.app.services.evaluation.dataset_generator import EvaluationDatasetGenerator


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# =====================================================================
# 1. Dataset Generator Tests
# =====================================================================

def test_dataset_generator_deterministic_reproducibility():
    """Verify that identical seeds produce strictly identical scenario datasets."""
    suite1 = EvaluationDatasetGenerator.generate_suite("FULL_BENCHMARK", sample_count=50, seed=42)
    suite2 = EvaluationDatasetGenerator.generate_suite("FULL_BENCHMARK", sample_count=50, seed=42)

    assert len(suite1) == 50
    assert len(suite2) == 50
    for s1, s2 in zip(suite1, suite2):
        assert s1.scenario_id == s2.scenario_id
        assert s1.ground_truth_class == s2.ground_truth_class
        assert s1.flow.packet_count == s2.flow.packet_count
        assert s1.flow.byte_count == s2.flow.byte_count
        assert s1.flow.dst_port == s2.flow.dst_port


def test_dataset_generator_all_classes_and_edge_cases():
    """Verify presence of all 5 classes, allowlisted admin, and borderline edge cases."""
    suite = EvaluationDatasetGenerator.generate_suite("FULL_BENCHMARK", sample_count=200)

    classes_present = {s.ground_truth_class for s in suite}
    for c in CLASSES:
        assert c in classes_present, f"Class {c} must be present in FULL_BENCHMARK"

    has_allowlist = any(s.is_allowlisted for s in suite)
    has_borderline = any(s.is_borderline for s in suite)
    assert has_allowlist is True, "Allowlist scenario must be present in benchmark"
    assert has_borderline is True, "Borderline scenario must be present in benchmark"


def test_specialized_suites_generation():
    """Verify specialized scenario suites generate expected threat distributions."""
    recon_suite = EvaluationDatasetGenerator.generate_suite("RECON_SUITE", sample_count=30)
    assert all(s.ground_truth_class == "PORT_SCAN" for s in recon_suite)

    brute_suite = EvaluationDatasetGenerator.generate_suite("BRUTE_FORCE_SUITE", sample_count=30)
    assert all(s.ground_truth_class == "BRUTE_FORCE" for s in brute_suite)

    benign_suite = EvaluationDatasetGenerator.generate_suite("BENIGN_SUITE", sample_count=30)
    assert all(s.ground_truth_class == "BENIGN" for s in benign_suite)


# =====================================================================
# 2. Mathematical Metrics & Zero-Division Safety Tests
# =====================================================================

def test_ml_classification_metrics_math_and_zero_division():
    """Verify confusion matrix and metrics computation with division safety."""
    # Synthetic test vector with perfect match
    gt = ["BENIGN", "PORT_SCAN", "BRUTE_FORCE", "TRAFFIC_SPIKE", "SUSPICIOUS_TRANSFER"]
    pred = ["BENIGN", "PORT_SCAN", "BRUTE_FORCE", "TRAFFIC_SPIKE", "SUSPICIOUS_TRANSFER"]

    metrics = ComparativeEvaluationService._calculate_ml_metrics(gt, pred)
    assert metrics.overall_accuracy == 1.0
    assert metrics.macro_f1 == 1.0

    for pc in metrics.per_class_metrics:
        assert pc.tp == 1
        assert pc.fp == 0
        assert pc.fn == 0
        assert pc.precision == 1.0
        assert pc.recall == 1.0
        assert pc.f1_score == 1.0
        assert pc.fpr == 0.0
        assert pc.fnr == 0.0

    # Test with unpredicted class (zero denominator handling)
    gt_zero = ["BENIGN", "BENIGN", "PORT_SCAN"]
    pred_zero = ["BENIGN", "BENIGN", "BENIGN"]  # PORT_SCAN never predicted

    m_zero = ComparativeEvaluationService._calculate_ml_metrics(gt_zero, pred_zero)
    assert 0.0 <= m_zero.overall_accuracy <= 1.0
    assert 0.0 <= m_zero.macro_precision <= 1.0
    assert 0.0 <= m_zero.macro_recall <= 1.0


# =====================================================================
# 3. Policy Divergence & Gating Tests
# =====================================================================

def test_comparative_policy_evaluation_metrics():
    """Verify independent over-blocking, under-blocking, and divergence metrics."""
    req = EvaluationRunRequest(
        suite_name="FULL_BENCHMARK",
        sample_count=100,
        include_shap=False,
        persist_events=False,
    )
    res = ComparativeEvaluationService.run_evaluation(req)

    assert res.total_flows_evaluated == 100
    pm = res.policy_comparison_metrics

    # Verify rates are bounded within [0.0, 1.0]
    assert 0.0 <= pm.static_over_blocking_rate <= 1.0
    assert 0.0 <= pm.adaptive_over_blocking_rate <= 1.0
    assert 0.0 <= pm.static_under_blocking_rate <= 1.0
    assert 0.0 <= pm.adaptive_under_blocking_rate <= 1.0
    assert 0.0 <= pm.divergence_rate <= 1.0
    assert 0.0 <= pm.borderline_gating_effectiveness <= 1.0

    # Verify latency distributions are populated
    assert res.latency_metrics.total_pipeline_latency_ms.mean > 0.0
    assert res.latency_metrics.throughput_flows_per_sec > 0.0
    assert res.latency_metrics.total_duration_seconds > 0.0


# =====================================================================
# 4. REST API Endpoint Tests
# =====================================================================

def test_api_list_suites(client: TestClient):
    """Verify GET /api/v1/evaluation/suites returns all defined suites."""
    resp = client.get("/api/v1/evaluation/suites")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 6
    suite_names = [s["suite_name"] for s in data]
    assert "FULL_BENCHMARK" in suite_names
    assert "RECON_SUITE" in suite_names


def test_api_run_evaluation(client: TestClient):
    """Verify POST /api/v1/evaluation/run returns empirical results."""
    payload = {
        "suite_name": "FULL_BENCHMARK",
        "sample_count": 50,
        "include_shap": True,
        "persist_events": False,
    }
    resp = client.post("/api/v1/evaluation/run", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["suite_name"] == "FULL_BENCHMARK"
    assert data["total_flows_evaluated"] == 50
    assert "ml_classification_metrics" in data
    assert "policy_comparison_metrics" in data
    assert "latency_metrics" in data
    assert len(data["ml_classification_metrics"]["confusion_matrix"]["matrix"]) == 5
    assert len(data["divergent_scenarios_sample"]) > 0


def test_api_run_evaluation_validation_errors(client: TestClient):
    """Verify rejection of invalid sample count and suite names."""
    # Sample count too large (> 500)
    resp_large = client.post(
        "/api/v1/evaluation/run",
        json={"suite_name": "FULL_BENCHMARK", "sample_count": 999},
    )
    assert resp_large.status_code in [400, 422]

    # Sample count too small (< 10)
    resp_small = client.post(
        "/api/v1/evaluation/run",
        json={"suite_name": "FULL_BENCHMARK", "sample_count": 2},
    )
    assert resp_small.status_code in [400, 422]


def test_api_export_evaluation(client: TestClient):
    """Verify GET /api/v1/evaluation/export generates downloadable JSON and CSV reports."""
    # JSON export
    resp_json = client.get("/api/v1/evaluation/export?suite_name=FULL_BENCHMARK&sample_count=50&export_format=json")
    assert resp_json.status_code == 200
    assert "application/json" in resp_json.headers.get("content-type", "")

    # CSV export
    resp_csv = client.get("/api/v1/evaluation/export?suite_name=FULL_BENCHMARK&sample_count=50&export_format=csv")
    assert resp_csv.status_code == 200
    assert "text/csv" in resp_csv.headers.get("content-type", "")
    assert "GATEWAY EVALUATION BENCHMARK REPORT" in resp_csv.text
