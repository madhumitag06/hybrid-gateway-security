"""
Evaluation & Benchmarking Schemas
=================================
Pydantic data models for ground-truth synthetic scenario generation,
multi-class classification performance metrics, Traditional Static Policy Baseline
vs Adaptive Policy Engine comparative analysis, and latency/throughput profiling.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from backend.app.schemas.predict import NetworkFlowRequest, SeverityLevel, PolicyAction


# Authoritative Phase 1 Class Ordering
CLASSES: List[str] = ["BENIGN", "PORT_SCAN", "BRUTE_FORCE", "TRAFFIC_SPIKE", "SUSPICIOUS_TRANSFER"]

SuiteNameType = Literal[
    "FULL_BENCHMARK",
    "RECON_SUITE",
    "BRUTE_FORCE_SUITE",
    "VOLUMETRIC_SUITE",
    "EVASION_BORDERLINE_SUITE",
    "BENIGN_SUITE",
]


class BenchmarkScenario(BaseModel):
    scenario_id: str
    ground_truth_class: str
    expected_policy_intent: str = Field(
        ...,
        description="Expected security posture intent: 'ALLOW', 'MONITOR', 'RESTRICT', or 'BLOCK'",
    )
    description: str
    is_borderline: bool = False
    is_allowlisted: bool = False
    source_ip: str
    destination_ip: str
    flow: NetworkFlowRequest


class PerClassMetrics(BaseModel):
    class_name: str
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1_score: float
    fpr: float
    fnr: float


class ConfusionMatrixSchema(BaseModel):
    classes: List[str]
    matrix: List[List[int]]  # Rows: Actual (Ground Truth), Columns: Predicted


class MLClassificationMetrics(BaseModel):
    overall_accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    confusion_matrix: ConfusionMatrixSchema
    per_class_metrics: List[PerClassMetrics]


class PolicyDivergenceRecord(BaseModel):
    scenario_id: str
    ground_truth_class: str
    source_ip: str
    destination_ip: str
    dst_port: int
    packet_count: int
    conn_rate: float
    static_action: str
    static_rule_matched: Optional[str] = None
    adaptive_action: str
    adaptive_risk_score: int
    adaptive_confidence: float
    adaptive_rule_matched: str
    divergence_category: str  # 'SAME_DECISION' | 'STATIC_OVERBLOCK' | 'STATIC_UNDERBLOCK' | 'ADAPTIVE_OVERBLOCK' | 'ADAPTIVE_UNDERBLOCK' | 'POLICY_DIFFERENCE'
    divergence_rationale: str
    is_borderline: bool
    is_allowlisted: bool


class PolicyComparisonMetrics(BaseModel):
    adaptive_action_distribution: Dict[str, int]
    static_action_distribution: Dict[str, int]
    static_over_blocking_count: int
    static_over_blocking_rate: float
    adaptive_over_blocking_count: int
    adaptive_over_blocking_rate: float
    static_under_blocking_count: int
    static_under_blocking_rate: float
    adaptive_under_blocking_count: int
    adaptive_under_blocking_rate: float
    total_divergent_decisions: int
    divergence_rate: float
    borderline_scenarios_count: int
    borderline_gated_to_monitor_count: int
    borderline_gating_effectiveness: float


class LatencyDistribution(BaseModel):
    mean: float
    p50: float
    p95: float
    p99: float


class LatencyBreakdown(BaseModel):
    total_pipeline_latency_ms: LatencyDistribution
    ml_inference_latency_ms: LatencyDistribution
    shap_attribution_latency_ms: Optional[LatencyDistribution] = None
    policy_evaluation_latency_ms: LatencyDistribution
    throughput_flows_per_sec: float
    total_duration_seconds: float


class EvaluationRunRequest(BaseModel):
    suite_name: SuiteNameType = "FULL_BENCHMARK"
    sample_count: int = Field(200, ge=10, le=500, description="Total sample count (max 500)")
    include_shap: bool = Field(True, description="Whether to include SHAP attribution profiling")
    persist_events: bool = Field(False, description="Persist evaluation runs into security_events (default False)")


class EvaluationSuiteInfo(BaseModel):
    suite_name: str
    title: str
    description: str
    default_sample_count: int
    available_classes: List[str]


class EvaluationRunResponse(BaseModel):
    suite_name: str
    total_flows_evaluated: int
    evaluation_timestamp: datetime
    ml_classification_metrics: MLClassificationMetrics
    policy_comparison_metrics: PolicyComparisonMetrics
    latency_metrics: LatencyBreakdown
    divergent_scenarios_sample: List[PolicyDivergenceRecord]
    disclaimer: str = Field(
        default=(
            "Evaluation metrics reflect empirical execution against controlled synthetic benchmark scenarios. "
            "They measure mathematical model sensitivity and rule divergence relative to defined scenario baselines."
        )
    )
