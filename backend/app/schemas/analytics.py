"""
Security Analytics & Explainability Schemas
===========================================
Pydantic schemas for historical telemetry distributions, analytics histogram bins,
telemetry provenance breakdowns, and full SHAP waterfall explanations.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.schemas.predict import NetworkFlowRequest, SeverityLevel, PolicyAction


class AnalyticsHistogramBin(BaseModel):
    bin_label: str = Field(..., description="Analytics Histogram Bucket label, e.g. '0-19', '20-39'")
    min_score: int = Field(..., ge=0, le=100)
    max_score: int = Field(..., ge=0, le=100)
    count: int = Field(..., ge=0)
    percentage: float = Field(..., ge=0.0, le=100.0)


class AttackTypeDistribution(BaseModel):
    attack_type: str
    count: int
    percentage: float


class ZoneTrafficDistribution(BaseModel):
    traffic_direction: str
    count: int
    percentage: float


class TelemetryProvenanceDistribution(BaseModel):
    telemetry_source: str
    count: int
    percentage: float
    is_real_telemetry: bool = Field(
        ..., description="True for real PCAP and real AWS VPC Flow Logs; False for fixtures and demo seeds"
    )


class PolicyDecisionDistribution(BaseModel):
    policy_action: PolicyAction
    count: int
    percentage: float


class GlobalFeatureSensitivity(BaseModel):
    feature: str
    mean_abs_shap: float
    importance_rank: int


class AnalyticsSummaryResponse(BaseModel):
    total_events_evaluated: int
    real_telemetry_events: int
    fixture_demo_events: int
    active_sandbox_rules_count: int
    histogram_buckets: List[AnalyticsHistogramBin]
    attack_type_distribution: List[AttackTypeDistribution]
    zone_traffic_distribution: List[ZoneTrafficDistribution]
    telemetry_provenance_distribution: List[TelemetryProvenanceDistribution]
    policy_decision_distribution: List[PolicyDecisionDistribution]
    top_sensitive_features: List[GlobalFeatureSensitivity]
    generated_at_utc: datetime


class DetailedFeatureAttribution(BaseModel):
    feature: str
    value: float
    shap_value: float
    contribution_direction: str
    description: str
    deviation_z_score: Optional[float] = None


class PolicyReasoningTrace(BaseModel):
    enacted_policy_action: PolicyAction
    policy_rule_name: str
    enforcement_status: str
    is_confidence_gated: bool
    is_allowlisted: bool


class EventExplanationResponse(BaseModel):
    event_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    telemetry_source: str
    attack_type: str
    confidence: float
    risk_score: int
    threat_level: SeverityLevel
    expected_base_probability: float
    all_base_values: Dict[str, float]
    feature_attributions: List[DetailedFeatureAttribution]
    top_positive_contributors: List[DetailedFeatureAttribution]
    top_mitigating_contributors: List[DetailedFeatureAttribution]
    policy_reasoning: PolicyReasoningTrace
    disclaimer: str = Field(
        default=(
            "SHAP feature attributions quantify statistical sensitivity of the decision trees "
            "to individual input values. They provide mathematical model transparency and do not "
            "constitute physical or legal proof of malicious causality."
        )
    )


class FlowExplanationRequest(BaseModel):
    flow: NetworkFlowRequest
    custom_allowlist: Optional[List[str]] = None


class FlowExplanationResponse(BaseModel):
    attack_type: str
    confidence: float
    risk_score: int
    threat_level: SeverityLevel
    action_recommendation: PolicyAction
    enacted_policy_decision: PolicyAction
    policy_rule_name: str
    expected_base_probability: float
    feature_attributions: List[DetailedFeatureAttribution]
    top_positive_contributors: List[DetailedFeatureAttribution]
    top_mitigating_contributors: List[DetailedFeatureAttribution]
    disclaimer: str
