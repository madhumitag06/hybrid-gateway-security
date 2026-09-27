"""
Security Analytics & Flow Explainability REST API Endpoints
===========================================================
Provides historical analytics summaries, histogram distributions, provenance metrics,
and on-demand SHAP explanations for arbitrary network flow vectors.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.schemas.analytics import (
    AnalyticsSummaryResponse,
    DetailedFeatureAttribution,
    FlowExplanationRequest,
    FlowExplanationResponse,
)
from backend.app.services.analytics_service import AnalyticsService
from backend.app.services.explainability_service import ExplainabilityService
from backend.app.services.ml_service import MLService
from backend.app.services.policy_engine import PolicyEngine

router = APIRouter(prefix="/analytics", tags=["Security Analytics & Explainability"])


@router.get(
    "/summary",
    response_model=AnalyticsSummaryResponse,
    summary="Get Security Analytics Summary",
    description="Returns historical distributions across Analytics Histogram Buckets, attack types, hybrid zones, and telemetry provenance.",
)
def get_analytics_summary(db: Session = Depends(get_db)) -> AnalyticsSummaryResponse:
    return AnalyticsService.get_summary(db)


@router.post(
    "/explain-flow",
    response_model=FlowExplanationResponse,
    summary="Explain Flow Vector Inference via SHAP",
    description="Computes full 10-feature Shapley attributions, predicted class probability baseline, and policy engine decision trace for an arbitrary flow vector.",
)
def explain_arbitrary_flow(req: FlowExplanationRequest) -> FlowExplanationResponse:
    # 1. Real ML Inference
    pred = MLService.predict(req.flow)

    # 2. Contextual Policy Decision
    decision = PolicyEngine.evaluate(
        prediction=pred,
        source_ip=req.flow.source_ip or "192.168.1.100",
        destination_ip=req.flow.destination_ip or "10.100.1.10",
        dst_port=req.flow.dst_port,
        protocol="TCP",
        custom_allowlist=req.custom_allowlist,
    )

    # 3. Full SHAP Explanation
    explain_svc = ExplainabilityService.get_instance()
    full_explanation = explain_svc.get_full_explanation(
        flow_input=req.flow,
        predicted_class=pred.attack_type,
        risk_score=pred.risk_score,
        confidence=pred.confidence,
        policy_action=decision.policy_action,
        policy_rule_name=decision.rule_name,
        enforcement_status="Simulated",
    )

    return FlowExplanationResponse(
        attack_type=pred.attack_type,
        confidence=pred.confidence,
        risk_score=pred.risk_score,
        threat_level=pred.threat_level,
        action_recommendation=pred.action_recommendation,
        enacted_policy_decision=decision.policy_action,
        policy_rule_name=decision.rule_name,
        expected_base_probability=full_explanation["expected_base_probability"],
        feature_attributions=[
            DetailedFeatureAttribution(**fa)
            for fa in full_explanation["feature_attributions"]
        ],
        top_positive_contributors=[
            DetailedFeatureAttribution(**fa)
            for fa in full_explanation["top_positive_contributors"]
        ],
        top_mitigating_contributors=[
            DetailedFeatureAttribution(**fa)
            for fa in full_explanation["top_mitigating_contributors"]
        ],
        disclaimer=full_explanation["disclaimer"],
    )
