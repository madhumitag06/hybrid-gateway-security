"""
Shadow Mode Comparison API Router (Phase 3)
===========================================
Exposes candidate model telemetry, agreement statistics, and shadow evaluation logs
without impacting production policy enforcement.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models.shadow_prediction import ShadowPredictionModel
from backend.app.services.shadow_service import ShadowService

router = APIRouter(prefix="/v1/shadow", tags=["Shadow Mode (XGBoost V2 Candidate)"])


@router.get(
    "/status",
    summary="Get Shadow Mode Candidate Model Status",
    description="Returns the operational status, feature schema, and configuration of the candidate XGBoost V2 model.",
)
def get_shadow_status() -> Dict[str, Any]:
    return ShadowService.get_status()


@router.get(
    "/comparison",
    summary="Get Production vs Candidate Comparison Telemetry",
    description="Returns aggregated agreement metrics, latency comparisons, and recent shadow prediction results.",
)
def get_shadow_comparison(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    # Total evaluated
    total_count = db.scalar(select(func.count(ShadowPredictionModel.id))) or 0
    agreement_count = db.scalar(
        select(func.count(ShadowPredictionModel.id)).where(ShadowPredictionModel.agreement == True)
    ) or 0
    disagreement_count = total_count - agreement_count
    agreement_rate = round((agreement_count / total_count * 100.0), 2) if total_count > 0 else 100.0

    # Latencies
    avg_prod_lat = db.scalar(select(func.avg(ShadowPredictionModel.prod_latency_ms))) or 0.0
    avg_cand_lat = db.scalar(select(func.avg(ShadowPredictionModel.candidate_latency_ms))) or 0.0

    # Disagreement Breakdown
    disagreements = (
        db.execute(
            select(
                ShadowPredictionModel.disagreement_type,
                func.count(ShadowPredictionModel.id),
            )
            .where(ShadowPredictionModel.agreement == False)
            .group_by(ShadowPredictionModel.disagreement_type)
        )
        .all()
    )
    disagreement_map = {row[0]: row[1] for row in disagreements if row[0]}

    # Candidate Attack Type Breakdown
    cand_dist = (
        db.execute(
            select(
                ShadowPredictionModel.candidate_attack_type,
                func.count(ShadowPredictionModel.id),
            )
            .group_by(ShadowPredictionModel.candidate_attack_type)
        )
        .all()
    )
    cand_dist_map = {row[0]: row[1] for row in cand_dist if row[0]}

    # Recent evaluation logs
    recent_records = (
        db.scalars(
            select(ShadowPredictionModel)
            .order_by(desc(ShadowPredictionModel.timestamp))
            .limit(limit)
        )
        .all()
    )

    recent_list = [
        {
            "id": r.id,
            "flow_id": r.flow_id,
            "timestamp": r.timestamp.isoformat(),
            "source_ip": r.source_ip,
            "destination_ip": r.destination_ip,
            "dst_port": r.dst_port,
            "protocol": r.protocol,
            "prod_attack_type": r.prod_attack_type,
            "prod_confidence": round(r.prod_confidence, 4),
            "prod_risk_score": r.prod_risk_score,
            "prod_latency_ms": round(r.prod_latency_ms, 3),
            "candidate_attack_type": r.candidate_attack_type,
            "candidate_confidence": round(r.candidate_confidence, 4),
            "candidate_risk_score": r.candidate_risk_score,
            "candidate_latency_ms": round(r.candidate_latency_ms, 3),
            "agreement": r.agreement,
            "disagreement_type": r.disagreement_type,
            "shap_attributions": r.shap_attributions,
        }
        for r in recent_records
    ]

    return {
        "candidate_status": ShadowService.get_status(),
        "summary": {
            "total_evaluated": total_count,
            "agreement_count": agreement_count,
            "disagreement_count": disagreement_count,
            "agreement_rate_pct": agreement_rate,
            "avg_prod_latency_ms": round(float(avg_prod_lat), 3),
            "avg_candidate_latency_ms": round(float(avg_cand_lat), 3),
        },
        "disagreements_by_type": disagreement_map,
        "candidate_distribution": cand_dist_map,
        "recent_comparisons": recent_list,
    }


@router.get(
    "/records",
    summary="Get Paginated Shadow Prediction Records",
    description="Returns detailed records from the shadow_predictions table.",
)
def get_shadow_records(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    disagreement_only: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    query = select(ShadowPredictionModel)
    if disagreement_only:
        query = query.where(ShadowPredictionModel.agreement == False)

    total_matching = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    records = db.scalars(
        query.order_by(desc(ShadowPredictionModel.timestamp))
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    return {
        "total": total_matching,
        "page": page,
        "page_size": page_size,
        "records": [
            {
                "id": r.id,
                "flow_id": r.flow_id,
                "timestamp": r.timestamp.isoformat(),
                "source_ip": r.source_ip,
                "destination_ip": r.destination_ip,
                "dst_port": r.dst_port,
                "prod_attack_type": r.prod_attack_type,
                "prod_confidence": round(r.prod_confidence, 4),
                "prod_risk_score": r.prod_risk_score,
                "candidate_attack_type": r.candidate_attack_type,
                "candidate_confidence": round(r.candidate_confidence, 4),
                "candidate_risk_score": r.candidate_risk_score,
                "agreement": r.agreement,
                "disagreement_type": r.disagreement_type,
                "flow_features": r.flow_features,
                "shap_attributions": r.shap_attributions,
            }
            for r in records
        ],
    }


@router.get(
    "/registry",
    summary="Get Model Lifecycle Registry and Promotion History",
    description="Returns active and standby model versions, feature schemas, algorithms, and promotion audit trail.",
)
def get_model_registry() -> Dict[str, Any]:
    from backend.app.services.ml_service import MLService
    return MLService.get_registry_status()


@router.post(
    "/promote",
    summary="Promote Model Version",
    description="Promotes a validated model version (e.g. candidate_xgboost_v2) to authoritative production primary.",
)
def promote_model_endpoint(payload: Dict[str, str]) -> Dict[str, Any]:
    from backend.app.services.ml_service import MLService
    version = payload.get("version", "candidate_xgboost_v2")
    reason = payload.get("reason", "API-triggered controlled model promotion")
    return MLService.promote_model(version, reason=reason)


@router.post(
    "/rollback",
    summary="Rollback Model Version",
    description="Restores the previous model version as authoritative production primary with zero downtime.",
)
def rollback_model_endpoint(payload: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    from backend.app.services.ml_service import MLService
    reason = (payload or {}).get("reason", "API-triggered emergency rollback")
    return MLService.rollback(reason=reason)

