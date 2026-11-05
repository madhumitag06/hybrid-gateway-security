"""
Adaptive Machine Learning API Router
====================================
Exposes endpoints for analyst feedback curation, ground truth label confirmation,
training dataset preparation, isolated candidate retraining, and evaluation review.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.services.adaptive_learning_service import AdaptiveLearningService

router = APIRouter(prefix="/v1/adaptive", tags=["Adaptive ML Learning"])


@router.get(
    "/telemetry",
    summary="Get Adaptive Learning Telemetry",
    description="Returns aggregate counts of ingested traffic, verified feedback labels, class distribution, and candidate training runs.",
)
def get_adaptive_telemetry(db: Session = Depends(get_db)) -> Dict[str, Any]:
    return AdaptiveLearningService.get_telemetry(db)


@router.get(
    "/feedbacks",
    summary="List Flow Records for Feedback Review",
    description="Returns paginated list of network flow records with model predictions and analyst verification status.",
)
def list_feedbacks(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status_filter: Optional[str] = Query(None, description="Filter by status: UNVERIFIED, CONFIRMED, CORRECTED, EXCLUDED"),
    ingestion_id: Optional[str] = Query(None, description="Filter by source PCAP ingestion ID"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    return AdaptiveLearningService.get_feedbacks(
        db=db,
        page=page,
        page_size=page_size,
        status_filter=status_filter,
        ingestion_id=ingestion_id,
    )


@router.post(
    "/feedback",
    summary="Submit Analyst Feedback on Flow Record",
    description="Allows an authorized analyst to confirm, correct, or exclude a model prediction.",
)
def submit_flow_feedback(
    payload: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    feedback_id = payload.get("feedback_id")
    action = payload.get("action", "CONFIRM")
    verified_label = payload.get("verified_label")
    reviewer = payload.get("reviewer", "admin")
    notes = payload.get("notes")

    if not feedback_id:
        raise HTTPException(status_code=400, detail="Missing required field 'feedback_id'.")

    try:
        return AdaptiveLearningService.submit_feedback(
            db=db,
            feedback_id=feedback_id,
            action=action,
            verified_label=verified_label,
            reviewer=reviewer,
            notes=notes,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post(
    "/dataset/prepare",
    summary="Prepare and Validate Verified Training Dataset",
    description="Validates verified labels, checks class balance and feature ranges before retraining.",
)
def prepare_dataset(
    min_samples: int = Query(5, ge=1),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    return AdaptiveLearningService.prepare_training_dataset(db=db, min_samples=min_samples)


@router.post(
    "/train",
    summary="Trigger Isolated Candidate Retraining",
    description="Trains a new versioned candidate model using verified feedback, saving artifacts to an isolated directory without modifying active production weights.",
)
def trigger_retraining(
    payload: Optional[Dict[str, Any]] = Body(None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    body = payload or {}
    candidate_version = body.get("candidate_version")
    created_by = body.get("created_by", "admin")

    try:
        return AdaptiveLearningService.trigger_candidate_training(
            db=db,
            candidate_version=candidate_version,
            created_by=created_by,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get(
    "/runs",
    summary="List Candidate Retraining Runs",
    description="Returns history of all candidate training runs with evaluation metrics and comparison vs active production model.",
)
def list_training_runs(
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    return AdaptiveLearningService.list_runs(db=db, limit=limit)


@router.post(
    "/promote",
    summary="Approve Candidate Model Promotion",
    description="Promotes an evaluated candidate model to authoritative primary after explicit administrator approval.",
)
def approve_candidate_promotion(
    payload: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    run_id = payload.get("run_id")
    approved_by = payload.get("approved_by", "admin")

    if not run_id:
        raise HTTPException(status_code=400, detail="Missing required field 'run_id'.")

    try:
        return AdaptiveLearningService.approve_candidate_promotion(
            db=db,
            run_id=run_id,
            approved_by=approved_by,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post(
    "/rollback",
    summary="Rollback Model Version",
    description="Rolls back active model to the previous standby version.",
)
def rollback_model(
    payload: Optional[Dict[str, Any]] = Body(None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    reason = (payload or {}).get("reason", "Administrator rollback")
    try:
        return AdaptiveLearningService.rollback(db=db, reason=reason)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
