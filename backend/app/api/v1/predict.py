"""
Prediction API Router (v1)
==========================
Handles network flow threat analysis requests using the Phase 1 machine learning model.
"""

from typing import Dict, List
from fastapi import APIRouter, HTTPException, status
from backend.app.schemas.predict import (
    BatchPredictionRequest,
    BatchPredictionResponse,
    NetworkFlowRequest,
    PredictionResponse,
)
from backend.app.services.ml_service import MLService

router = APIRouter(prefix="/v1/predict", tags=["Prediction"])


@router.post(
    "",
    response_model=PredictionResponse,
    summary="Evaluate single network flow",
    description="Passes a structured network flow record to the trained Phase 1 ML model and returns real threat classification, class probability estimates, continuous 0-100 risk score, and policy recommendation.",
)
def predict_flow(request: NetworkFlowRequest) -> PredictionResponse:
    try:
        return MLService.predict(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference execution failed: {str(e)}",
        )


@router.post(
    "/batch",
    response_model=BatchPredictionResponse,
    summary="Evaluate batch of network flows",
    description="Evaluates multiple network flow records and returns ordered prediction outputs.",
)
def predict_flow_batch(request: BatchPredictionRequest) -> BatchPredictionResponse:
    try:
        results = MLService.predict_batch(request.flows)
        return BatchPredictionResponse(results=results, total_evaluated=len(results))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch inference failed: {str(e)}",
        )


@router.get(
    "/presets",
    response_model=Dict[str, NetworkFlowRequest],
    summary="Get sample flow presets for interactive testing",
    description="Returns verified baseline and anomaly flow vectors for interactive testing.",
)
def get_test_presets() -> Dict[str, NetworkFlowRequest]:
    return {
        "BENIGN_HTTPS": NetworkFlowRequest(
            packet_count=25,
            byte_count=15000,
            duration=2.5,
            conn_rate=2.0,
            dst_port=443,
            unique_dst_ports=1,
            failed_auth_count=0,
        ),
        "PORT_SCAN": NetworkFlowRequest(
            packet_count=2,
            byte_count=120,
            duration=0.08,
            conn_rate=120.0,
            dst_port=8080,
            unique_dst_ports=75,
            failed_auth_count=0,
        ),
        "BRUTE_FORCE_SSH": NetworkFlowRequest(
            packet_count=35,
            byte_count=8500,
            duration=1.8,
            conn_rate=18.0,
            dst_port=22,
            unique_dst_ports=1,
            failed_auth_count=12,
        ),
        "TRAFFIC_SPIKE": NetworkFlowRequest(
            packet_count=4500,
            byte_count=4500000,
            duration=4.0,
            conn_rate=60.0,
            dst_port=80,
            unique_dst_ports=1,
            failed_auth_count=0,
        ),
        "BORDERLINE_FLOW": NetworkFlowRequest(
            packet_count=8,
            byte_count=600,
            duration=0.8,
            conn_rate=15.0,
            dst_port=8080,
            unique_dst_ports=5,
            failed_auth_count=0,
        ),
        "SUSPICIOUS_TRANSFER": NetworkFlowRequest(
            packet_count=1200,
            byte_count=1600000,
            duration=120.0,
            conn_rate=3.0,
            dst_port=8443,
            unique_dst_ports=1,
            failed_auth_count=0,
        ),
    }
