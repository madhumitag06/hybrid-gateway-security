"""
Prediction API Router (v1)
==========================
Handles network flow threat analysis requests using the Phase 1 machine learning model
and persists results into PostgreSQL.
"""

from typing import Dict, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.db.session import get_db
from backend.app.schemas.predict import (
    BatchPredictionRequest,
    BatchPredictionResponse,
    NetworkFlowRequest,
    PredictionResponse,
)
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.ml_service import MLService

router = APIRouter(prefix="/v1/predict", tags=["Prediction"])


@router.post(
    "",
    response_model=PredictionResponse,
    summary="Evaluate and persist single network flow",
    description="Passes a structured network flow record to the trained Phase 1 ML model, calculates real threat classification, continuous risk score, and persists the record into PostgreSQL.",
)
def predict_flow(
    request: NetworkFlowRequest,
    db: Session = Depends(get_db),
) -> PredictionResponse:
    try:
        if request.persist:
            pred, _ = DashboardService.record_prediction(
                db=db,
                flow_request=request,
                source_ip=request.source_ip or "192.168.1.100",
                destination_ip=request.destination_ip or "10.100.1.10",
                is_demo=False,
            )
            return pred
        else:
            return MLService.predict(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference/persistence execution failed: {str(e)}",
        )


@router.post(
    "/batch",
    response_model=BatchPredictionResponse,
    summary="Evaluate batch of network flows",
    description="Evaluates multiple network flow records and returns ordered prediction outputs.",
)
def predict_flow_batch(
    request: BatchPredictionRequest,
    db: Session = Depends(get_db),
) -> BatchPredictionResponse:
    try:
        results: List[PredictionResponse] = []
        for flow_req in request.flows:
            if flow_req.persist:
                pred, _ = DashboardService.record_prediction(
                    db=db,
                    flow_request=flow_req,
                    source_ip=flow_req.source_ip or "192.168.1.100",
                    destination_ip=flow_req.destination_ip or "10.100.1.10",
                    is_demo=False,
                )
                results.append(pred)
            else:
                results.append(MLService.predict(flow_req))
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
            source_ip="192.168.1.50",
            destination_ip="10.100.0.1",
        ),
        "PORT_SCAN": NetworkFlowRequest(
            packet_count=2,
            byte_count=120,
            duration=0.08,
            conn_rate=120.0,
            dst_port=8080,
            unique_dst_ports=75,
            failed_auth_count=0,
            source_ip="192.168.1.77",
            destination_ip="10.100.4.12",
        ),
        "BRUTE_FORCE_SSH": NetworkFlowRequest(
            packet_count=35,
            byte_count=8500,
            duration=1.8,
            conn_rate=18.0,
            dst_port=22,
            unique_dst_ports=1,
            failed_auth_count=12,
            source_ip="203.0.113.24",
            destination_ip="10.100.2.18",
        ),
        "TRAFFIC_SPIKE": NetworkFlowRequest(
            packet_count=4500,
            byte_count=4500000,
            duration=4.0,
            conn_rate=60.0,
            dst_port=80,
            unique_dst_ports=1,
            failed_auth_count=0,
            source_ip="198.51.100.9",
            destination_ip="10.100.1.44",
        ),
        "BORDERLINE_FLOW": NetworkFlowRequest(
            packet_count=8,
            byte_count=600,
            duration=0.8,
            conn_rate=15.0,
            dst_port=8080,
            unique_dst_ports=5,
            failed_auth_count=0,
            source_ip="192.0.2.56",
            destination_ip="10.100.3.20",
        ),
        "SUSPICIOUS_TRANSFER": NetworkFlowRequest(
            packet_count=1200,
            byte_count=1600000,
            duration=120.0,
            conn_rate=3.0,
            dst_port=8443,
            unique_dst_ports=1,
            failed_auth_count=0,
            source_ip="192.168.1.101",
            destination_ip="10.100.4.12",
        ),
    }
