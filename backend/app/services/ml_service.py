"""
ML Service Adapter
==================
Singleton service wrapper that loads the Phase 1 ThreatPredictor and exposes
it to FastAPI dependency injection without duplicating ML or risk-scoring logic.
"""

from typing import Any, Dict, List, Optional
from pathlib import Path

from backend.app.config import settings
from backend.app.schemas.predict import (
    ContributingFeatureSchema,
    NetworkFlowRequest,
    PredictionResponse,
)
from ml.models.predict import ThreatPredictor, PredictionOutput
from ml.features.extractor import NetworkFlowInput


class MLService:
    _instance: Optional[ThreatPredictor] = None

    @classmethod
    def get_predictor(cls) -> ThreatPredictor:
        """
        Lazily initialize or return the singleton ThreatPredictor instance.
        """
        if cls._instance is None:
            cls._instance = ThreatPredictor(artifacts_dir=settings.ml_artifacts_dir)
        return cls._instance

    @classmethod
    def is_loaded(cls) -> bool:
        """
        Check if model artifacts exist and can be loaded.
        """
        try:
            predictor = cls.get_predictor()
            return predictor.model is not None
        except Exception:
            return False

    @classmethod
    def get_metadata(cls) -> Dict[str, Any]:
        predictor = cls.get_predictor()
        return predictor.metadata

    @classmethod
    def predict(cls, request: NetworkFlowRequest) -> PredictionResponse:
        """
        Execute prediction on a single flow request using the Phase 1 model.
        """
        predictor = cls.get_predictor()
        flow_input = NetworkFlowInput(**request.model_dump())
        pred_output: PredictionOutput = predictor.predict_flow(flow_input)

        contributing = [
            ContributingFeatureSchema(
                feature=cf.feature,
                value=cf.value,
                deviation_z_score=cf.deviation_z_score,
                description=cf.description,
            )
            for cf in pred_output.top_contributing_features
        ]

        return PredictionResponse(
            risk_score=pred_output.risk_score,
            threat_level=pred_output.threat_level,
            attack_type=pred_output.attack_type,
            confidence=pred_output.confidence,
            action_recommendation=pred_output.action_recommendation,
            is_anomaly=pred_output.is_anomaly,
            class_probabilities=pred_output.class_probabilities,
            top_contributing_features=contributing,
        )

    @classmethod
    def predict_batch(cls, requests: List[NetworkFlowRequest]) -> List[PredictionResponse]:
        """
        Execute prediction on a batch of flow requests.
        """
        return [cls.predict(r) for r in requests]
