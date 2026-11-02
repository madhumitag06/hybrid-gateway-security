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
    def predict(
        cls,
        request: NetworkFlowRequest,
        enable_shap: Optional[bool] = None,
        shap_threshold: Optional[int] = None,
    ) -> PredictionResponse:
        """
        Execute prediction on a single flow request using the Phase 1 model.
        
        SHAP explainability is conditionally invoked based on:
          1. Explicit enable_shap override (True/False).
          2. Threat indicators: if traffic is classified as an anomaly (is_anomaly=True)
             or risk_score >= shap_threshold (default settings.shap_risk_threshold=50).
        For low-risk benign baseline flows, expensive TreeExplainer calculation is skipped
        and baseline z-score deviations are supplied without fabricated SHAP values.
        """
        predictor = cls.get_predictor()
        flow_input = NetworkFlowInput(**request.model_dump())
        pred_output: PredictionOutput = predictor.predict_flow(flow_input)

        threshold = shap_threshold if shap_threshold is not None else getattr(settings, "shap_risk_threshold", 50)
        should_explain = (
            enable_shap
            if enable_shap is not None
            else (pred_output.is_anomaly or pred_output.risk_score >= threshold)
        )

        contributing: List[ContributingFeatureSchema] = []
        explanation_status = "SKIPPED_LOW_RISK"

        if should_explain:
            from backend.app.services.explainability_service import ExplainabilityService

            # Generate lightweight top-3 SHAP feature attributions
            try:
                explain_svc = ExplainabilityService.get_instance()
                shap_features = explain_svc.explain_flow(
                    flow_input=flow_input,
                    predicted_class=pred_output.attack_type,
                    top_n=3,
                )
                contributing = [
                    ContributingFeatureSchema(
                        feature=sf["feature"],
                        value=sf["value"],
                        deviation_z_score=sf.get("deviation_z_score", 0.0) or 0.0,
                        description=sf["description"],
                        shap_value=sf.get("shap_value"),
                        contribution_direction=sf.get("contribution_direction"),
                    )
                    for sf in shap_features
                ]
                explanation_status = "CALCULATED"
            except Exception:
                contributing = [
                    ContributingFeatureSchema(
                        feature=cf.feature,
                        value=cf.value,
                        deviation_z_score=cf.deviation_z_score,
                        description=cf.description,
                        shap_value=None,
                        contribution_direction=None,
                    )
                    for cf in pred_output.top_contributing_features
                ]
                explanation_status = "UNAVAILABLE"
        else:
            # Low-risk baseline flow: transparently provide honest baseline z-score deviations
            # without fabricated SHAP values or directions.
            contributing = [
                ContributingFeatureSchema(
                    feature=cf.feature,
                    value=cf.value,
                    deviation_z_score=cf.deviation_z_score,
                    description=cf.description,
                    shap_value=None,
                    contribution_direction=None,
                )
                for cf in pred_output.top_contributing_features
            ]
            explanation_status = "SKIPPED_LOW_RISK"

        return PredictionResponse(
            risk_score=pred_output.risk_score,
            threat_level=pred_output.threat_level,
            attack_type=pred_output.attack_type,
            confidence=pred_output.confidence,
            action_recommendation=pred_output.action_recommendation,
            is_anomaly=pred_output.is_anomaly,
            class_probabilities=pred_output.class_probabilities,
            top_contributing_features=contributing,
            explanation_status=explanation_status,
        )

    @classmethod
    def predict_batch(
        cls,
        requests: List[NetworkFlowRequest],
        enable_shap: Optional[bool] = None,
        shap_threshold: Optional[int] = None,
    ) -> List[PredictionResponse]:
        """
        Execute prediction on a batch of flow requests.
        """
        return [
            cls.predict(r, enable_shap=enable_shap, shap_threshold=shap_threshold)
            for r in requests
        ]
