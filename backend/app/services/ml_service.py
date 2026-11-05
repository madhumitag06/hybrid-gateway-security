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


from datetime import datetime, timezone

class MLService:
    _predictors: Dict[str, ThreatPredictor] = {}
    _custom_models: Dict[str, Dict[str, Any]] = {}
    _active_version: str = getattr(settings, "active_model_version", "candidate_xgboost_v2")
    _previous_version: Optional[str] = getattr(settings, "standby_model_version", "production_rf")
    _promotion_history: List[Dict[str, Any]] = [
        {
            "event": "PRODUCTION_PROMOTION",
            "active_version": "candidate_xgboost_v2",
            "previous_version": "production_rf",
            "timestamp": "2026-11-06T00:00:00Z",
            "reason": "Production promotion of Big Data XGBoost V2 as authoritative active primary model; Random Forest retained as standby rollback.",
        }
    ]

    @classmethod
    def register_model(cls, version_id: str, details: Dict[str, Any]) -> None:
        cls._custom_models[version_id] = details

    @classmethod
    def get_registry(cls) -> Dict[str, Dict[str, Any]]:
        base_reg = {
            "production_rf": {
                "version_id": "production_rf",
                "name": "Production Random Forest (Synthetic Baseline)",
                "model_version": "v1.0",
                "artifacts_dir": str(settings.ml_artifacts_dir),
                "algorithm": "RandomForestClassifier",
                "schema_version": "v1",
                "feature_count": 10,
                "role": "ACTIVE_PRIMARY" if cls._active_version == "production_rf" else "STANDBY_ROLLBACK",
                "description": "Authoritative 100-tree Random Forest model governing live gateway policy and router enforcement." if cls._active_version == "production_rf" else "Standby 100-tree Random Forest baseline preserved for zero-downtime rollback.",
            },
            "candidate_xgboost_v2": {
                "version_id": "candidate_xgboost_v2",
                "name": "Big Data XGBoost V2 (Clean Schema)",
                "model_version": "v2.0",
                "artifacts_dir": str(settings.shadow_artifacts_dir),
                "algorithm": "XGBClassifier",
                "schema_version": "v2",
                "feature_count": 9,
                "role": "ACTIVE_PRIMARY" if cls._active_version == "candidate_xgboost_v2" else "STANDBY_ROLLBACK",
                "description": "Authoritative production-grade XGBoost trained on 6.49M multi-dataset records with clean 9-feature schema." if cls._active_version == "candidate_xgboost_v2" else "Candidate XGBoost V2 model available for promotion.",
            },
        }
        base_reg.update(cls._custom_models)
        return base_reg

    @classmethod
    def get_active_version(cls) -> str:
        return cls._active_version

    @classmethod
    def get_previous_version(cls) -> Optional[str]:
        return cls._previous_version

    @classmethod
    def get_predictor(cls, version: Optional[str] = None) -> ThreatPredictor:
        """
        Lazily initialize or return the requested ThreatPredictor instance (defaults to active model).
        """
        ver = version or cls._active_version
        if ver not in cls._predictors:
            registry = cls.get_registry()
            if ver not in registry:
                raise ValueError(f"Unknown model version '{ver}'. Available: {list(registry.keys())}")
            art_dir = Path(registry[ver]["artifacts_dir"])
            cls._predictors[ver] = ThreatPredictor(artifacts_dir=art_dir)
        return cls._predictors[ver]

    @classmethod
    def get_standby_predictor(cls) -> Optional[ThreatPredictor]:
        """
        Returns the standby/comparison predictor if available.
        """
        if cls._previous_version:
            return cls.get_predictor(cls._previous_version)
        return None

    @classmethod
    def promote_model(cls, version: str, reason: str = "") -> Dict[str, Any]:
        """
        Controlled model promotion: sets the target version as active primary,
        retains the current active model as standby, and resets the SHAP explainer cache.
        """
        registry = cls.get_registry()
        if version not in registry:
            raise ValueError(f"Cannot promote unknown model '{version}'. Available: {list(registry.keys())}")

        if version == cls._active_version:
            return {
                "status": "ALREADY_ACTIVE",
                "active_version": cls._active_version,
                "message": f"Model '{version}' is already the active authoritative model.",
            }

        old_active = cls._active_version
        cls._previous_version = old_active
        cls._active_version = version

        # Ensure model is loadable
        new_predictor = cls.get_predictor(version)

        # Reset SHAP explainer cache so it attaches to new predictor
        from backend.app.services.explainability_service import ExplainabilityService
        ExplainabilityService._instance = None
        ExplainabilityService._explainer = None

        record = {
            "event": "PROMOTION",
            "active_version": version,
            "previous_version": old_active,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": reason or f"Controlled promotion of {version} to active production primary.",
        }
        cls._promotion_history.append(record)

        return {
            "status": "PROMOTED",
            "active_version": cls._active_version,
            "previous_version": cls._previous_version,
            "algorithm": registry[version]["algorithm"],
            "feature_count": registry[version]["feature_count"],
            "timestamp": record["timestamp"],
            "message": f"Successfully promoted '{version}' to active authoritative model.",
        }

    @classmethod
    def rollback(cls, reason: str = "") -> Dict[str, Any]:
        """
        Zero-downtime rollback: restores the previous model version as authoritative primary.
        """
        if not cls._previous_version:
            raise ValueError("No previous model version recorded for rollback.")

        target = cls._previous_version
        return cls.promote_model(target, reason=reason or "Emergency or operational rollback to previous model version.")

    @classmethod
    def get_registry_status(cls) -> Dict[str, Any]:
        registry = cls.get_registry()
        return {
            "active_version": cls._active_version,
            "previous_version": cls._previous_version,
            "active_model_details": registry.get(cls._active_version, {}),
            "standby_model_details": registry.get(cls._previous_version, {}) if cls._previous_version else None,
            "all_models": registry,
            "promotion_history": cls._promotion_history,
        }

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
