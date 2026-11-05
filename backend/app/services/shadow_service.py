"""
Shadow Mode Prediction & Evaluation Service (Phase 3)
=====================================================
Integrates the Big Data XGBoost V2 candidate model alongside the authoritative
production Random Forest model.

Key Operational Principles:
1. NON-ENFORCING / ADVISORY ONLY:
   Candidate predictions are collected strictly for telemetry, latency measurement,
   agreement auditing, and SHAP attribution. The candidate model NEVER emits policy
   decisions or modifies router firewall/iptables rules.
2. INDEPENDENT ARTIFACT INTEGRITY:
   XGBoost V2 is loaded from `ml/models/candidates/bigdata_v2/` with its dedicated
   StandardScaler, LabelEncoder, and exact 9-feature schema.
3. FAIL-SAFE / NON-BLOCKING:
   If the candidate model fails or database persistence encounters an error, the
   authoritative production pipeline continues uninterrupted.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

import numpy as np
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.shadow_prediction import ShadowPredictionModel
from backend.app.schemas.predict import NetworkFlowRequest, PredictionResponse
from ml.features.extractor import (
    FEATURE_NAMES_V2,
    FeatureExtractor,
    NetworkFlowInput,
)
from ml.models.predict import PredictionOutput, ThreatPredictor

logger = logging.getLogger("shadow_service")


@dataclass
class ShadowEvaluationResult:
    flow_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    dst_port: Optional[int]
    protocol: str
    feature_schema_version: str
    flow_features: Dict[str, Any]
    prod_model_version: str
    prod_attack_type: str
    prod_confidence: float
    prod_risk_score: int
    prod_latency_ms: float
    candidate_model_version: str
    candidate_attack_type: str
    candidate_confidence: float
    candidate_risk_score: int
    candidate_latency_ms: float
    agreement: bool
    disagreement_type: Optional[str]
    shap_attributions: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "feature_schema_version": self.feature_schema_version,
            "flow_features": self.flow_features,
            "prod_model_version": self.prod_model_version,
            "prod_attack_type": self.prod_attack_type,
            "prod_confidence": round(self.prod_confidence, 4),
            "prod_risk_score": self.prod_risk_score,
            "prod_latency_ms": round(self.prod_latency_ms, 3),
            "candidate_model_version": self.candidate_model_version,
            "candidate_attack_type": self.candidate_attack_type,
            "candidate_confidence": round(self.candidate_confidence, 4),
            "candidate_risk_score": self.candidate_risk_score,
            "candidate_latency_ms": round(self.candidate_latency_ms, 3),
            "agreement": self.agreement,
            "disagreement_type": self.disagreement_type,
            "shap_attributions": self.shap_attributions,
        }


class ShadowService:
    """
    Singleton service managing candidate model lifecycle, shadow inference,
    agreement auditing, and non-blocking database persistence.
    """
    _instance: Optional["ShadowService"] = None
    _candidate_predictor: Optional[ThreatPredictor] = None
    _candidate_explainer: Optional[Any] = None
    _init_attempted: bool = False
    _init_error: Optional[str] = None

    @classmethod
    def get_candidate_predictor(cls) -> Optional[ThreatPredictor]:
        """
        Lazily initialize and validate the candidate XGBoost V2 model predictor.
        """
        if cls._candidate_predictor is None and not cls._init_attempted:
            cls._init_attempted = True
            artifacts_dir = Path(settings.shadow_artifacts_dir)
            logger.info("Initializing Candidate Model (XGBoost V2) from: %s", artifacts_dir)

            try:
                # 1. Validate Artifact Existence
                req_files = [
                    "model.joblib",
                    "scaler.joblib",
                    "label_encoder.joblib",
                    "metadata.json",
                    "feature_schema.json",
                ]
                missing = [f for f in req_files if not (artifacts_dir / f).is_file()]
                if missing:
                    err_msg = f"Candidate model artifacts incomplete in {artifacts_dir}. Missing: {missing}"
                    logger.error(err_msg)
                    cls._init_error = err_msg
                    return None

                # 2. Validate Feature Schema Definition
                with open(artifacts_dir / "feature_schema.json", "r", encoding="utf-8") as f:
                    schema_data = json.load(f)
                features = (
                    schema_data.get("feature_names")
                    or schema_data.get("features")
                    or schema_data.get("feature_schema", [])
                )
                if len(features) != 9 or features != FEATURE_NAMES_V2:
                    err_msg = (
                        f"Incompatible candidate feature schema: expected {FEATURE_NAMES_V2}, "
                        f"found {features}"
                    )
                    logger.error(err_msg)
                    cls._init_error = err_msg
                    return None

                # 3. Instantiate ThreatPredictor for Candidate
                predictor = ThreatPredictor(artifacts_dir=artifacts_dir)
                cls._candidate_predictor = predictor
                logger.info(
                    "[+] Candidate XGBoost V2 initialized successfully. Features: %s, Classes: %s",
                    predictor.feature_schema,
                    predictor.classes,
                )
            except Exception as e:
                err_msg = f"Failed to initialize candidate predictor: {e}"
                logger.error(err_msg, exc_info=True)
                cls._init_error = err_msg
                cls._candidate_predictor = None

        return cls._candidate_predictor

    @classmethod
    def is_available(cls) -> bool:
        """
        Return True if shadow mode is enabled in settings and candidate model is loaded.
        """
        if not getattr(settings, "shadow_mode_enabled", True):
            return False
        return cls.get_candidate_predictor() is not None

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        """
        Return status telemetry of the shadow inference engine.
        """
        predictor = cls.get_candidate_predictor()
        enabled = bool(getattr(settings, "shadow_mode_enabled", True))
        artifacts_dir = str(settings.shadow_artifacts_dir)

        if predictor is not None:
            from backend.app.services.ml_service import MLService
            is_authoritative = (MLService.get_active_version() == "candidate_xgboost_v2")
            return {
                "status": "ONLINE (AUTHORITATIVE PRIMARY)" if is_authoritative else "ONLINE",
                "shadow_mode_enabled": enabled,
                "candidate_model": "Big Data XGBoost V2",
                "candidate_version": "v2.0.0",
                "feature_schema_version": "v2",
                "feature_count": len(predictor.feature_schema),
                "features": predictor.feature_schema,
                "classes": predictor.classes,
                "artifacts_dir": artifacts_dir,
                "role": "ACTIVE_PRIMARY" if is_authoritative else "SHADOW_CANDIDATE",
                "enforcement_authority": (
                    "AUTHORITATIVE PRIMARY (Active Gateway & Router Enforcement)"
                    if is_authoritative
                    else "NONE (SHADOW / ADVISORY ONLY)"
                ),
            }
        else:
            return {
                "status": "DISABLED" if not enabled else "ERROR",
                "shadow_mode_enabled": enabled,
                "error": cls._init_error or "Candidate model not loaded",
                "artifacts_dir": artifacts_dir,
                "enforcement_authority": "NONE",
            }

    @classmethod
    def evaluate_shadow_flow(
        cls,
        flow_request: Union[NetworkFlowRequest, NetworkFlowInput, Dict[str, Any]],
        prod_pred: Union[PredictionResponse, PredictionOutput],
        prod_latency_ms: float = 0.0,
        flow_id: Optional[str] = None,
        source_ip: str = "192.168.1.100",
        destination_ip: str = "10.100.1.10",
        protocol: str = "TCP",
    ) -> Optional[ShadowEvaluationResult]:
        """
        Execute shadow prediction on an eligible flow using XGBoost V2 without modifying
        authoritative production enforcement decisions.
        """
        if not cls.is_available():
            return None

        predictor = cls.get_candidate_predictor()
        if predictor is None:
            return None

        fid = flow_id or f"flow-{uuid.uuid4().hex[:8]}"

        # Standardize input to NetworkFlowInput
        if isinstance(flow_request, NetworkFlowRequest):
            flow_input = NetworkFlowInput(**flow_request.model_dump())
        elif isinstance(flow_request, dict):
            flow_input = NetworkFlowInput(**flow_request)
        else:
            flow_input = flow_request

        # Measure Candidate Inference Latency
        t0 = time.perf_counter()
        try:
            cand_pred: PredictionOutput = predictor.predict_flow(flow_input)
            cand_latency_ms = (time.perf_counter() - t0) * 1000.0
        except Exception as e:
            logger.error("Candidate shadow inference failed for flow %s: %s", fid, e)
            return None

        # Determine Agreement / Disagreement
        agreement = (prod_pred.attack_type == cand_pred.attack_type)
        disagreement_type = None if agreement else f"{prod_pred.attack_type}_vs_{cand_pred.attack_type}"

        # Extract Raw Feature Dictionary (9-feature V2 Schema)
        raw_v2_vector = FeatureExtractor.extract_v2_from_flow(flow_input)
        raw_feature_dict = {
            name: round(float(raw_v2_vector[0][idx]), 2)
            for idx, name in enumerate(FEATURE_NAMES_V2)
        }

        # Calculate Candidate SHAP Attributions when applicable
        # (Triggered on disagreement, or when candidate risk >= threshold, or anomaly)
        shap_threshold = getattr(settings, "shadow_shap_threshold", 50)
        should_explain = (
            not agreement
            or cand_pred.is_anomaly
            or cand_pred.risk_score >= shap_threshold
        )
        shap_attributions: List[Dict[str, Any]] = []

        if should_explain:
            try:
                from backend.app.services.explainability_service import ExplainabilityService
                if cls._candidate_explainer is None:
                    cls._candidate_explainer = ExplainabilityService(predictor=predictor)

                shap_list = cls._candidate_explainer.explain_flow(
                    flow_input=flow_input,
                    predicted_class=cand_pred.attack_type,
                    top_n=3,
                )
                shap_attributions = shap_list
            except Exception as e:
                logger.debug("SHAP explanation skipped for candidate flow %s: %s", fid, e)

        return ShadowEvaluationResult(
            flow_id=fid,
            timestamp=datetime.now(timezone.utc),
            source_ip=source_ip,
            destination_ip=destination_ip,
            dst_port=flow_input.dst_port,
            protocol=protocol,
            feature_schema_version="v2",
            flow_features=raw_feature_dict,
            prod_model_version="v1_random_forest",
            prod_attack_type=prod_pred.attack_type,
            prod_confidence=float(prod_pred.confidence),
            prod_risk_score=int(prod_pred.risk_score),
            prod_latency_ms=float(prod_latency_ms),
            candidate_model_version="v2_xgboost",
            candidate_attack_type=cand_pred.attack_type,
            candidate_confidence=float(cand_pred.confidence),
            candidate_risk_score=int(cand_pred.risk_score),
            candidate_latency_ms=float(cand_latency_ms),
            agreement=agreement,
            disagreement_type=disagreement_type,
            shap_attributions=shap_attributions,
        )

    @classmethod
    def persist_shadow_record(
        cls,
        db: Session,
        eval_result: ShadowEvaluationResult,
    ) -> Optional[ShadowPredictionModel]:
        """
        Persists a single shadow prediction record into PostgreSQL without blocking
        or failing the primary transaction.
        """
        if not getattr(settings, "shadow_persist_records", True):
            return None

        try:
            record_id = f"shd-{uuid.uuid4().hex[:12]}"
            model_record = ShadowPredictionModel(
                id=record_id,
                flow_id=eval_result.flow_id,
                timestamp=eval_result.timestamp,
                source_ip=eval_result.source_ip,
                destination_ip=eval_result.destination_ip,
                dst_port=eval_result.dst_port,
                protocol=eval_result.protocol,
                feature_schema_version=eval_result.feature_schema_version,
                flow_features=eval_result.flow_features,
                prod_model_version=eval_result.prod_model_version,
                prod_attack_type=eval_result.prod_attack_type,
                prod_confidence=eval_result.prod_confidence,
                prod_risk_score=eval_result.prod_risk_score,
                prod_latency_ms=eval_result.prod_latency_ms,
                candidate_model_version=eval_result.candidate_model_version,
                candidate_attack_type=eval_result.candidate_attack_type,
                candidate_confidence=eval_result.candidate_confidence,
                candidate_risk_score=eval_result.candidate_risk_score,
                candidate_latency_ms=eval_result.candidate_latency_ms,
                agreement=eval_result.agreement,
                disagreement_type=eval_result.disagreement_type,
                shap_attributions=eval_result.shap_attributions,
            )
            db.add(model_record)
            db.flush()
            return model_record
        except Exception as e:
            logger.warning("Failed to persist shadow prediction record: %s", e)
            return None

    @classmethod
    def persist_shadow_batch(
        cls,
        db: Session,
        eval_results: List[ShadowEvaluationResult],
    ) -> int:
        """
        Batch persist multiple shadow prediction records with deduplication.
        """
        if not getattr(settings, "shadow_persist_records", True) or not eval_results:
            return 0

        inserted_count = 0
        try:
            for result in eval_results:
                record_id = f"shd-{uuid.uuid4().hex[:12]}"
                model_record = ShadowPredictionModel(
                    id=record_id,
                    flow_id=result.flow_id,
                    timestamp=result.timestamp,
                    source_ip=result.source_ip,
                    destination_ip=result.destination_ip,
                    dst_port=result.dst_port,
                    protocol=result.protocol,
                    feature_schema_version=result.feature_schema_version,
                    flow_features=result.flow_features,
                    prod_model_version=result.prod_model_version,
                    prod_attack_type=result.prod_attack_type,
                    prod_confidence=result.prod_confidence,
                    prod_risk_score=result.prod_risk_score,
                    prod_latency_ms=result.prod_latency_ms,
                    candidate_model_version=result.candidate_model_version,
                    candidate_attack_type=result.candidate_attack_type,
                    candidate_confidence=result.candidate_confidence,
                    candidate_risk_score=result.candidate_risk_score,
                    candidate_latency_ms=result.candidate_latency_ms,
                    agreement=result.agreement,
                    disagreement_type=result.disagreement_type,
                    shap_attributions=result.shap_attributions,
                )
                db.add(model_record)
                inserted_count += 1
            db.flush()
        except Exception as e:
            logger.warning("Failed to batch persist shadow predictions: %s", e)

        return inserted_count
