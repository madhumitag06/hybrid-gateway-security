"""
Inference Engine and Risk Scoring Subsystem
============================================
Loads serialized machine learning artifacts, extracts flow features,
runs model inference to compute class probability estimates,
and derives transparent continuous risk scores (0–100) with policy recommendations.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Union
import joblib
import numpy as np
from pydantic import BaseModel, Field

from ml.features.extractor import FEATURE_NAMES, FeatureExtractor, NetworkFlowInput

DEFAULT_ARTIFACTS_DIR = Path(__file__).resolve().parent

SeverityLevel = Literal["LOW", "MEDIUM", "HIGH"]
PolicyAction = Literal["Allow", "Monitor", "Restrict", "Block"]


class ContributingFeature(BaseModel):
    feature: str
    value: float
    deviation_z_score: float
    description: str


class PredictionOutput(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="Normalized risk score from 0 to 100")
    threat_level: SeverityLevel = Field(..., description="Categorical threat severity tier")
    attack_type: str = Field(..., description="Predicted traffic classification")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model class probability estimate for predicted class")
    action_recommendation: PolicyAction = Field(..., description="Recommended gateway policy action")
    is_anomaly: bool = Field(..., description="True if classified as non-benign traffic")
    class_probabilities: Dict[str, float] = Field(..., description="Class probability estimates from model")
    top_contributing_features: List[ContributingFeature] = Field(default_factory=list, description="Top anomalous feature indicators")


class ThreatPredictor:
    """
    Production-ready inference service for security gateway network flow evaluation.
    """

    def __init__(self, artifacts_dir: Optional[Union[str, Path]] = None):
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else DEFAULT_ARTIFACTS_DIR
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        model_path = self.artifacts_dir / "model.joblib"
        scaler_path = self.artifacts_dir / "scaler.joblib"
        le_path = self.artifacts_dir / "label_encoder.joblib"
        meta_path = self.artifacts_dir / "metadata.json"

        if not model_path.exists() or not scaler_path.exists() or not le_path.exists():
            raise FileNotFoundError(
                f"Trained model artifacts not found in {self.artifacts_dir}. "
                "Please run `python -m ml.models.train` first."
            )

        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.label_encoder = joblib.load(le_path)

        self.metadata: Dict[str, Any] = {}
        if meta_path.exists():
            with open(meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

        self.classes: List[str] = list(self.label_encoder.classes_)
        self.benign_idx = self.classes.index("BENIGN") if "BENIGN" in self.classes else 0
        self.benign_baseline = self.metadata.get("benign_baseline", {})

    def predict_flow(self, flow: Union[NetworkFlowInput, Dict[str, Any]]) -> PredictionOutput:
        """
        Execute real inference for a single network flow record.
        """
        if isinstance(flow, dict):
            flow_obj = NetworkFlowInput(**flow)
        else:
            flow_obj = flow

        # Extract numerical feature vector [1, n_features]
        X_raw = FeatureExtractor.extract_from_flow(flow_obj)

        # Apply preprocessing scaling fitted during training
        X_scaled = self.scaler.transform(X_raw)

        # Obtain class probability estimates from Random Forest
        proba = self.model.predict_proba(X_scaled)[0]

        # Map class probabilities
        prob_dict = {
            cls_name: round(float(proba[idx]), 4)
            for idx, cls_name in enumerate(self.classes)
        }

        # Calculate anomaly probability (sum of all non-benign class estimates)
        benign_prob = float(proba[self.benign_idx])
        anomaly_prob = float(1.0 - benign_prob)

        # Predicted class and confidence
        predicted_idx = int(np.argmax(proba))
        predicted_class = self.classes[predicted_idx]
        confidence = float(proba[predicted_idx])
        is_anomaly = predicted_class != "BENIGN"

        # Calculate continuous Risk Score (0 - 100)
        # Mathematical mapping:
        # - Benign predictions scale anomaly_prob into [0, 39]
        # - Anomalous predictions scale anomaly_prob into [40, 100]
        if not is_anomaly:
            raw_risk = anomaly_prob * 39.0
        else:
            # Scale from 40 to 100 based on anomaly probability and confidence
            raw_risk = 40.0 + (anomaly_prob * 60.0)

        risk_score = int(np.clip(np.round(raw_risk), 0, 100))

        # Severity classification and policy action mapping
        if risk_score < 40:
            threat_level: SeverityLevel = "LOW"
            action: PolicyAction = "Allow"
        elif risk_score < 70:
            threat_level = "MEDIUM"
            action = "Monitor"
        else:
            threat_level = "HIGH"
            # Critical threshold or high brute-force confidence triggers immediate Block
            if risk_score >= 85 or (predicted_class == "BRUTE_FORCE" and confidence > 0.8):
                action = "Block"
            else:
                action = "Restrict"

        # Identify top contributing anomalous features (z-score against benign baseline)
        top_features = self._calculate_contributing_features(flow_obj, X_raw[0])

        return PredictionOutput(
            risk_score=risk_score,
            threat_level=threat_level,
            attack_type=predicted_class,
            confidence=round(confidence, 4),
            action_recommendation=action,
            is_anomaly=is_anomaly,
            class_probabilities=prob_dict,
            top_contributing_features=top_features,
        )

    def predict_batch(
        self, flows: List[Union[NetworkFlowInput, Dict[str, Any]]]
    ) -> List[PredictionOutput]:
        """
        Execute batch inference across multiple flow records.
        """
        return [self.predict_flow(f) for f in flows]

    def _calculate_contributing_features(
        self, flow: NetworkFlowInput, raw_values: np.ndarray
    ) -> List[ContributingFeature]:
        """
        Compute deviation of flow features from the learned benign baseline.
        """
        means = self.benign_baseline.get("means", {})
        stds = self.benign_baseline.get("stds", {})

        contributions: List[ContributingFeature] = []
        for idx, feat_name in enumerate(FEATURE_NAMES):
            val = float(raw_values[idx])
            mean = means.get(feat_name, 0.0)
            std = stds.get(feat_name, 1.0)
            std_safe = std if std > 1e-5 else 1.0
            z_score = (val - mean) / std_safe

            if abs(z_score) >= 1.5 or (feat_name == "failed_auth_count" and val > 0):
                desc = (
                    f"{feat_name} value ({val:.1f}) deviates by {z_score:+.2f} std devs from benign baseline"
                )
                contributions.append(
                    ContributingFeature(
                        feature=feat_name,
                        value=round(val, 2),
                        deviation_z_score=round(float(z_score), 2),
                        description=desc,
                    )
                )

        # Sort by absolute z-score deviation descending
        contributions.sort(key=lambda c: abs(c.deviation_z_score), reverse=True)
        return contributions[:3]


if __name__ == "__main__":
    predictor = ThreatPredictor()
    sample_flow = {
        "packet_count": 2,
        "byte_count": 80,
        "duration": 0.05,
        "conn_rate": 95.0,
        "dst_port": 8080,
        "unique_dst_ports": 45,
        "failed_auth_count": 0,
    }
    result = predictor.predict_flow(sample_flow)
    print("Inference Result Sample:")
    print(result.model_dump_json(indent=2))
