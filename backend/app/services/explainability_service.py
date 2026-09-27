"""
Explainability Service (SHAP TreeExplainer Engine)
==================================================
Provides transparent, non-causal feature attributions using exact Shapley values
via shap.TreeExplainer for the Phase 1 RandomForest classifier.
"""

from typing import Any, Dict, List, Literal, Optional, Tuple, Union
import numpy as np
import shap

from ml.features.extractor import FEATURE_NAMES, FeatureExtractor, NetworkFlowInput
from ml.models.predict import ContributingFeature, ThreatPredictor

ContributionDirection = Literal["INCREASES_RISK", "DECREASES_RISK", "NEUTRAL"]


class FeatureAttributionDetail:
    def __init__(
        self,
        feature: str,
        value: float,
        shap_value: float,
        contribution_direction: ContributionDirection,
        description: str,
        deviation_z_score: Optional[float] = None,
    ):
        self.feature = feature
        self.value = value
        self.shap_value = shap_value
        self.contribution_direction = contribution_direction
        self.description = description
        self.deviation_z_score = deviation_z_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "value": round(float(self.value), 2),
            "shap_value": round(float(self.shap_value), 4),
            "contribution_direction": self.contribution_direction,
            "description": self.description,
            "deviation_z_score": (
                round(float(self.deviation_z_score), 2)
                if self.deviation_z_score is not None
                else None
            ),
        }


class ExplainabilityService:
    _instance: Optional["ExplainabilityService"] = None
    _explainer: Optional[shap.TreeExplainer] = None

    def __init__(self, predictor: Optional[ThreatPredictor] = None):
        if predictor is None:
            from backend.app.services.ml_service import MLService
            predictor = MLService.get_predictor()
        self.predictor = predictor
        self._init_explainer()

    def _init_explainer(self) -> None:
        if self.predictor.model is not None and self._explainer is None:
            self._explainer = shap.TreeExplainer(self.predictor.model)

    @classmethod
    def get_instance(cls) -> "ExplainabilityService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def compute_shap_attributions(
        self, X_scaled: np.ndarray, predicted_class: str
    ) -> Tuple[np.ndarray, float, Dict[str, float]]:
        """
        Computes Shapley values using TreeExplainer, handling multiclass array/list output dynamically.
        Returns:
            - attributions for the predicted class [n_features]
            - expected base value for the predicted class (float)
            - base values across all classes (Dict[class_name, float])
        """
        if self._explainer is None:
            self._init_explainer()
        if self._explainer is None:
            raise RuntimeError("SHAP TreeExplainer could not be initialized.")

        classes = self.predictor.classes
        pred_idx = classes.index(predicted_class) if predicted_class in classes else 0

        shap_vals = self._explainer.shap_values(X_scaled)
        expected_values = self._explainer.expected_value

        # Normalize expected_values mapping
        all_base_values: Dict[str, float] = {}
        if isinstance(expected_values, (list, np.ndarray)):
            for idx, c_name in enumerate(classes):
                if idx < len(expected_values):
                    all_base_values[c_name] = float(expected_values[idx])
            pred_base_value = float(expected_values[pred_idx]) if pred_idx < len(expected_values) else 0.0
        else:
            pred_base_value = float(expected_values)
            all_base_values[predicted_class] = pred_base_value

        # Dynamically extract attributions for sample 0 and class pred_idx
        # In shap >= 0.42.0: shap_vals is ndarray of shape (n_samples, n_features, n_classes)
        # In older versions: shap_vals is list of n_classes ndarrays of shape (n_samples, n_features)
        if isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
            class_attributions = shap_vals[0, :, pred_idx]
        elif isinstance(shap_vals, list) and len(shap_vals) > pred_idx:
            class_attributions = shap_vals[pred_idx][0, :]
        elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 2:
            class_attributions = shap_vals[0, :]
        else:
            raise ValueError(f"Unsupported SHAP output structure: {type(shap_vals)}")

        return class_attributions, pred_base_value, all_base_values

    def explain_flow(
        self,
        flow_input: Union[NetworkFlowInput, Dict[str, Any]],
        predicted_class: str,
        raw_feature_vector: Optional[np.ndarray] = None,
        top_n: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Generates lightweight top-N feature contributions for a single flow prediction.
        Safe fallback to z-score deviations if SHAP evaluation fails.
        """
        if isinstance(flow_input, dict):
            flow_obj = NetworkFlowInput(**flow_input)
        else:
            flow_obj = flow_input

        if raw_feature_vector is None:
            raw_feature_vector = FeatureExtractor.extract_from_flow(flow_obj)[0]

        try:
            X_scaled = self.predictor.scaler.transform([raw_feature_vector])
            class_attributions, _, _ = self.compute_shap_attributions(
                X_scaled, predicted_class
            )

            # Compute z-scores for context
            means = self.predictor.benign_baseline.get("means", {})
            stds = self.predictor.benign_baseline.get("stds", {})

            detailed_features: List[FeatureAttributionDetail] = []

            for idx, feat_name in enumerate(FEATURE_NAMES):
                raw_val = float(raw_feature_vector[idx])
                shap_val = float(class_attributions[idx])
                mean = means.get(feat_name, 0.0)
                std = stds.get(feat_name, 1.0)
                std_safe = std if std > 1e-5 else 1.0
                z_score = (raw_val - mean) / std_safe

                if shap_val > 0.005:
                    direction: ContributionDirection = "INCREASES_RISK"
                elif shap_val < -0.005:
                    direction = "DECREASES_RISK"
                else:
                    direction = "NEUTRAL"

                # Non-causal, descriptive text
                if direction == "INCREASES_RISK":
                    desc = (
                        f"{feat_name} ({raw_val:.1f}) elevated {predicted_class} prediction probability "
                        f"by +{shap_val * 100:.1f}% (model sensitivity indicator)."
                    )
                elif direction == "DECREASES_RISK":
                    desc = (
                        f"{feat_name} ({raw_val:.1f}) reduced {predicted_class} prediction probability "
                        f"by {shap_val * 100:.1f}%."
                    )
                else:
                    desc = f"{feat_name} ({raw_val:.1f}) had neutral impact on {predicted_class} classification."

                detailed_features.append(
                    FeatureAttributionDetail(
                        feature=feat_name,
                        value=raw_val,
                        shap_value=shap_val,
                        contribution_direction=direction,
                        description=desc,
                        deviation_z_score=z_score,
                    )
                )

            # Rank by absolute magnitude of SHAP contribution
            detailed_features.sort(key=lambda f: abs(f.shap_value), reverse=True)
            return [f.to_dict() for f in detailed_features[:top_n]]

        except Exception as exc:
            # Safe fallback to z-score baseline deviations
            fallback_items = self.predictor._calculate_contributing_features(
                flow_obj, raw_feature_vector
            )
            return [
                {
                    "feature": c.feature,
                    "value": c.value,
                    "shap_value": 0.0,
                    "contribution_direction": "INCREASES_RISK" if c.deviation_z_score > 0 else "DECREASES_RISK",
                    "description": f"{c.description} (baseline heuristic fallback)",
                    "deviation_z_score": c.deviation_z_score,
                }
                for c in fallback_items
            ]

    def get_full_explanation(
        self,
        flow_input: Union[NetworkFlowInput, Dict[str, Any]],
        predicted_class: str,
        risk_score: int,
        confidence: float,
        policy_action: str,
        policy_rule_name: str,
        enforcement_status: str,
    ) -> Dict[str, Any]:
        """
        Generates comprehensive on-demand 10-feature waterfall attribution for deep incident investigation.
        """
        if isinstance(flow_input, dict):
            flow_obj = NetworkFlowInput(**flow_input)
        else:
            flow_obj = flow_input

        raw_vector = FeatureExtractor.extract_from_flow(flow_obj)[0]
        X_scaled = self.predictor.scaler.transform([raw_vector])
        class_attributions, base_val, all_base_vals = self.compute_shap_attributions(
            X_scaled, predicted_class
        )

        means = self.predictor.benign_baseline.get("means", {})
        stds = self.predictor.benign_baseline.get("stds", {})

        all_features: List[Dict[str, Any]] = []
        positive_contributors: List[Dict[str, Any]] = []
        mitigating_contributors: List[Dict[str, Any]] = []

        for idx, feat_name in enumerate(FEATURE_NAMES):
            raw_val = float(raw_vector[idx])
            shap_val = float(class_attributions[idx])
            mean = means.get(feat_name, 0.0)
            std = stds.get(feat_name, 1.0)
            std_safe = std if std > 1e-5 else 1.0
            z_score = (raw_val - mean) / std_safe

            if shap_val > 0.005:
                direction = "INCREASES_RISK"
            elif shap_val < -0.005:
                direction = "DECREASES_RISK"
            else:
                direction = "NEUTRAL"

            # Check special provenance note for failed_auth_count on VPC logs
            if feat_name == "failed_auth_count" and raw_val == 0:
                note = " (L7 authentication is unavailable from L3/L4 VPC Flow Logs; value is strictly 0)"
            else:
                note = ""

            desc = (
                f"{feat_name} ({raw_val:.1f}) model attribution: {shap_val:+.4f}{note}."
            )

            item = {
                "feature": feat_name,
                "value": round(raw_val, 2),
                "shap_value": round(shap_val, 4),
                "contribution_direction": direction,
                "description": desc,
                "deviation_z_score": round(float(z_score), 2),
            }
            all_features.append(item)

            if direction == "INCREASES_RISK":
                positive_contributors.append(item)
            elif direction == "DECREASES_RISK":
                mitigating_contributors.append(item)

        # Sort features by absolute contribution
        all_features.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
        positive_contributors.sort(key=lambda x: x["shap_value"], reverse=True)
        mitigating_contributors.sort(key=lambda x: x["shap_value"])

        return {
            "predicted_class": predicted_class,
            "confidence": round(float(confidence), 4),
            "risk_score": risk_score,
            "expected_base_probability": round(float(base_val), 4),
            "all_base_values": {k: round(v, 4) for k, v in all_base_vals.items()},
            "feature_attributions": all_features,
            "top_positive_contributors": positive_contributors[:5],
            "top_mitigating_contributors": mitigating_contributors[:5],
            "policy_reasoning": {
                "enacted_policy_action": policy_action,
                "policy_rule_name": policy_rule_name,
                "enforcement_status": enforcement_status,
                "is_confidence_gated": policy_rule_name == "CONFIDENCE_GATING_MONITOR",
                "is_allowlisted": policy_rule_name == "MANAGEMENT_ALLOWLIST_PROTECTION",
            },
            "disclaimer": (
                "SHAP feature attributions quantify statistical sensitivity of the decision trees "
                "to individual input values. They provide mathematical model transparency and do not "
                "constitute physical or legal proof of malicious causality."
            ),
        }
