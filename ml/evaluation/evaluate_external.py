"""
External Generalization & Benchmark Evaluation Runner
=====================================================
Executes rigorous generalization testing of the trained Phase 11B ML model
against external public network intrusion benchmark data (e.g. CIC-IDS2017 schema).
"""

import json
from pathlib import Path
from typing import Any, Dict
import joblib
import numpy as np

from ml.data.generator import TRAFFIC_CLASSES
from ml.evaluation.evaluate import evaluate_model, format_evaluation_report
from ml.evaluation.external_dataset_loader import load_external_cic_dataset
from ml.features.extractor import FEATURE_NAMES, FeatureExtractor

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


def run_external_evaluation(
    n_samples: int = 5000,
    random_seed: int = 101,
) -> Dict[str, Any]:
    """
    Evaluates the Phase 11B production model on external benchmark data without data leakage.
    """
    model_path = MODELS_DIR / "model.joblib"
    scaler_path = MODELS_DIR / "scaler.joblib"
    le_path = MODELS_DIR / "label_encoder.joblib"

    if not (model_path.exists() and scaler_path.exists() and le_path.exists()):
        raise FileNotFoundError("Model artifacts not found. Please train model first.")

    clf = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    label_encoder = joblib.load(le_path)

    print(f"[*] Loading and mapping external benchmark dataset ({n_samples} samples)...")
    external_df, data_stats = load_external_cic_dataset(n_samples=n_samples, random_seed=random_seed)

    print("[*] External Data Cleaning & Mapping Summary:")
    for k, v in data_stats.items():
        print(f"    {k:<30}: {v}")

    X, y_labels = FeatureExtractor.extract_from_dataframe(external_df)

    # Scale external features using the existing fitted scaler (no refitting on test data!)
    X_scaled = scaler.transform(X)

    # Predictions
    preds_idx = clf.predict(X_scaled)
    preds_labels = label_encoder.inverse_transform(preds_idx)

    # Evaluation
    metrics = evaluate_model(
        y_true=y_labels,
        y_pred=preds_labels,
        labels=TRAFFIC_CLASSES,
    )

    print("\n" + "=" * 50)
    print("      EXTERNAL DATASET GENERALIZATION REPORT")
    print("=" * 50)
    print(format_evaluation_report(metrics))

    return {
        "dataset_name": "CIC-IDS2017-Benchmark-Subset",
        "cleaning_stats": data_stats,
        "metrics": metrics,
    }


if __name__ == "__main__":
    run_external_evaluation()
