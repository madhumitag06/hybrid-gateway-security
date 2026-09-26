"""
Model Training Pipeline
=======================
Trains a RandomForestClassifier on reproducible synthetic network-flow data,
evaluates performance across Train/Val/Test splits without data leakage,
and serializes model artifacts.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from ml.data.generator import TRAFFIC_CLASSES, generate_synthetic_dataset
from ml.evaluation.evaluate import evaluate_model, format_evaluation_report
from ml.features.extractor import FEATURE_NAMES, FeatureExtractor

ARTIFACTS_DIR = Path(__file__).resolve().parent


def run_training_pipeline(
    n_samples: int = 10000,
    random_seed: int = 42,
    artifacts_dir: Path = ARTIFACTS_DIR,
) -> Dict[str, Any]:
    """
    Execute end-to-end dataset generation, preprocessing, model training,
    evaluation, and artifact serialization.
    """
    print(f"[*] Generating synthetic network-flow dataset ({n_samples} samples, seed={random_seed})...")
    df = generate_synthetic_dataset(n_samples=n_samples, random_seed=random_seed)

    X, y_labels = FeatureExtractor.extract_from_dataframe(df)

    # Encode string class labels to integers
    label_encoder = LabelEncoder()
    # Fit on all defined classes to ensure deterministic ordering
    label_encoder.fit(TRAFFIC_CLASSES)
    y = label_encoder.transform(y_labels)

    # Stratified Split: 70% Train, 15% Validation, 15% Test
    print("[*] Splitting dataset: 70% Train, 15% Validation, 15% Test...")
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, random_state=random_seed, stratify=y
    )
    # Val size relative to original dataset is 0.15 / 0.85 approx 0.1765
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.17647, random_state=random_seed, stratify=y_train_val
    )

    print(f"    Train size:      {X_train.shape[0]} samples")
    print(f"    Validation size: {X_val.shape[0]} samples")
    print(f"    Test size:       {X_test.shape[0]} samples")

    # Preprocessing: Fit StandardScaler strictly on the training set to prevent data leakage
    print("[*] Fitting StandardScaler on training set...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    # Model definition
    print("[*] Training RandomForestClassifier (n_estimators=100, max_depth=12)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=random_seed,
        n_jobs=-1,
    )
    clf.fit(X_train_scaled, y_train)

    # Evaluation on Validation Set
    val_preds = clf.predict(X_val_scaled)
    val_metrics = evaluate_model(
        y_true=label_encoder.inverse_transform(y_val),
        y_pred=label_encoder.inverse_transform(val_preds),
        labels=TRAFFIC_CLASSES,
    )

    # Evaluation on Holdout Test Set
    test_preds = clf.predict(X_test_scaled)
    test_metrics = evaluate_model(
        y_true=label_encoder.inverse_transform(y_test),
        y_pred=label_encoder.inverse_transform(test_preds),
        labels=TRAFFIC_CLASSES,
    )

    print("\n" + format_evaluation_report(test_metrics) + "\n")

    # Compute Feature Importances
    feature_importances = {
        feat: round(float(imp), 4)
        for feat, imp in zip(FEATURE_NAMES, clf.feature_importances_)
    }
    sorted_importances = dict(sorted(feature_importances.items(), key=lambda item: item[1], reverse=True))
    print("[*] Feature Importances:")
    for feat, imp in sorted_importances.items():
        print(f"    {feat:<20}: {imp:.4f}")

    # Compute baseline feature statistics on Benign training samples for anomaly explanation
    benign_class_idx = label_encoder.transform(["BENIGN"])[0]
    benign_mask = y_train == benign_class_idx
    benign_X = X_train[benign_mask]
    benign_means = np.mean(benign_X, axis=0).tolist()
    benign_stds = np.std(benign_X, axis=0).tolist()

    # Save artifacts
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    model_path = artifacts_dir / "model.joblib"
    scaler_path = artifacts_dir / "scaler.joblib"
    le_path = artifacts_dir / "label_encoder.joblib"
    metadata_path = artifacts_dir / "metadata.json"

    print(f"[*] Serializing artifacts to {artifacts_dir}...")
    joblib.dump(clf, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(label_encoder, le_path)

    metadata = {
        "model_type": "RandomForestClassifier",
        "training_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "random_seed": random_seed,
        "sample_counts": {
            "total": n_samples,
            "train": int(X_train.shape[0]),
            "val": int(X_val.shape[0]),
            "test": int(X_test.shape[0]),
        },
        "features": FEATURE_NAMES,
        "classes": TRAFFIC_CLASSES,
        "hyperparameters": {
            "n_estimators": clf.n_estimators,
            "max_depth": clf.max_depth,
            "min_samples_split": clf.min_samples_split,
            "min_samples_leaf": clf.min_samples_leaf,
        },
        "feature_importances": sorted_importances,
        "benign_baseline": {
            "means": dict(zip(FEATURE_NAMES, benign_means)),
            "stds": dict(zip(FEATURE_NAMES, benign_stds)),
        },
        "validation_metrics": val_metrics["overall"],
        "test_metrics": test_metrics,
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("[+] Model training pipeline completed successfully.")
    return metadata


if __name__ == "__main__":
    run_training_pipeline()
