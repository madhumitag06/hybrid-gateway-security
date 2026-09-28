"""
Experimental External Model Training Pipeline (Path B)
======================================================
Trains an experimental RandomForestClassifier directly on mapped public benchmark
data (CIC-IDS2017 schema) for comparative academic benchmarking against the production model.
Artifacts are saved strictly to a separate directory (ml/models/experimental_external/)
to ensure zero interference with the production inference pipeline.
"""

import json
from pathlib import Path
from typing import Any, Dict
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from ml.data.generator import TRAFFIC_CLASSES
from ml.evaluation.evaluate import evaluate_model, format_evaluation_report
from ml.evaluation.external_dataset_loader import load_external_cic_dataset
from ml.features.extractor import FEATURE_NAMES, FeatureExtractor

EXP_ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "models" / "experimental_external"


def run_external_training_pipeline(
    n_samples: int = 10000,
    random_seed: int = 42,
    artifacts_dir: Path = EXP_ARTIFACTS_DIR,
) -> Dict[str, Any]:
    """
    Train and evaluate an experimental model strictly on external benchmark distribution.
    """
    print(f"[*] Generating/Loading external benchmark dataset ({n_samples} samples)...")
    df, stats = load_external_cic_dataset(n_samples=n_samples, random_seed=random_seed)

    X, y_labels = FeatureExtractor.extract_from_dataframe(df)

    label_encoder = LabelEncoder()
    label_encoder.fit(TRAFFIC_CLASSES)
    y = label_encoder.transform(y_labels)

    # 70/15/15 Stratified Split
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, random_state=random_seed, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.17647, random_state=random_seed, stratify=y_train_val
    )

    # Preprocessing: StandardScaler fitted strictly on Train partition
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=random_seed,
        n_jobs=-1,
    )
    clf.fit(X_train_scaled, y_train)

    test_preds = clf.predict(X_test_scaled)
    test_metrics = evaluate_model(
        y_true=label_encoder.inverse_transform(y_test),
        y_pred=label_encoder.inverse_transform(test_preds),
        labels=TRAFFIC_CLASSES,
    )

    print("\n" + "=" * 50)
    print("   EXPERIMENTAL EXTERNAL MODEL TEST EVALUATION")
    print("=" * 50)
    print(format_evaluation_report(test_metrics))

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, artifacts_dir / "model.joblib")
    joblib.dump(scaler, artifacts_dir / "scaler.joblib")
    joblib.dump(label_encoder, artifacts_dir / "label_encoder.joblib")

    with open(artifacts_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "model_type": "ExperimentalExternalRandomForest",
                "dataset_source": "CIC-IDS2017-Benchmark-Schema",
                "sample_counts": {
                    "total": int(len(df)),
                    "train": int(X_train.shape[0]),
                    "val": int(X_val.shape[0]),
                    "test": int(X_test.shape[0]),
                },
                "test_metrics": test_metrics,
            },
            f,
            indent=2,
        )

    return test_metrics


if __name__ == "__main__":
    run_external_training_pipeline()
