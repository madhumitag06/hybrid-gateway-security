"""
Phase 10: Authoritative XGBoost V2 500-Sample Holdout Benchmark
==============================================================
Evaluates the exact authoritative production model artifact (bigdata_v2)
from ml/models/candidates/bigdata_v2 on a balanced 500-sample holdout test suite
sampled from data/processed_v2/test.parquet (100 samples per class).
Measures accuracy, precision, recall, F1-scores, confusion matrix, and latency.
"""

import json
import time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support

def run_benchmark():
    model_dir = Path("ml/models/candidates/bigdata_v2")
    model_path = model_dir / "model.joblib"
    scaler_path = model_dir / "scaler.joblib"
    encoder_path = model_dir / "label_encoder.joblib"
    schema_path = model_dir / "feature_schema.json"
    metadata_path = model_dir / "metadata.json"
    test_parquet_path = Path("data/processed_v2/test.parquet")

    print(f"[1] Loading authoritative model artifact: {model_path}")
    assert model_path.exists(), f"Model artifact missing at {model_path}"
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    encoder = joblib.load(encoder_path)

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_data = json.load(f)
    feature_names = schema_data.get("feature_names", [])
    print(f"[2] Canonical 9-feature schema: {feature_names}")
    assert len(feature_names) == 9, f"Expected 9 features, got {len(feature_names)}"

    with open(metadata_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    print(f"[3] Model Algorithm: {meta.get('algorithm')}")
    print(f"[4] Production Classes: {meta.get('classes')}")

    print(f"[5] Loading holdout test records from: {test_parquet_path}")
    df_test = pd.read_parquet(test_parquet_path)
    classes = ["BENIGN", "PORT_SCAN", "BRUTE_FORCE", "TRAFFIC_SPIKE", "SUSPICIOUS_TRANSFER"]
    samples_per_class = 100

    sampled_dfs = []
    for c in classes:
        sub = df_test[df_test["label"] == c].sample(n=samples_per_class, random_state=42)
        sampled_dfs.append(sub)

    df_500 = pd.concat(sampled_dfs, ignore_index=True)
    X_raw = df_500[feature_names].to_numpy(dtype=np.float64)
    y_true = df_500["label"].to_numpy()
    total_samples = len(y_true)
    print(f"[6] Balanced evaluation matrix constructed: {X_raw.shape} (N={total_samples})")

    # Apply preprocessing scaling fitted during training
    X_scaled = scaler.transform(X_raw)

    # Latency profiling
    # Warmup
    for i in range(50):
        _ = model.predict(X_scaled[i:i+1])

    latencies = []
    for i in range(100):
        t0 = time.perf_counter()
        _ = model.predict(X_scaled[i:i+1])
        latencies.append((time.perf_counter() - t0) * 1000.0)

    median_latency = float(np.median(latencies))
    p95_latency = float(np.percentile(latencies, 95))

    # Batch throughput
    t_start = time.perf_counter()
    y_pred_idx = model.predict(X_scaled)
    batch_duration = time.perf_counter() - t_start
    throughput = float(total_samples / batch_duration)

    y_pred = encoder.inverse_transform(y_pred_idx)

    # Compute classification metrics
    acc = float(accuracy_score(y_true, y_pred))
    prec_macro, rec_macro, f1_macro, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    prec_wt, rec_wt, f1_wt, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=classes)
    report = classification_report(y_true, y_pred, labels=classes, output_dict=True, zero_division=0)

    print("\n" + "="*65)
    print("PHASE 10 AUTHORITATIVE XGBOOST V2 500-SAMPLE HOLDOUT BENCHMARK")
    print("="*65)
    print(f"Total Evaluated Samples : {total_samples}")
    print(f"Accuracy               : {acc * 100:.2f}%")
    print(f"Macro Precision        : {float(prec_macro) * 100:.2f}%")
    print(f"Macro Recall           : {float(rec_macro) * 100:.2f}%")
    print(f"Macro F1-Score         : {float(f1_macro) * 100:.2f}%")
    print(f"Weighted F1-Score      : {float(f1_wt) * 100:.2f}%")
    print(f"Median Latency         : {median_latency:.3f} ms")
    print(f"95th Pct Latency       : {p95_latency:.3f} ms")
    print(f"Batch Throughput       : {throughput:.0f} flows/sec")
    print("\nConfusion Matrix (Labels: BENIGN, PORT_SCAN, BRUTE_FORCE, TRAFFIC_SPIKE, SUSPICIOUS_TRANSFER):")
    print(cm)
    print("\nPer-Class Metrics:")
    for c in classes:
        cr = report[c]
        print(f"  {c:<20}: Precision={cr['precision']*100:.1f}%, Recall={cr['recall']*100:.1f}%, F1={cr['f1-score']*100:.1f}%, Support={cr['support']}")
    print("="*65)

    out_data = {
        "benchmark_name": "Phase 10 Authoritative XGBoost V2 500-Sample Holdout Verification",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_artifact": str(model_path),
        "total_samples": total_samples,
        "feature_schema": feature_names,
        "classes": classes,
        "overall": {
            "accuracy": acc,
            "macro_precision": float(prec_macro),
            "macro_recall": float(rec_macro),
            "macro_f1": float(f1_macro),
            "weighted_f1": float(f1_wt),
            "median_latency_ms": median_latency,
            "p95_latency_ms": p95_latency,
            "batch_throughput_fps": throughput,
        },
        "confusion_matrix": cm.tolist(),
        "per_class": report,
    }

    out_file = Path("ml/evaluation/phase10_benchmark_results.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(out_data, f, indent=2)
    print(f"\n[✓] Phase 10 Benchmark results exported to: {out_file}")

if __name__ == "__main__":
    run_benchmark()
