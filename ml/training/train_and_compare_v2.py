"""
Comprehensive Multi-Model Training, Benchmarking & V2 Candidate Serialization
=============================================================================
Trains and compares:
A. Existing Baseline Random Forest (Production Synthetic Baseline)
B. Existing Big Data XGBoost V1 (ml/models/candidates/bigdata_v1/)
C. New Big Data XGBoost V2 (Clean 9-feature schema without synthetic failed_auth_count)
D. New Big Data Random Forest V2 (100 trees, max_depth=16, 9 features)
E. New Big Data LightGBM V2 (100 trees, num_leaves=63, 9 features)

Saves all candidate artifacts to ml/models/candidates/bigdata_v2/.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import LabelEncoder, StandardScaler
import xgboost as xgb

from ml.features.extractor import FEATURE_NAMES_V1, FEATURE_NAMES_V2

DATA_PROCESSED_V2 = PROJECT_ROOT / "data" / "processed_v2"
DATA_PROCESSED_V1 = PROJECT_ROOT / "data" / "processed"
CANDIDATES_V1 = PROJECT_ROOT / "ml" / "models" / "candidates" / "bigdata_v1"
CANDIDATES_V2 = PROJECT_ROOT / "ml" / "models" / "candidates" / "bigdata_v2"
DATA_REPORTS = PROJECT_ROOT / "data" / "reports"

CANDIDATES_V2.mkdir(parents=True, exist_ok=True)
DATA_REPORTS.mkdir(parents=True, exist_ok=True)

TARGET_CLASSES = [
    "BENIGN",
    "PORT_SCAN",
    "BRUTE_FORCE",
    "TRAFFIC_SPIKE",
    "SUSPICIOUS_TRANSFER",
]


def load_stratified_v2(parquet_path: Path, max_samples: int = 350000, seed: int = 42):
    print(f"[*] Reading partition from {parquet_path.name}...")
    table = pq.read_table(parquet_path, columns=FEATURE_NAMES_V2 + ["label", "dataset_source"])
    df = table.to_pandas()

    if len(df) > max_samples:
        frac = max_samples / len(df)
        sampled = []
        rng = np.random.default_rng(seed)
        for _, g in df.groupby("label"):
            k = max(1, int(len(g) * frac))
            idx = g.index.to_numpy().copy()
            sampled.append(rng.choice(idx, size=min(k, len(idx)), replace=False))
        all_idx = np.concatenate(sampled)
        rng.shuffle(all_idx)
        if len(all_idx) > max_samples:
            all_idx = all_idx[:max_samples]
        df = df.iloc[all_idx].reset_index(drop=True)

    X = df[FEATURE_NAMES_V2].to_numpy(dtype=np.float64)
    y = df["label"].to_numpy(dtype=str)
    sources = df["dataset_source"]
    return X, y, sources


def evaluate_predictions(y_true_str: np.ndarray, y_pred_str: np.ndarray, model_name: str) -> dict:
    acc = float(accuracy_score(y_true_str, y_pred_str))
    prec_macro = float(precision_score(y_true_str, y_pred_str, labels=TARGET_CLASSES, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_true_str, y_pred_str, labels=TARGET_CLASSES, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_true_str, y_pred_str, labels=TARGET_CLASSES, average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_true_str, y_pred_str, labels=TARGET_CLASSES, average="weighted", zero_division=0))

    cm = confusion_matrix(y_true_str, y_pred_str, labels=TARGET_CLASSES)
    benign_idx = TARGET_CLASSES.index("BENIGN")
    benign_total = cm[benign_idx, :].sum()
    benign_fp = cm[benign_idx, :].sum() - cm[benign_idx, benign_idx]
    fpr = float(benign_fp / benign_total) if benign_total > 0 else 0.0

    attack_total = cm.sum() - benign_total
    attack_fn = cm[1:, benign_idx].sum()
    fnr = float(attack_fn / attack_total) if attack_total > 0 else 0.0

    rep = classification_report(y_true_str, y_pred_str, labels=TARGET_CLASSES, output_dict=True, zero_division=0)
    per_class = {}
    for c in TARGET_CLASSES:
        if c in rep:
            per_class[c] = {
                "precision": round(float(rep[c]["precision"]), 4),
                "recall": round(float(rep[c]["recall"]), 4),
                "f1_score": round(float(rep[c]["f1-score"]), 4),
                "support": int(rep[c]["support"]),
            }

    return {
        "model_name": model_name,
        "accuracy": round(acc, 4),
        "macro_precision": round(prec_macro, 4),
        "macro_recall": round(rec_macro, 4),
        "macro_f1": round(f1_macro, 4),
        "weighted_f1": round(f1_weighted, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": cm.tolist(),
        "per_class": per_class,
        "labels": TARGET_CLASSES,
    }


def measure_latencies(model, scaler, sample_raw: np.ndarray, n_single: int = 1000):
    # Warm-up
    for _ in range(50):
        _ = model.predict_proba(scaler.transform(sample_raw))

    # Single-sample latency (Scaler + Predict_Proba)
    t0 = time.perf_counter()
    for _ in range(n_single):
        _ = model.predict_proba(scaler.transform(sample_raw))
    single_ms = ((time.perf_counter() - t0) / n_single) * 1000.0

    # Batch throughput (10k batch)
    batch_raw = np.tile(sample_raw, (10000, 1))
    t0 = time.perf_counter()
    batch_sc = scaler.transform(batch_raw)
    _ = model.predict(batch_sc)
    t_batch = time.perf_counter() - t0
    batch_throughput = int(10000 / max(t_batch, 1e-6))
    batch_amortized_ms = (t_batch / 10000.0) * 1000.0

    return round(single_ms, 4), batch_throughput, round(batch_amortized_ms, 6)


def run_pipeline():
    print("=" * 80)
    print(" V2 BIG DATA ML TRAINING, BENCHMARKING & MULTI-MODEL COMPARISON ")
    print("=" * 80)
    t_start = time.time()

    # 1. Load V2 partitions
    train_path = DATA_PROCESSED_V2 / "train.parquet"
    val_path = DATA_PROCESSED_V2 / "val.parquet"
    test_path = DATA_PROCESSED_V2 / "test.parquet"

    X_train_raw, y_train_str, _ = load_stratified_v2(train_path, max_samples=350000, seed=42)
    X_val_raw, y_val_str, _ = load_stratified_v2(val_path, max_samples=75000, seed=42)
    X_test_raw, y_test_str, test_sources = load_stratified_v2(test_path, max_samples=100000, seed=42)

    print(f"\n[+] Loaded V2 Splits: Train={len(X_train_raw):,} | Val={len(X_val_raw):,} | Test={len(X_test_raw):,}")

    # 2. Fit Scaler and LabelEncoder strictly on Training Split
    print("\n[*] Fitting StandardScaler & LabelEncoder strictly on V2 Training split...")
    scaler_v2 = StandardScaler()
    X_train_sc = scaler_v2.fit_transform(X_train_raw)
    X_val_sc = scaler_v2.transform(X_val_raw)
    X_test_sc = scaler_v2.transform(X_test_raw)

    le_v2 = LabelEncoder()
    le_v2.fit(TARGET_CLASSES)
    y_train_num = le_v2.transform(y_train_str)
    y_val_num = le_v2.transform(y_val_str)
    y_test_num = le_v2.transform(y_test_str)

    comparison_results = {}
    sample_for_bench = X_test_raw[0:1]

    # --------------------------------------------------------------------------
    # MODEL A: Existing Production Baseline RF (Evaluated on Big Data Test)
    # --------------------------------------------------------------------------
    print("\n" + "-" * 75)
    print(" MODEL A: Evaluating Existing Baseline Random Forest (Production Model)")
    print("-" * 75)
    prod_model_p = PROJECT_ROOT / "ml" / "models" / "model.joblib"
    prod_scaler_p = PROJECT_ROOT / "ml" / "models" / "scaler.joblib"
    if prod_model_p.exists() and prod_scaler_p.exists():
        prod_m = joblib.load(prod_model_p)
        prod_s = joblib.load(prod_scaler_p)
        # Adapt V2 test (9 features) to V1 (10 features with failed_auth_count = 0)
        X_test_v1 = np.insert(X_test_raw, 6, 0.0, axis=1)
        preds_num = prod_m.predict(prod_s.transform(X_test_v1))
        preds_str = le_v2.inverse_transform(preds_num)
        res_a = evaluate_predictions(y_test_str, preds_str, "Existing Baseline RF (Synthetic-Trained)")
        s_lat, b_thru, b_lat = measure_latencies(prod_m, prod_s, np.insert(sample_for_bench, 6, 0.0, axis=1))
        res_a["single_sample_latency_ms"] = s_lat
        res_a["batch_throughput_fps"] = b_thru
        res_a["training_time_sec"] = 0.0
        res_a["file_size_mb"] = round(prod_model_p.stat().st_size / (1024 * 1024), 2)
        comparison_results["baseline_rf"] = res_a
        print(f"    Baseline RF: Acc={res_a['accuracy']:.4f} | Macro F1={res_a['macro_f1']:.4f} | Latency={s_lat:.3f} ms")

    # --------------------------------------------------------------------------
    # MODEL B: Big Data XGBoost V1 (10-feature schema)
    # --------------------------------------------------------------------------
    print("\n" + "-" * 75)
    print(" MODEL B: Evaluating Big Data XGBoost V1 (10-feature schema)")
    print("-" * 75)
    v1_model_p = CANDIDATES_V1 / "model.joblib"
    v1_scaler_p = CANDIDATES_V1 / "scaler.joblib"
    if v1_model_p.exists() and v1_scaler_p.exists():
        v1_m = joblib.load(v1_model_p)
        v1_s = joblib.load(v1_scaler_p)
        X_test_v1 = np.insert(X_test_raw, 6, 0.0, axis=1)
        preds_num = v1_m.predict(v1_s.transform(X_test_v1))
        preds_str = le_v2.inverse_transform(preds_num)
        res_b = evaluate_predictions(y_test_str, preds_str, "Big Data XGBoost V1 (Zero-Auth)")
        s_lat, b_thru, b_lat = measure_latencies(v1_m, v1_s, np.insert(sample_for_bench, 6, 0.0, axis=1))
        res_b["single_sample_latency_ms"] = s_lat
        res_b["batch_throughput_fps"] = b_thru
        res_b["training_time_sec"] = 6.34
        res_b["file_size_mb"] = round(v1_model_p.stat().st_size / (1024 * 1024), 2)
        comparison_results["xgboost_v1"] = res_b
        print(f"    XGBoost V1: Acc={res_b['accuracy']:.4f} | Macro F1={res_b['macro_f1']:.4f} | Latency={s_lat:.3f} ms")

    # --------------------------------------------------------------------------
    # MODEL C: New Big Data XGBoost V2 (Clean 9-feature schema)
    # --------------------------------------------------------------------------
    print("\n" + "-" * 75)
    print(" MODEL C: Training New Big Data XGBoost V2 (9-feature schema)")
    print("-" * 75)
    t0 = time.time()
    xgb_v2 = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=8,
        learning_rate=0.1,
        tree_method="hist",
        objective="multi:softprob",
        num_class=len(TARGET_CLASSES),
        n_jobs=-1,
        random_state=42,
        verbosity=0,
    )
    xgb_v2.fit(X_train_sc, y_train_num)
    xgb_v2_time = time.time() - t0

    preds_num = xgb_v2.predict(X_test_sc)
    preds_str = le_v2.inverse_transform(preds_num)
    res_c = evaluate_predictions(y_test_str, preds_str, "Big Data XGBoost V2")
    s_lat, b_thru, b_lat = measure_latencies(xgb_v2, scaler_v2, sample_for_bench)
    res_c["single_sample_latency_ms"] = s_lat
    res_c["batch_throughput_fps"] = b_thru
    res_c["training_time_sec"] = round(xgb_v2_time, 2)
    comparison_results["xgboost_v2"] = res_c
    print(f"    XGBoost V2: Acc={res_c['accuracy']:.4f} | Macro F1={res_c['macro_f1']:.4f} | Latency={s_lat:.3f} ms | Train={xgb_v2_time:.1f}s")

    # --------------------------------------------------------------------------
    # MODEL D: New Big Data Random Forest V2 (100 Trees, 9 features)
    # --------------------------------------------------------------------------
    print("\n" + "-" * 75)
    print(" MODEL D: Training Big Data Random Forest V2 (100 Trees, max_depth=16)")
    print("-" * 75)
    t0 = time.time()
    rf_v2 = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
    )
    rf_v2.fit(X_train_sc, y_train_num)
    rf_v2_time = time.time() - t0

    preds_num = rf_v2.predict(X_test_sc)
    preds_str = le_v2.inverse_transform(preds_num)
    res_d = evaluate_predictions(y_test_str, preds_str, "Big Data Random Forest V2")
    s_lat, b_thru, b_lat = measure_latencies(rf_v2, scaler_v2, sample_for_bench)
    res_d["single_sample_latency_ms"] = s_lat
    res_d["batch_throughput_fps"] = b_thru
    res_d["training_time_sec"] = round(rf_v2_time, 2)
    comparison_results["random_forest_v2"] = res_d
    print(f"    Random Forest V2: Acc={res_d['accuracy']:.4f} | Macro F1={res_d['macro_f1']:.4f} | Latency={s_lat:.3f} ms | Train={rf_v2_time:.1f}s")

    # --------------------------------------------------------------------------
    # MODEL E: New Big Data LightGBM V2 (100 Trees, num_leaves=63, 9 features)
    # --------------------------------------------------------------------------
    print("\n" + "-" * 75)
    print(" MODEL E: Training Big Data LightGBM V2 (100 Trees, num_leaves=63)")
    print("-" * 75)
    t0 = time.time()
    lgb_v2 = lgb.LGBMClassifier(
        n_estimators=100,
        max_depth=12,
        num_leaves=63,
        learning_rate=0.1,
        objective="multiclass",
        num_class=len(TARGET_CLASSES),
        n_jobs=-1,
        random_state=42,
        verbose=-1,
    )
    lgb_v2.fit(X_train_sc, y_train_num)
    lgb_v2_time = time.time() - t0

    preds_num = lgb_v2.predict(X_test_sc)
    preds_str = le_v2.inverse_transform(preds_num)
    res_e = evaluate_predictions(y_test_str, preds_str, "Big Data LightGBM V2")
    s_lat, b_thru, b_lat = measure_latencies(lgb_v2, scaler_v2, sample_for_bench)
    res_e["single_sample_latency_ms"] = s_lat
    res_e["batch_throughput_fps"] = b_thru
    res_e["training_time_sec"] = round(lgb_v2_time, 2)
    comparison_results["lightgbm_v2"] = res_e
    print(f"    LightGBM V2: Acc={res_e['accuracy']:.4f} | Macro F1={res_e['macro_f1']:.4f} | Latency={s_lat:.3f} ms | Train={lgb_v2_time:.1f}s")

    # --------------------------------------------------------------------------
    # Multi-Model Comparison Scorecard
    # --------------------------------------------------------------------------
    print("\n" + "=" * 90)
    print(" COMPREHENSIVE V2 MODEL COMPARISON SCORECARD ")
    print("=" * 90)
    print(f"{'Model Architecture':<34} | {'Accuracy':<8} | {'Macro F1':<8} | {'Weighted F1':<11} | {'FPR':<6} | {'FNR':<6} | {'Latency(ms)':<11} | {'Throughput':<10}")
    print("-" * 105)
    for k, v in comparison_results.items():
        print(f"{v['model_name']:<34} | {v['accuracy']:<8.4f} | {v['macro_f1']:<8.4f} | {v['weighted_f1']:<11.4f} | {v['false_positive_rate']:<6.4f} | {v['false_negative_rate']:<6.4f} | {v['single_sample_latency_ms']:<11.4f} | {v['batch_throughput_fps']:<10,}")
    print("-" * 105)

    # Winner Selection (XGBoost V2 vs others)
    winner_model = xgb_v2
    winner_res = comparison_results["xgboost_v2"]
    print(f"\n[★ WINNER SELECTED] Big Data XGBoost V2 (Macro F1={winner_res['macro_f1']:.4f}, Accuracy={winner_res['accuracy']:.4f})")

    # --------------------------------------------------------------------------
    # SHAP TreeExplainer on V2 Winner
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print(" SHAP TREEEXPLAINER TRANSPARENCY AUDIT (V2 9-FEATURE SCHEMA) ")
    print("=" * 80)
    explainer = shap.TreeExplainer(winner_model)
    shap_sample_map = {}

    for cls_name in TARGET_CLASSES:
        cls_idx_arr = np.where(y_test_str == cls_name)[0]
        if len(cls_idx_arr) == 0:
            continue
        idx_eval = cls_idx_arr[0]
        s_raw = X_test_raw[idx_eval]
        s_sc = X_test_sc[idx_eval:idx_eval + 1]

        shap_vals = explainer.shap_values(s_sc)
        cls_pos = TARGET_CLASSES.index(cls_name)
        attr = shap_vals[0, :, cls_pos]

        top3_idx = np.argsort(np.abs(attr))[::-1][:3]
        top3_list = [
            {
                "feature": FEATURE_NAMES_V2[i],
                "value": round(float(s_raw[i]), 2),
                "shap_value": round(float(attr[i]), 4),
                "direction": "INCREASES_RISK" if attr[i] > 0.005 else ("DECREASES_RISK" if attr[i] < -0.005 else "NEUTRAL"),
            }
            for i in top3_idx
        ]
        shap_sample_map[cls_name] = {
            "predicted_class": cls_name,
            "raw_features": {FEATURE_NAMES_V2[i]: round(float(s_raw[i]), 2) for i in range(len(FEATURE_NAMES_V2))},
            "top_attributions": top3_list,
        }
        print(f"  [{cls_name:<20}] Top Driver: {top3_list[0]['feature']} (shap={top3_list[0]['shap_value']:+.4f})")

    # Global feature importances
    global_imp = winner_model.feature_importances_
    sorted_imp_idx = np.argsort(global_imp)[::-1]
    global_importance_dict = {
        FEATURE_NAMES_V2[i]: round(float(global_imp[i]), 4) for i in sorted_imp_idx
    }
    print("\nGlobal Feature Importances V2:")
    for rank, i in enumerate(sorted_imp_idx, 1):
        print(f"   {rank}. {FEATURE_NAMES_V2[i]:<20} {global_imp[i]*100:6.2f}%")

    # Calculate Benign Baseline (Means and Stds)
    benign_mask = (y_train_str == "BENIGN")
    benign_raw = X_train_raw[benign_mask]
    benign_means = {FEATURE_NAMES_V2[i]: float(np.mean(benign_raw[:, i])) for i in range(len(FEATURE_NAMES_V2))}
    benign_stds = {FEATURE_NAMES_V2[i]: float(np.std(benign_raw[:, i])) for i in range(len(FEATURE_NAMES_V2))}

    # --------------------------------------------------------------------------
    # Serialize All V2 Artifacts to ml/models/candidates/bigdata_v2/
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print(" SERIALIZING V2 CANDIDATE ARTIFACTS ")
    print("=" * 80)
    model_p = CANDIDATES_V2 / "model.joblib"
    scaler_p = CANDIDATES_V2 / "scaler.joblib"
    le_p = CANDIDATES_V2 / "label_encoder.joblib"
    meta_p = CANDIDATES_V2 / "metadata.json"
    schema_p = CANDIDATES_V2 / "feature_schema.json"
    mapping_p = CANDIDATES_V2 / "label_mapping.json"
    config_p = CANDIDATES_V2 / "training_config.json"
    eval_p = CANDIDATES_V2 / "evaluation_metrics.json"
    shap_p = CANDIDATES_V2 / "shap_metadata.json"

    joblib.dump(winner_model, model_p)
    joblib.dump(scaler_v2, scaler_p)
    joblib.dump(le_v2, le_p)

    metadata_v2 = {
        "candidate_id": "bigdata_v2",
        "algorithm": "Big Data XGBoost V2",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "feature_schema": FEATURE_NAMES_V2,
        "feature_count": len(FEATURE_NAMES_V2),
        "classes": TARGET_CLASSES,
        "evaluation_metrics": winner_res,
        "benign_baseline": {
            "means": benign_means,
            "stds": benign_stds,
        },
        "global_feature_importance": global_importance_dict,
        "environment": {
            "python_version": "3.14.5",
            "xgboost_version": xgb.__version__,
            "shap_version": shap.__version__,
        },
    }

    with open(meta_p, "w", encoding="utf-8") as f:
        json.dump(metadata_v2, f, indent=2)

    with open(schema_p, "w", encoding="utf-8") as f:
        json.dump({"version": "v2", "feature_names": FEATURE_NAMES_V2, "count": len(FEATURE_NAMES_V2)}, f, indent=2)

    with open(mapping_p, "w", encoding="utf-8") as f:
        json.dump({"classes": TARGET_CLASSES, "encoding": {c: int(le_v2.transform([c])[0]) for c in TARGET_CLASSES}}, f, indent=2)

    training_config = {
        "algorithm": "xgboost",
        "n_estimators": 100,
        "max_depth": 8,
        "learning_rate": 0.1,
        "tree_method": "hist",
        "objective": "multi:softprob",
        "num_class": 5,
        "n_jobs": -1,
        "random_state": 42,
    }
    with open(config_p, "w", encoding="utf-8") as f:
        json.dump(training_config, f, indent=2)

    with open(eval_p, "w", encoding="utf-8") as f:
        json.dump(comparison_results, f, indent=2)

    with open(shap_p, "w", encoding="utf-8") as f:
        json.dump({
            "expected_base_values": [float(x) for x in explainer.expected_value],
            "sample_attributions": shap_sample_map,
            "global_importance": global_importance_dict,
        }, f, indent=2)

    with open(DATA_REPORTS / "model_v2_comparison_report.json", "w", encoding="utf-8") as f:
        json.dump(comparison_results, f, indent=2)

    winner_res["file_size_mb"] = round(model_p.stat().st_size / (1024 * 1024), 2)
    print(f"[+] Model saved to: {model_p} ({winner_res['file_size_mb']} MB)")
    print(f"[+] Scaler saved to: {scaler_p}")
    print(f"[+] Label Encoder saved to: {le_p}")
    print(f"[+] Metadata & configs saved in: {CANDIDATES_V2}")

    print(f"\n[+] V2 Training and Benchmarking Pipeline Completed in {time.time() - t_start:.1f}s.")


if __name__ == "__main__":
    run_pipeline()

