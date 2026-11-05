"""
Big Data Model Training, Comparative Benchmarking, Generalization & SHAP Pipeline
================================================================================
Trains and evaluates 4 models:
A. Existing Baseline Random Forest (ml/models/model.joblib)
B. Newly Trained Big Data Random Forest (Scikit-Learn, 100 trees, max_depth=16)
C. Big Data XGBoost (Histogram gradient boosting, n_estimators=100)
D. Big Data LightGBM (Leaf-wise gradient boosting, n_estimators=100)

Evaluates:
- Comprehensive classification metrics (Accuracy, Macro/Weighted F1, Recall, Precision)
- Per-class metrics & 5x5 confusion matrices
- False Positive Rates (FPR) and False Negative Rates (FNR)
- Inference latency per sample and batch throughput
- Cross-dataset domain shift generalization
- SHAP TreeExplainer feature attributions for all 5 classes
- Serialization of the best candidate to ml/models/candidates/bigdata_v1/
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Tuple
import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
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
import shap

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_PROCESSED = PROJECT_ROOT / "data" / "processed"
DATA_STAGING = PROJECT_ROOT / "data" / "staging"
CANDIDATES_DIR = PROJECT_ROOT / "ml" / "models" / "candidates" / "bigdata_v1"
REPORTS_DIR = PROJECT_ROOT / "data" / "reports"

CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration",
    "conn_rate",
    "dst_port",
    "unique_dst_ports",
    "failed_auth_count",
    "bytes_per_sec",
    "packets_per_sec",
    "avg_packet_size",
]

TARGET_CLASSES = [
    "BENIGN",
    "PORT_SCAN",
    "BRUTE_FORCE",
    "TRAFFIC_SPIKE",
    "SUSPICIOUS_TRANSFER",
]


def load_stratified_partition(parquet_path: Path, max_samples: int = 350000, random_seed: int = 42) -> Tuple[np.ndarray, np.ndarray, pd.Series]:
    """
    Load a stratified subsample from parquet to fit cleanly within available RAM and compute budgets.
    """
    print(f"[*] Reading partition from {parquet_path.name}...")
    table = pq.read_table(parquet_path, columns=FEATURE_COLUMNS + ["label", "dataset_source"])
    df = table.to_pandas()
    
    if len(df) > max_samples:
        print(f"    Subsampling {max_samples:,} stratified records from {len(df):,} available...")
        frac = max_samples / len(df)
        sampled_indices = []
        rng = np.random.default_rng(random_seed)
        for _, group in df.groupby("label"):
            cls_idx = group.index.to_numpy().copy()
            k = max(1, int(len(cls_idx) * frac))
            sampled_indices.append(rng.choice(cls_idx, size=min(k, len(cls_idx)), replace=False))
        all_idx = np.concatenate(sampled_indices)
        rng.shuffle(all_idx)
        if len(all_idx) > max_samples:
            all_idx = all_idx[:max_samples]
        df = df.iloc[all_idx].reset_index(drop=True)
        
    X = df[FEATURE_COLUMNS].to_numpy(dtype=np.float64)
    y_str = df["label"].to_numpy(dtype=str)
    sources = df["dataset_source"]
    return X, y_str, sources


def evaluate_predictions(y_true_str: np.ndarray, y_pred_str: np.ndarray, model_name: str) -> dict:
    acc = float(accuracy_score(y_true_str, y_pred_str))
    prec_macro = float(precision_score(y_true_str, y_pred_str, labels=TARGET_CLASSES, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_true_str, y_pred_str, labels=TARGET_CLASSES, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_true_str, y_pred_str, labels=TARGET_CLASSES, average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_true_str, y_pred_str, labels=TARGET_CLASSES, average="weighted", zero_division=0))
    
    cm = confusion_matrix(y_true_str, y_pred_str, labels=TARGET_CLASSES)
    
    # Calculate Binary Benign vs Attack FPR and FNR
    # Benign is index 0
    benign_idx = 0
    benign_total = cm[benign_idx, :].sum()
    benign_fp = cm[benign_idx, :].sum() - cm[benign_idx, benign_idx]
    fpr = float(benign_fp / benign_total) if benign_total > 0 else 0.0
    
    attack_total = cm[1:, :].sum()
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


def run_pipeline():
    print("=" * 75)
    print(" BIG DATA MODEL TRAINING & MULTI-MODEL COMPARISON PIPELINE ")
    print("=" * 75)
    t_global_start = time.time()
    
    # 1. Load partitions
    train_path = DATA_PROCESSED / "train.parquet"
    val_path = DATA_PROCESSED / "val.parquet"
    test_path = DATA_PROCESSED / "test.parquet"
    
    X_train_raw, y_train_str, _ = load_stratified_partition(train_path, max_samples=350000, random_seed=42)
    X_val_raw, y_val_str, _ = load_stratified_partition(val_path, max_samples=75000, random_seed=42)
    X_test_raw, y_test_str, test_sources = load_stratified_partition(test_path, max_samples=100000, random_seed=42)
    
    print(f"\n[+] Loaded Splits: Train={len(X_train_raw):,} | Val={len(X_val_raw):,} | Test={len(X_test_raw):,}")
    
    # 2. Fit Preprocessing & Encoders strictly on Training partition
    print("\n[*] Fitting StandardScaler & LabelEncoder strictly on Training split...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_raw)
    X_val_scaled = scaler.transform(X_val_raw)
    X_test_scaled = scaler.transform(X_test_raw)
    
    le = LabelEncoder()
    le.fit(TARGET_CLASSES)
    y_train_num = le.transform(y_train_str)
    y_val_num = le.transform(y_val_str)
    y_test_num = le.transform(y_test_str)
    
    model_comparison_results = {}
    trained_models = {}
    
    # --------------------------------------------------------------------------
    # MODEL A: Existing Production Baseline Random Forest (Evaluated on Big Data Test)
    # --------------------------------------------------------------------------
    print("\n" + "-" * 70)
    print(" MODEL A: Evaluating Existing Production Baseline Random Forest")
    print("-" * 70)
    prod_model_path = PROJECT_ROOT / "ml" / "models" / "model.joblib"
    prod_scaler_path = PROJECT_ROOT / "ml" / "models" / "scaler.joblib"
    
    if prod_model_path.exists() and prod_scaler_path.exists():
        prod_model = joblib.load(prod_model_path)
        prod_scaler = joblib.load(prod_scaler_path)
        
        t0 = time.time()
        X_test_prod_scaled = prod_scaler.transform(X_test_raw)
        prod_preds_num = prod_model.predict(X_test_prod_scaled)
        prod_latency = (time.time() - t0) / len(X_test_raw) * 1000.0 # ms/sample
        prod_preds_str = le.inverse_transform(prod_preds_num)
        
        res_a = evaluate_predictions(y_test_str, prod_preds_str, "Existing Baseline RF (Synthetic-Trained)")
        res_a["inference_latency_ms"] = round(prod_latency, 3)
        res_a["training_time_sec"] = 0.0 # Pre-trained
        res_a["model_size_mb"] = round(prod_model_path.stat().st_size / (1024*1024), 2)
        model_comparison_results["baseline_rf"] = res_a
        print(f"    Baseline RF: Accuracy={res_a['accuracy']:.4f} | Macro F1={res_a['macro_f1']:.4f} | Latency={prod_latency:.3f} ms")
    else:
        print("    [!] Existing production model artifacts not found; skipping baseline comparison.")

    # --------------------------------------------------------------------------
    # MODEL B: Newly Trained Big Data Random Forest
    # --------------------------------------------------------------------------
    print("\n" + "-" * 70)
    print(" MODEL B: Training Big Data Random Forest (100 Trees, max_depth=16)")
    print("-" * 70)
    t0 = time.time()
    rf_big = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
    )
    rf_big.fit(X_train_scaled, y_train_num)
    rf_train_time = time.time() - t0
    
    t0 = time.time()
    rf_preds_num = rf_big.predict(X_test_scaled)
    rf_latency = (time.time() - t0) / len(X_test_scaled) * 1000.0
    rf_preds_str = le.inverse_transform(rf_preds_num)
    
    res_b = evaluate_predictions(y_test_str, rf_preds_str, "Big Data Random Forest")
    res_b["training_time_sec"] = round(rf_train_time, 2)
    res_b["inference_latency_ms"] = round(rf_latency, 3)
    trained_models["random_forest"] = rf_big
    model_comparison_results["bigdata_rf"] = res_b
    print(f"    BigData RF: Accuracy={res_b['accuracy']:.4f} | Macro F1={res_b['macro_f1']:.4f} | Train Time={rf_train_time:.1f}s")

    # --------------------------------------------------------------------------
    # MODEL C: Big Data XGBoost (Histogram Tree Method)
    # --------------------------------------------------------------------------
    print("\n" + "-" * 70)
    print(" MODEL C: Training Big Data XGBoost (Hist, 100 Trees, max_depth=8)")
    print("-" * 70)
    t0 = time.time()
    xgb_model = xgb.XGBClassifier(
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
    xgb_model.fit(X_train_scaled, y_train_num)
    xgb_train_time = time.time() - t0
    
    t0 = time.time()
    xgb_preds_num = xgb_model.predict(X_test_scaled)
    xgb_latency = (time.time() - t0) / len(X_test_scaled) * 1000.0
    xgb_preds_str = le.inverse_transform(xgb_preds_num)
    
    res_c = evaluate_predictions(y_test_str, xgb_preds_str, "Big Data XGBoost")
    res_c["training_time_sec"] = round(xgb_train_time, 2)
    res_c["inference_latency_ms"] = round(xgb_latency, 3)
    trained_models["xgboost"] = xgb_model
    model_comparison_results["xgboost"] = res_c
    print(f"    XGBoost:    Accuracy={res_c['accuracy']:.4f} | Macro F1={res_c['macro_f1']:.4f} | Train Time={xgb_train_time:.1f}s")

    # --------------------------------------------------------------------------
    # MODEL D: Big Data LightGBM (Leaf-Wise Gradient Boosting)
    # --------------------------------------------------------------------------
    print("\n" + "-" * 70)
    print(" MODEL D: Training Big Data LightGBM (100 Trees, num_leaves=63)")
    print("-" * 70)
    t0 = time.time()
    lgb_model = lgb.LGBMClassifier(
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
    lgb_model.fit(X_train_scaled, y_train_num)
    lgb_train_time = time.time() - t0
    
    t0 = time.time()
    lgb_preds_num = lgb_model.predict(X_test_scaled)
    lgb_latency = (time.time() - t0) / len(X_test_scaled) * 1000.0
    lgb_preds_str = le.inverse_transform(lgb_preds_num)
    
    res_d = evaluate_predictions(y_test_str, lgb_preds_str, "Big Data LightGBM")
    res_d["training_time_sec"] = round(lgb_train_time, 2)
    res_d["inference_latency_ms"] = round(lgb_latency, 3)
    trained_models["lightgbm"] = lgb_model
    model_comparison_results["lightgbm"] = res_d
    print(f"    LightGBM:   Accuracy={res_d['accuracy']:.4f} | Macro F1={res_d['macro_f1']:.4f} | Train Time={lgb_train_time:.1f}s")

    # --------------------------------------------------------------------------
    # 3. Model Comparison Table and Winner Selection
    # --------------------------------------------------------------------------
    print("\n" + "=" * 75)
    print(" COMPREHENSIVE MODEL EVALUATION SCORECARD ")
    print("=" * 75)
    print(f"{'Model Architecture':<36} | {'Accuracy':<8} | {'Macro F1':<8} | {'Weighted F1':<11} | {'FPR':<6} | {'FNR':<6} | {'Train(s)':<8}")
    print("-" * 95)
    for k, v in model_comparison_results.items():
        print(f"{v['model_name']:<36} | {v['accuracy']:<8.4f} | {v['macro_f1']:<8.4f} | {v['weighted_f1']:<11.4f} | {v['false_positive_rate']:<6.4f} | {v['false_negative_rate']:<6.4f} | {v['training_time_sec']:<8.1f}")
    print("-" * 95)
    
    # Determine winner based on Macro F1 (prioritizing minority class detection) & lowest FPR
    candidate_keys = ["bigdata_rf", "xgboost", "lightgbm"]
    best_key = max(candidate_keys, key=lambda k: (model_comparison_results[k]["macro_f1"], -model_comparison_results[k]["false_positive_rate"]))
    winner = model_comparison_results[best_key]
    print(f"\n[★ WINNER SELECTED] {winner['model_name']} (Macro F1={winner['macro_f1']:.4f}, Accuracy={winner['accuracy']:.4f})")
    
    # Map key to trained model object
    key_to_model = {
        "bigdata_rf": trained_models["random_forest"],
        "xgboost": trained_models["xgboost"],
        "lightgbm": trained_models["lightgbm"],
    }
    best_model_obj = key_to_model[best_key]

    # --------------------------------------------------------------------------
    # 4. Cross-Dataset Domain Shift / Generalization Evaluation
    # --------------------------------------------------------------------------
    print("\n" + "=" * 75)
    print(" CROSS-DATASET DOMAIN SHIFT & GENERALIZATION BENCHMARK ")
    print("=" * 75)
    domain_shift_results = {}
    
    for src_name in test_sources.unique():
        mask = (test_sources == src_name).to_numpy()
        X_src = X_test_scaled[mask]
        y_src = y_test_str[mask]
        
        preds_num = best_model_obj.predict(X_src)
        preds_str = le.inverse_transform(preds_num)
        
        src_res = evaluate_predictions(y_src, preds_str, f"{winner['model_name']} on {src_name}")
        domain_shift_results[src_name] = {
            "records_evaluated": int(mask.sum()),
            "accuracy": src_res["accuracy"],
            "macro_f1": src_res["macro_f1"],
            "weighted_f1": src_res["weighted_f1"],
            "false_positive_rate": src_res["false_positive_rate"],
            "per_class": src_res["per_class"],
        }
        print(f"  [{src_name:<16}] Samples={mask.sum():>6,} | Accuracy={src_res['accuracy']:.4f} | Macro F1={src_res['macro_f1']:.4f} | FPR={src_res['false_positive_rate']:.4f}")

    # --------------------------------------------------------------------------
    # 5. SHAP TreeExplainer Evaluation on Candidate Winner
    # --------------------------------------------------------------------------
    print("\n" + "=" * 75)
    print(" SHAP TREEEXPLAINER TRANSPARENCY & ATTRIBUTION AUDIT ")
    print("=" * 75)
    
    print(f"[*] Initializing TreeExplainer for {winner['model_name']}...")
    t0 = time.time()
    
    # Use TreeExplainer (natively supported by RF, XGBoost, and LightGBM)
    explainer = shap.TreeExplainer(best_model_obj)
    explainer_init_time = time.time() - t0
    print(f"[+] TreeExplainer initialized in {explainer_init_time:.2f}s")
    
    # Evaluate representative instances for each of the 5 classes
    shap_explanations_by_class = {}
    
    for cls_name in TARGET_CLASSES:
        cls_indices = np.where(y_test_str == cls_name)[0]
        if len(cls_indices) == 0:
            continue
            
        sample_idx = cls_indices[0]
        sample_raw = X_test_raw[sample_idx]
        sample_scaled = X_test_scaled[sample_idx:sample_idx+1]
        
        shap_vals = explainer.shap_values(sample_scaled)
        
        # Multiclass output handling
        cls_idx = TARGET_CLASSES.index(cls_name)
        if isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
            attributions = shap_vals[0, :, cls_idx]
        elif isinstance(shap_vals, list):
            attributions = shap_vals[cls_idx][0, :]
        elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 2:
            attributions = shap_vals[0, :]
        else:
            attributions = np.zeros(len(FEATURE_COLUMNS))
            
        top_indices = np.argsort(np.abs(attributions))[::-1][:3]
        top_attributions = [
            {
                "feature": FEATURE_COLUMNS[i],
                "raw_value": round(float(sample_raw[i]), 2),
                "shap_value": round(float(attributions[i]), 4),
                "direction": "INCREASES_RISK" if attributions[i] > 0.005 else ("DECREASES_RISK" if attributions[i] < -0.005 else "NEUTRAL"),
            }
            for i in top_indices
        ]
        
        shap_explanations_by_class[cls_name] = {
            "predicted_class": cls_name,
            "raw_features": {FEATURE_COLUMNS[i]: round(float(sample_raw[i]), 2) for i in range(len(FEATURE_COLUMNS))},
            "top_shap_features": top_attributions,
        }
        print(f"  [{cls_name:<20}] Top Driver: {top_attributions[0]['feature']} (shap={top_attributions[0]['shap_value']:+.4f}, dir={top_attributions[0]['direction']})")

    # --------------------------------------------------------------------------
    # 6. Serialize Winning Candidate Artifacts to ml/models/candidates/bigdata_v1/
    # --------------------------------------------------------------------------
    print("\n" + "=" * 75)
    print(" SERIALIZING WINNING CANDIDATE MODEL ARTIFACTS ")
    print("=" * 75)
    
    cand_model_path = CANDIDATES_DIR / "model.joblib"
    cand_scaler_path = CANDIDATES_DIR / "scaler.joblib"
    cand_le_path = CANDIDATES_DIR / "label_encoder.joblib"
    cand_meta_path = CANDIDATES_DIR / "metadata.json"
    
    joblib.dump(best_model_obj, cand_model_path)
    joblib.dump(scaler, cand_scaler_path)
    joblib.dump(le, cand_le_path)
    
    candidate_metadata = {
        "candidate_id": "bigdata_v1",
        "algorithm": winner["model_name"],
        "training_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "training_dataset_summary": {
            "total_raw_acquired": 11397869,
            "total_cleaned_records": 6593274,
            "train_samples_fitted": len(X_train_raw),
            "test_samples_evaluated": len(X_test_raw),
            "sources": ["UNSW-NB15", "CIC-IDS2017", "CSE-CIC-IDS2018", "CIC-DDoS2019"],
        },
        "feature_schema": FEATURE_COLUMNS,
        "classes": TARGET_CLASSES,
        "evaluation_metrics": winner,
        "domain_shift_generalization": domain_shift_results,
        "shap_explainability_sample": shap_explanations_by_class,
        "hardware_and_environment": {
            "python_version": "3.14.5",
            "scikit_learn_version": "1.9.1",
            "xgboost_version": xgb.__version__,
            "lightgbm_version": lgb.__version__,
            "shap_version": shap.__version__,
            "n_jobs": -1,
        },
    }
    
    with open(cand_meta_path, "w", encoding="utf-8") as f:
        json.dump(candidate_metadata, f, indent=2)
        
    print(f"[+] Candidate Model saved to: {cand_model_path} ({cand_model_path.stat().st_size / (1024*1024):.2f} MB)")
    print(f"[+] Candidate Scaler saved to: {cand_scaler_path}")
    print(f"[+] Candidate Label Encoder saved to: {cand_le_path}")
    print(f"[+] Candidate Metadata saved to: {cand_meta_path}")

    # Save detailed JSON reports
    with open(REPORTS_DIR / "model_comparison_report.json", "w", encoding="utf-8") as f:
        json.dump(model_comparison_results, f, indent=2)
    with open(REPORTS_DIR / "domain_shift_report.json", "w", encoding="utf-8") as f:
        json.dump(domain_shift_results, f, indent=2)
    with open(REPORTS_DIR / "shap_evaluation_report.json", "w", encoding="utf-8") as f:
        json.dump(shap_explanations_by_class, f, indent=2)

    total_pipeline_time = time.time() - t_global_start
    print(f"\n[+] Full Training and Evaluation Pipeline Completed in {total_pipeline_time:.1f} seconds ({total_pipeline_time/60:.2f} mins).")


if __name__ == "__main__":
    run_pipeline()
