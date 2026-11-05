"""
Strict Leave-One-Dataset-Out (LODO) Generalization Benchmark
============================================================
Evaluates genuine cross-network domain shift by iteratively holding out
one complete dataset source from training, fitting XGBoost V2 strictly
on the other 3 sources, and testing purely on the unseen held-out network.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
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

from ml.features.extractor import FEATURE_NAMES_V2

DATA_STAGING_V2 = PROJECT_ROOT / "data" / "staging_v2"
DATA_REPORTS = PROJECT_ROOT / "data" / "reports"
DATA_REPORTS.mkdir(parents=True, exist_ok=True)

TARGET_CLASSES = [
    "BENIGN",
    "PORT_SCAN",
    "BRUTE_FORCE",
    "TRAFFIC_SPIKE",
    "SUSPICIOUS_TRANSFER",
]

DATASET_FILES = {
    "UNSW-NB15": DATA_STAGING_V2 / "unsw_nb15.parquet",
    "CIC-IDS2017": DATA_STAGING_V2 / "cic_ids2017.parquet",
    "CSE-CIC-IDS2018": DATA_STAGING_V2 / "cse_cic_ids2018.parquet",
    "CIC-DDoS2019": DATA_STAGING_V2 / "cic_ddos2019.parquet",
}


def load_stratified_df(parquet_path: Path, max_samples: int = 150000, seed: int = 42) -> pd.DataFrame:
    df = pd.read_parquet(parquet_path, columns=FEATURE_NAMES_V2 + ["label", "dataset_source"])
    if len(df) > max_samples:
        frac = max_samples / len(df)
        sampled = []
        rng = np.random.default_rng(seed)
        for _, g in df.groupby("label"):
            k = max(1, int(len(g) * frac))
            idx = g.index.to_numpy().copy()
            chosen = rng.choice(idx, size=min(k, len(idx)), replace=False)
            sampled.append(chosen)
        all_idx = np.concatenate(sampled)
        rng.shuffle(all_idx)
        df = df.loc[all_idx].reset_index(drop=True)
    return df


def run_lodo_benchmark():
    print("=" * 80)
    print(" STRICT LEAVE-ONE-DATASET-OUT (LODO) GENERALIZATION BENCHMARK ")
    print("=" * 80)
    t_global_start = time.time()

    le = LabelEncoder()
    le.fit(TARGET_CLASSES)

    lodo_results = {}

    for held_out_name in DATASET_FILES.keys():
        print("\n" + "-" * 75)
        print(f" [LODO RUN] HELD-OUT UNSEEN DATASET: {held_out_name}")
        print("-" * 75)
        t_run_start = time.time()

        # 1. Pool training data strictly from the other 3 datasets
        train_dfs = []
        for src_name, path in DATASET_FILES.items():
            if src_name == held_out_name:
                continue
            df_part = load_stratified_df(path, max_samples=100000, seed=42)
            train_dfs.append(df_part)
            print(f"    Train Source: {src_name:<16} ({len(df_part):,} records)")

        df_train = pd.concat(train_dfs, ignore_index=True)

        # 2. Load held-out test data
        df_test = load_stratified_df(DATASET_FILES[held_out_name], max_samples=75000, seed=42)
        print(f"    Test Source:  {held_out_name:<16} ({len(df_test):,} held-out records)")

        # Verify zero source overlap
        assert held_out_name not in df_train["dataset_source"].unique()

        X_train_raw = df_train[FEATURE_NAMES_V2].to_numpy(dtype=np.float64)
        y_train_str = df_train["label"].to_numpy(dtype=str)

        X_test_raw = df_test[FEATURE_NAMES_V2].to_numpy(dtype=np.float64)
        y_test_str = df_test["label"].to_numpy(dtype=str)

        # Fit Scaler strictly on training pool
        scaler = StandardScaler()
        X_train_sc = scaler.fit_transform(X_train_raw)
        X_test_sc = scaler.transform(X_test_raw)

        # Filter classes present in training
        present_classes = sorted(list(np.unique(y_train_str)))
        train_le = LabelEncoder()
        train_le.fit(present_classes)
        y_train_num = train_le.transform(y_train_str)

        # Train XGBoost V2 on the 3 pooled sources
        print(f"    Fitting XGBoost V2 on {len(X_train_raw):,} training records across {len(present_classes)} classes...")
        t0 = time.time()
        model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=8,
            learning_rate=0.1,
            tree_method="hist",
            objective="multi:softprob",
            num_class=len(present_classes),
            n_jobs=-1,
            random_state=42,
            verbosity=0,
        )
        model.fit(X_train_sc, y_train_num)
        train_time = time.time() - t0

        # Evaluate on held-out unseen dataset
        preds_num = model.predict(X_test_sc)
        preds_str = train_le.inverse_transform(preds_num)

        acc = float(accuracy_score(y_test_str, preds_str))
        eval_classes = [c for c in TARGET_CLASSES if c in np.unique(y_test_str)]
        macro_f1 = float(f1_score(y_test_str, preds_str, labels=eval_classes, average="macro", zero_division=0))
        weighted_f1 = float(f1_score(y_test_str, preds_str, labels=eval_classes, average="weighted", zero_division=0))

        cm = confusion_matrix(y_test_str, preds_str, labels=TARGET_CLASSES)
        benign_idx = TARGET_CLASSES.index("BENIGN")
        benign_total = cm[benign_idx, :].sum()
        benign_fp = cm[benign_idx, :].sum() - cm[benign_idx, benign_idx]
        fpr = float(benign_fp / benign_total) if benign_total > 0 else 0.0

        attack_total = cm.sum() - benign_total
        attack_fn = cm[1:, benign_idx].sum()
        fnr = float(attack_fn / attack_total) if attack_total > 0 else 0.0

        rep = classification_report(y_test_str, preds_str, labels=TARGET_CLASSES, output_dict=True, zero_division=0)
        per_class = {}
        for c in TARGET_CLASSES:
            if c in rep:
                per_class[c] = {
                    "precision": round(float(rep[c]["precision"]), 4),
                    "recall": round(float(rep[c]["recall"]), 4),
                    "f1_score": round(float(rep[c]["f1-score"]), 4),
                    "support": int(rep[c]["support"]),
                }

        run_elapsed = time.time() - t_run_start
        print(f"    [RESULT] Held-Out {held_out_name}: Acc={acc:.4f} | Macro F1={macro_f1:.4f} | Weighted F1={weighted_f1:.4f} | FPR={fpr:.4f} | FNR={fnr:.4f} in {run_elapsed:.1f}s")

        lodo_results[held_out_name] = {
            "held_out_dataset": held_out_name,
            "trained_on_sources": [s for s in DATASET_FILES.keys() if s != held_out_name],
            "train_sample_count": len(X_train_raw),
            "test_sample_count": len(X_test_raw),
            "training_time_sec": round(train_time, 2),
            "accuracy": round(acc, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "per_class": per_class,
            "confusion_matrix": cm.tolist(),
        }

    # Summary table
    print("\n" + "=" * 80)
    print(" LEAVE-ONE-DATASET-OUT SCORECARD SUMMARY ")
    print("=" * 80)
    print(f"{'Held-Out Dataset':<20} | {'Accuracy':<8} | {'Macro F1':<8} | {'Weighted F1':<11} | {'FPR':<6} | {'FNR':<6}")
    print("-" * 75)
    for k, v in lodo_results.items():
        print(f"{k:<20} | {v['accuracy']:<8.4f} | {v['macro_f1']:<8.4f} | {v['weighted_f1']:<11.4f} | {v['false_positive_rate']:<6.4f} | {v['false_negative_rate']:<6.4f}")
    print("-" * 75)

    with open(DATA_REPORTS / "leave_one_dataset_out_report.json", "w", encoding="utf-8") as f:
        json.dump(lodo_results, f, indent=2)

    total_time = time.time() - t_global_start
    print(f"\n[+] LODO Benchmark Completed in {total_time:.1f}s ({total_time/60:.2f} mins).")


if __name__ == "__main__":
    run_lodo_benchmark()

