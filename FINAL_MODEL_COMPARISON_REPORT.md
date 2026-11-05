# FINAL MODEL COMPARISON REPORT: BASELINE VS. BIG DATA CANDIDATES

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Phase:** Phase 4 — Final Model Architecture Evaluation  
**Date:** November 2026  
**Artifacts Audited:** `data/reports/model_v2_comparison_report.json`, `data/reports/performance_stability_benchmark.json`  

---

## 1. Executive Summary

This report delivers the definitive comparative benchmark across all model architectures developed and evaluated for the **Adaptive AI-Powered Security Gateway for Hybrid Cloud**:

1. **Baseline Random Forest (Synthetic-Trained):** Active production model (`ml/models/model.joblib`, 100 trees, 10-feature schema with synthetic `failed_auth_count`).
2. **Big Data XGBoost V1:** First big data candidate (`ml/models/candidates/bigdata_v1/`, 100 estimators, max_depth=6, 10-feature schema).
3. **Big Data XGBoost V2:** Production-grade candidate (`ml/models/candidates/bigdata_v2/`, 100 estimators, max_depth=6, clean 9-feature schema).
4. **Big Data Random Forest V2:** Multi-dataset Random Forest (`train_and_compare_v2.py`, 100 trees, max_depth=16, clean 9-feature schema).
5. **Big Data LightGBM V2:** Multi-dataset LightGBM (`train_and_compare_v2.py`, 100 trees, num_leaves=63, clean 9-feature schema).

All models were evaluated under identical conditions on a stratified test partition of **99,997 samples** drawn from the cleaned 6.49M multi-dataset corpus (UNSW-NB15, CIC-IDS2017, CSE-CIC-IDS2018, CIC-DDoS2019).

---

## 2. Empirical Benchmark Matrix

| Evaluation Dimension | 1. Baseline RF (Synthetic) | 2. XGBoost V1 (Big Data) | 3. XGBoost V2 (Clean 9) | 4. Random Forest V2 | 5. LightGBM V2 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Feature Schema Version** | Schema V1 (10 Feats) | Schema V1 (10 Feats) | **Schema V2 (9 Feats)** | Schema V2 (9 Feats) | Schema V2 (9 Feats) |
| **Synthetic Features Used** | Yes (`failed_auth_count`) | Yes (Suppressed) | **None (100% Observable)**| None (100% Observable)| None (100% Observable)|
| **Overall Accuracy** | 57.23% | 96.12% | **98.42%** | 98.33% | 93.39% |
| **Macro Precision** | 0.1928 | 0.8124 | **0.9548** | 0.9412 | 0.7812 |
| **Macro Recall** | 0.3596 | 0.6982 | **0.9429** | 0.9205 | 0.6431 |
| **Macro F1 Score** | 0.1871 | 0.7340 | **0.9486** | 0.9301 | 0.6728 |
| **Weighted F1 Score** | 0.4993 | 0.9610 | **0.9842** | 0.9831 | 0.9312 |
| **False Positive Rate (FPR)**| 14.48% | 2.36% | **0.96%** | **0.89%** | 6.04% |
| **False Negative Rate (FNR)**| 74.90% | 6.40% | **2.51%** | 2.92% | 2.99% |
| **Single-Flow Latency (Mean)**| 20.73 ms | 1.12 ms | **0.897 ms** | 18.42 ms | 1.05 ms |
| **Single-Flow Latency (P95)** | 30.63 ms | 1.45 ms | **1.10 ms** | 26.50 ms | 1.32 ms |
| **Single-Flow Latency (P99)** | 33.24 ms | 1.82 ms | **1.76 ms** | 29.80 ms | 1.95 ms |
| **Batch Throughput (FPS)** | 226,671 fps | 480,120 fps | **507,372 fps** | 240,110 fps | 495,200 fps |
| **Model Artifact Size** | 1.14 MB | 2.28 MB | **2.29 MB** | 14.20 MB | 1.85 MB |
| **SHAP TreeExplainer Support**| Verified | Verified | **Verified (<35 ms)** | Verified (>120 ms) | Verified (<40 ms) |

---

## 3. Detailed Per-Class Performance Comparison

### Big Data XGBoost V2 (Clean 9-Feature Schema)
```
========================================================================================
CLASS                  PRECISION    RECALL      F1-SCORE    SUPPORT    FALSE POSITIVES
----------------------------------------------------------------------------------------
BENIGN                 0.9864       0.9904      0.9884      64,870     622 (0.96%)
PORT_SCAN              0.9935       0.9935      0.9935      1,531      10
BRUTE_FORCE            0.9980       1.0000      0.9990      1,485      3
TRAFFIC_SPIKE          0.9796       0.9739      0.9767      31,623     595
SUSPICIOUS_TRANSFER    0.8150       0.7566      0.7847      489        84
----------------------------------------------------------------------------------------
MACRO AVERAGE          0.9548       0.9429      0.9486      99,997     FPR: 0.96%
WEIGHTED AVERAGE       0.9842       0.9842      0.9842      99,997     FNR: 2.51%
========================================================================================
```

### Baseline Random Forest (Synthetic-Trained)
```
========================================================================================
CLASS                  PRECISION    RECALL      F1-SCORE    SUPPORT    FALSE POSITIVES
----------------------------------------------------------------------------------------
BENIGN                 0.6806       0.8552      0.7580      64,870     9,395 (14.48%)
PORT_SCAN              0.1530       0.9327      0.2628      1,531      7,908
BRUTE_FORCE            0.0000       0.0000      0.0000      1,485      0 (Missed 100%)
TRAFFIC_SPIKE          0.2016       0.0102      0.0193      31,623     1,273
SUSPICIOUS_TRANSFER    0.0000       0.0000      0.0000      489        222
----------------------------------------------------------------------------------------
MACRO AVERAGE          0.1928       0.3596      0.1871      99,997     FPR: 14.48%
WEIGHTED AVERAGE       0.4993       0.5723      0.4993      99,997     FNR: 74.90%
========================================================================================
```

---

## 4. Why Big Data XGBoost V2 Outperforms All Competitors

1. **Resolution of Feature Leakage & Parity:**  
   XGBoost V2 is the first model to eliminate `failed_auth_count`. The legacy Random Forest and XGBoost V1 relied on this synthetic feature, causing training/inference parity failures in live network gateways.
2. **23.1x Latency Advantage:**  
   Scikit-Learn's Python/Cython decision tree traversal imposes a mean latency of **20.73 ms** per flow. In contrast, XGBoost V2's compiled native C++ engine evaluates single flows in **0.897 ms** (P95: 1.10 ms), well within the sub-5ms packet routing budget.
3. **Overcoming False Positives in Live Scenarios:**  
   As proven in live Docker Scenarios 3 and 4, XGBoost V2 correctly recognizes legitimate 1.2 MB web transfers and 320 KB REST API payloads as `BENIGN`, eliminating false-alarm rate-limiting that plagues the legacy model.
4. **SHAP TreeExplainer Efficiency:**  
   Computing SHAP TreeExplainer values for XGBoost V2 takes less than **35 ms**, compared to over **120 ms** for Random Forest V2.

---

## 5. Formal Recommendation for Phase 5

Big Data XGBoost V2 decisively surpasses all acceptance requirements:
- **Macro F1:** 0.9486 (> 0.90 target)
- **FPR:** 0.96% (< 2.0% target)
- **FNR:** 2.51% (< 5.0% target)
- **Single-flow latency:** 0.897 ms (< 5.0 ms target)
- **Feature Parity:** 100% clean observable 9-feature schema

**Decision:** Formally proceed to **Phase 5: Controlled Model Promotion and Rollback**, establishing Big Data XGBoost V2 as the authoritative production model while maintaining Baseline Random Forest as a standby rollback fail-safe.

