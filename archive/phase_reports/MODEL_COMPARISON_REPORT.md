# Big Data ML Training: Comprehensive Model Comparison Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Evaluation Dataset:** Stratified Held-Out Big Data Test Partition ($N = 99,997$ records)  
**Evaluation Date:** 2026-11-06  
**Winner Selected:** **Big Data XGBoost** (Histogram Gradient Boosting)

---

## 1. Executive Summary & Benchmark Scorecard

Four model configurations were rigorously evaluated on an identical 99,997-sample held-out multi-source test set:
1. **Existing Baseline Random Forest** (Synthetic-Trained production model)
2. **Big Data Random Forest** (Scikit-Learn, 100 estimators, max_depth=16)
3. **Big Data XGBoost** (Histogram gradient boosting, 100 estimators, max_depth=8)
4. **Big Data LightGBM** (Leaf-wise gradient boosting, 100 estimators, num_leaves=63)

### Benchmark Scorecard

| Model Architecture | Accuracy | Macro F1 | Weighted F1 | Macro Precision | Macro Recall | FPR | FNR | Inference Latency | Training Time | File Size |
|---|---|---|---|---|---|---|---|---|---|---|
| **Baseline RF (Synthetic-Trained)** | 0.5952 | 0.4088 | 0.5177 | 0.4205 | 0.5536 | 0.1402 | 0.6982 | 0.001 ms/sample | Pretrained | 1.09 MB |
| **Big Data Random Forest** | 0.9829 | 0.9268 | 0.9827 | 0.9528 | 0.9074 | **0.0094** | 0.0291 | 0.002 ms/sample | 9.60 s | 2.84 MB |
| **Big Data XGBoost (WINNER)** | **0.9838** | **0.9449** | **0.9837** | 0.9511 | **0.9391** | 0.0120 | **0.0218** | **0.001 ms/sample** | 6.34 s | 2.17 MB |
| **Big Data LightGBM** | 0.9832 | 0.9299 | 0.9832 | 0.9238 | 0.9367 | 0.0120 | 0.0227 | 0.004 ms/sample | **4.63 s** | 1.18 MB |

---

## 2. Key Findings & Critical Vulnerability Analysis

### 2.1 The Baseline Failure Phenomenon
The existing baseline model was trained on a small, idealized synthetic flow distribution. When confronted with real-world network packet captures from UNSW-NB15, CIC-IDS2017, CSE-CIC-IDS2018, and CIC-DDoS2019:
- **Catastrophic False Negative Rate (69.82%):** Nearly 70% of real-world attacks were misclassified as `BENIGN` or routed incorrectly.
- **Traffic Spike Detection Breakdown:** F1-score for `TRAFFIC_SPIKE` collapsed to **0.0224** with a recall of only **1.17%** (missing 30,805 out of 31,171 volumetric attack flows).
- **High False Positive Rate (14.02%):** More than 14% of legitimate enterprise flows were flagged as malicious, leading to severe alert fatigue and false firewall blocks.

### 2.2 Superiority of Big Data Gradient Boosting
- **XGBoost achieved the highest Macro F1 (0.9449)**, providing exceptional sensitivity to minority attack classes (`SUSPICIOUS_TRANSFER` F1=0.7677, compared to 0.0111 on the baseline).
- **XGBoost minimized FNR to 2.18%**, catching over 97.8% of all intrusion attempts across all four benchmark sources.
- **Random Forest achieved the lowest False Positive Rate (0.94%)**, but sacrificed minority class recall on subtle file transfers.

---

## 3. Per-Class Performance Scorecard

### 3.1 Big Data XGBoost (Candidate Winner)
- **Overall Accuracy:** 98.38% | **Macro F1:** 0.9449

| Class Name | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| `BENIGN` | 0.9877 | 0.9880 | 0.9879 | 63,928 |
| `PORT_SCAN` | 0.9941 | 0.9896 | 0.9919 | 2,890 |
| `BRUTE_FORCE` | **1.0000** | **1.0000** | **1.0000** | 1,526 |
| `TRAFFIC_SPIKE` | 0.9766 | 0.9774 | 0.9770 | 31,171 |
| `SUSPICIOUS_TRANSFER` | 0.7969 | 0.7407 | **0.7677** | 482 |

### 3.2 Big Data Random Forest
- **Overall Accuracy:** 98.29% | **Macro F1:** 0.9268

| Class Name | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| `BENIGN` | 0.9837 | 0.9906 | 0.9872 | 63,928 |
| `PORT_SCAN` | 0.9976 | 0.9879 | 0.9927 | 2,890 |
| `BRUTE_FORCE` | 1.0000 | 0.9993 | 0.9997 | 1,526 |
| `TRAFFIC_SPIKE` | 0.9810 | 0.9718 | 0.9764 | 31,171 |
| `SUSPICIOUS_TRANSFER` | 0.8017 | 0.5871 | 0.6778 | 482 |

### 3.3 Big Data LightGBM
- **Overall Accuracy:** 98.32% | **Macro F1:** 0.9299

| Class Name | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| `BENIGN` | 0.9872 | 0.9880 | 0.9876 | 63,928 |
| `PORT_SCAN` | 0.9941 | 0.9903 | 0.9922 | 2,890 |
| `BRUTE_FORCE` | 1.0000 | 0.9993 | 0.9997 | 1,526 |
| `TRAFFIC_SPIKE` | 0.9786 | 0.9757 | 0.9771 | 31,171 |
| `SUSPICIOUS_TRANSFER` | 0.6592 | 0.7303 | 0.6929 | 482 |

---

## 4. Confusion Matrices (5x5 Multiclass)

### 4.1 Big Data XGBoost Confusion Matrix
- **Classes:** `[BENIGN, PORT_SCAN, BRUTE_FORCE, TRAFFIC_SPIKE, SUSPICIOUS_TRANSFER]`

$$\begin{pmatrix}
63164 & 1 & 0 & 723 & 40 \\
7 & 2860 & 0 & 1 & 22 \\
0 & 0 & 1526 & 0 & 0 \\
671 & 4 & 0 & 30467 & 29 \\
107 & 12 & 0 & 6 & 357
\end{pmatrix}$$

- **Key Observations:**
  - `BRUTE_FORCE`: Zero false negatives, zero false positives across 1,526 test flows.
  - `BENIGN`: 63,164 out of 63,928 accurately recognized (98.80% true benign rate).
  - `SUSPICIOUS_TRANSFER`: 357 out of 482 detected accurately, with errors predominantly shifting to benign rather than critical alarms.

---

## 5. Inference Latency & System Throughput Benchmark

- **Single Flow Latency:**
  - XGBoost: **0.001 ms** per flow ($1.0 \mu\text{s}$)
  - Random Forest: **0.002 ms** per flow ($2.0 \mu\text{s}$)
  - LightGBM: **0.004 ms** per flow ($4.0 \mu\text{s}$)
- **Batch Processing Rate:**
  - In batch mode, Big Data XGBoost achieved throughput exceeding **950,000 flows per second** on 16 CPU threads, comfortably exceeding 10 Gbps and 40 Gbps hybrid-cloud traffic monitoring thresholds.

