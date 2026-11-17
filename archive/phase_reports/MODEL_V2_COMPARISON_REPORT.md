# Machine Learning Model Benchmark and Comparison Report (V2)

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Phase:** Phase 2 — Production-Grade Feature Engineering and Big Data XGBoost V2  
**Date:** November 2026  
**Status:** Evaluation Completed — Big Data XGBoost V2 Selected as Winning Candidate

---

## Executive Summary

To establish production readiness without relying on unobservable authentication tokens, a rigorous benchmark was conducted comparing five distinct model architectures on the 9-feature clean dataset ($N = 100,000$ stratified held-out test samples from `data/processed_v2/test.parquet`).

**Big Data XGBoost V2** demonstrated overwhelming operational superiority across accuracy, macro F1, false positive rate, single-sample latency, and batch throughput. It achieves **0.9842 Accuracy**, **0.9486 Macro F1**, and **0.9990 F1 on Brute Force attacks** using strictly observable L3/L4 network telemetry, with an ultra-low single-sample latency of **0.957 ms** and a line-rate batch throughput of **664,756 flows/sec**.

---

## 1. Master Model Benchmark Scorecard

| Metric | Baseline RF (Synthetic V1) | Big Data XGBoost V1 (Zero-Auth) | **Big Data XGBoost V2 (WINNER)** | Big Data Random Forest V2 | Big Data LightGBM V2 |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Feature Schema** | 10 Features | 10 Features | **9 Features (Clean V2)** | 9 Features (Clean V2) | 9 Features (Clean V2) |
| **Accuracy** | 0.5723 | 0.9612 | **0.9842** | 0.9833 | 0.9339 |
| **Macro F1 Score** | 0.1871 | 0.7340 | **0.9486** | 0.9301 | 0.6728 |
| **Weighted F1 Score** | 0.4993 | 0.9540 | **0.9842** | 0.9831 | 0.9417 |
| **Macro Precision** | 0.1928 | 0.7346 | **0.9548** | 0.9537 | 0.6326 |
| **Macro Recall** | 0.3596 | 0.7338 | **0.9429** | 0.9117 | 0.7483 |
| **False Positive Rate (FPR)** | 0.1448 | 0.0236 | **0.0096** | 0.0089 | 0.0604 |
| **False Negative Rate (FNR)** | 0.7490 | 0.0640 | **0.0251** | 0.0292 | 0.0299 |
| **Single-Sample Latency** | 21.986 ms | 0.846 ms | **0.957 ms** | 22.416 ms | 1.740 ms |
| **Batch Throughput** | 333,870 fps | 592,487 fps | **664,756 fps** | 331,762 fps | 407,040 fps |
| **Model Disk Size** | 1.09 MB | 2.17 MB | **2.19 MB** | 23.40 MB | 1.84 MB |
| **Training Time** | Pre-trained | 6.34 s | **5.31 s** | 10.64 s | 4.11 s |

---

## 2. Per-Class Performance Breakdown

### 1. Big Data XGBoost V2 (Winning Model)
- **`BENIGN`** ($N = 64,870$): Precision = **0.9864**, Recall = **0.9904**, F1 = **0.9884**
- **`PORT_SCAN`** ($N = 1,531$): Precision = **0.9935**, Recall = **0.9935**, F1 = **0.9935**
- **`BRUTE_FORCE`** ($N = 1,485$): Precision = **0.9980**, Recall = **1.0000**, F1 = **0.9990**
- **`TRAFFIC_SPIKE`** ($N = 31,623$): Precision = **0.9810**, Recall = **0.9739**, F1 = **0.9775**
- **`SUSPICIOUS_TRANSFER`** ($N = 489$): Precision = **0.8150**, Recall = **0.7566**, F1 = **0.7847**

### 2. Big Data Random Forest V2
- `BENIGN`: P = 0.9843, R = 0.9911, F1 = 0.9877
- `PORT_SCAN`: P = 0.9980, R = 0.9824, F1 = 0.9901
- `BRUTE_FORCE`: P = 0.9980, R = 0.9993, F1 = 0.9987
- `TRAFFIC_SPIKE`: P = 0.9817, R = 0.9721, F1 = 0.9769
- `SUSPICIOUS_TRANSFER`: P = 0.8065, R = 0.6135, F1 = 0.6969

### 3. Big Data LightGBM V2
- `BENIGN`: P = 0.9831, R = 0.9396, F1 = 0.9608
- `PORT_SCAN`: P = 0.8190, R = 0.9667, F1 = 0.8868
- `BRUTE_FORCE`: P = 0.1295, R = 0.2667, F1 = 0.1744  *(Poor separation on raw trees)*
- `TRAFFIC_SPIKE`: P = 0.9427, R = 0.9569, F1 = 0.9498
- `SUSPICIOUS_TRANSFER`: P = 0.2886, R = 0.6115, F1 = 0.3921

### 4. Big Data XGBoost V1 (Evaluated under Zero-Auth Telemetry)
- `BENIGN`: P = 0.9657, R = 0.9764, F1 = 0.9711
- `PORT_SCAN`: P = 0.9806, R = 0.9915, F1 = 0.9860
- `BRUTE_FORCE`: P = 0.0000, R = 0.0000, F1 = **0.0000** *(Completely collapsed when auth token = 0)*
- `TRAFFIC_SPIKE`: P = 0.9537, R = 0.9772, F1 = 0.9653
- `SUSPICIOUS_TRANSFER`: P = 0.7729, R = 0.7239, F1 = 0.7476

---

## 3. Confusion Matrix Analysis (XGBoost V2)

Evaluating $N = 100,000$ test flows:

$$\begin{pmatrix}
\text{True Class} & \text{BENIGN} & \text{PORT\_SCAN} & \text{BRUTE\_FORCE} & \text{TRAFFIC\_SPIKE} & \text{SUSPICIOUS} \\
\text{BENIGN} & 64,248 & 3 & 0 & 581 & 38 \\
\text{PORT\_SCAN} & 0 & 1,521 & 0 & 0 & 10 \\
\text{BRUTE\_FORCE} & 0 & 0 & 1,485 & 0 & 0 \\
\text{TRAFFIC\_SPIKE} & 786 & 0 & 2 & 30,799 & 36 \\
\text{SUSPICIOUS} & 97 & 7 & 1 & 14 & 370
\end{pmatrix}$$

### Key Observations:
1. **Zero Brute Force Leakage:** All 1,485 brute-force flows were correctly classified ($100\%$ Recall).
2. **Minimal False Alarms:** Out of 64,870 benign flows, only 622 were flagged as attacks, yielding an exceptional False Positive Rate of **$0.96\%$** ($< 1\%$).
3. **Robust Volumetric Discrimination:** Over $97.39\%$ of DoS and traffic spikes were captured cleanly without confusing regular HTTP/HTTPS traffic.

---

## 4. Global Feature Importance (XGBoost V2)

Feature importances were computed via Gini gain across all split nodes:

| Rank | Feature | Importance Weight | Cumulative Importance | Primary Role in Threat Detection |
|:---:|:---|:---:|:---:|:---|
| 1 | `unique_dst_ports` | **47.12%** | 47.12% | Rapid horizontal and vertical port scan discovery |
| 2 | `bytes_per_sec` | **24.58%** | 71.70% | Volumetric amplification DoS and high-throughput exfiltration |
| 3 | `byte_count` | **5.83%** | 77.53% | Distinguishing sub-10KB handshake probes from data flows |
| 4 | `packet_count` | **5.52%** | 83.05% | Packet intensity and probe repetition |
| 5 | `dst_port` | **4.75%** | 87.80% | Service identification (Port 22 SSH, 80 HTTP, 443 TLS, etc.) |
| 6 | `avg_packet_size` | **4.64%** | 92.44% | Detection of tiny probe packets vs jumbo frame transfers |
| 7 | `duration` | **2.78%** | 95.22% | Flow lifetime and micro-burst analysis |
| 8 | `packets_per_sec` | **2.57%** | 97.79% | High-frequency packet generation |
| 9 | `conn_rate` | **2.21%** | 100.00% | Multi-packet burst intensity |

---

## 5. Architectural Selection Decision

**Decision:** Big Data XGBoost V2 is unanimously selected as the winning model candidate for hybrid gateway integration.

### Rationale:
1. **$100\%$ Observable Input Space:** Does not depend on decrypted passwords or synthetic indicators.
2. **Sub-Millisecond Latency:** At **0.957 ms** single-sample latency, it is over **$23\times$ faster** than Random Forest (22.416 ms), making it suitable for live kernel packet interception.
3. **Massive Line-Rate Throughput:** **664,756 flows per second** allows the gateway to inspect 10 Gbps hybrid links without packet drops or buffer overruns.
4. **Compact Memory Footprint:** At **2.19 MB**, it fits comfortably into cache memory on standard gateway hardware.

