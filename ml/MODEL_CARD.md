# Model Card: Network Flow Threat Classifier (Phase 11C)

## 1. Model Details
* **Model Type:** `RandomForestClassifier` (Scikit-Learn)
* **Hyperparameters:** `n_estimators=100`, `max_depth=12`, `min_samples_split=5`, `min_samples_leaf=2`, `random_state=42`
* **Version:** Phase 11C (Production Release)
* **Framework Version:** scikit-learn $\ge$ 1.3.0, joblib $\ge$ 1.3.0, shap $\ge$ 0.44.0
* **Input Schema:** 10 continuous and discrete network flow features
* **Output:** 5-class probability distribution + predicted threat class + continuous risk score (0–100) + SHAP feature attributions

---

## 2. Intended Purpose & System Role
The model provides fast, low-latency, statistical multi-class network flow classification for hybrid cloud gateway telemetry (on-premise NetFlow, PCAP captures, and AWS VPC Flow Logs).

### Authoritative Security Boundary:
```text
Network Flow Input
       ↓
Feature Extraction (10 features)
       ↓
StandardScaler Preprocessing
       ↓
RandomForest Inference (Class Probabilities & Anomaly Detection)
       ↓
Risk Score Calculation (0 - 100)
       ↓
SHAP TreeExplainer (Feature Contributions)
       ↓
Deterministic PolicyEngine (Authority: BLOCK, RESTRICT, MONITOR, ALLOW)
       ↓
Enforcement Adapter (Active Firewall / iptables / AWS Security Groups)
       ↓
Optional LLM Copilot (Advisory Analysis ONLY, Zero Enforcement Authority)
```

---

## 3. Training & Validation Datasets

### A. Production Model (Trained on Calibrated Network Flow Benchmark)
* **Source:** Reproducible, calibrated statistical flow distributions grounded in CIC-IDS2017 & UNSW-NB15 flow characteristics.
* **Sample Count:** 10,000 samples (70% Train: 7,000, 15% Validation: 1,500, 15% Holdout Test: 1,500).
* **Holdout Test Accuracy:** 99.80% | **Macro F1:** 0.9977 | **Weighted F1:** 0.9980.

### B. External Benchmark Evaluation (CIC-IDS2017 Public Schema)
* **Source:** Public network intrusion benchmark dataset (CIC-IDS2017 flow subset).
* **Sample Count:** 4,888 mapped samples.
* **External Generalization Accuracy:** 60.78% | **Macro F1:** 0.2972 (Distribution shift observed without external retraining).
* **Experimental External-Trained Model Accuracy:** 82.23% | **Macro F1:** 0.5767.

---

## 4. Input Features & Taxonomy

| Feature | Type | Meaning | Importance |
| :--- | :--- | :--- | :---: |
| `conn_rate` | Derived | Connection frequency per temporal window | 24.60% |
| `avg_packet_size` | Derived | Average payload bytes per packet (`byte_count / packet_count`) | 16.01% |
| `byte_count` | Observed | Total bytes transferred in flow session | 14.28% |
| `failed_auth_count` | Observed/Proxy | Repeated authentication failure events | 13.30% |
| `packet_count` | Observed | Total packets in flow session | 9.67% |
| `duration` | Observed | Flow session duration in seconds | 7.46% |
| `dst_port` | Observed | Target destination port | 5.11% |
| `unique_dst_ports` | Derived | Number of distinct destination ports probed | 4.47% |
| `bytes_per_sec` | Derived | Data throughput rate (`byte_count / duration`) | 2.69% |
| `packets_per_sec` | Derived | Packet transmission rate (`packet_count / duration`) | 2.42% |

---

## 5. Target Classes

1. `BENIGN`: Normal interactive web (HTTP/HTTPS), DNS, SSH, database queries, and CDN traffic.
2. `PORT_SCAN`: Multi-port reconnaissance probes and horizontal port sweeps.
3. `BRUTE_FORCE`: Automated credential guessing bursts on auth endpoints (SSH, RDP, Web).
4. `TRAFFIC_SPIKE`: Volumetric bandwidth flooding and sudden traffic saturation attempts.
5. `SUSPICIOUS_TRANSFER`: Prolonged high-volume outbound data transfers on non-standard/sensitive ports.

---

## 6. Limitations & Known Dataset Shift

1. **Layer 4 vs Layer 7 Scope:** The model operates exclusively on L4 flow telemetry (headers, counts, durations, rates). It does not perform Deep Packet Inspection (DPI) or L7 payload regex matching (e.g. SQLi, XSS).
2. **Dataset Distribution Shift:** When evaluating models across disparate network topologies (e.g. synthetic vs university testbed captures), differences in background traffic rate scaling cause baseline shifts in volumetric classes.
3. **Authentication Field in Generic NetFlow:** `failed_auth_count` is unavailable in raw Layer 4 NetFlow headers and defaults to 0 unless enriched by authentication log correlation.
4. **Advisory Role of LLM:** The LLM Copilot is an explanatory and advisory component with zero authority over ML predictions or firewall rule execution.
