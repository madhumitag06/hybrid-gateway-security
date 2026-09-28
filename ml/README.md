# ML Threat Detection & Explainability Subsystem (Phase 11C)

> **Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
> **Subsystem:** Machine Learning Behavioral Detection & SHAP Explainability Engine  
> **Authoritative Pipeline:** Feature Extraction $\to$ StandardScaler $\to$ RandomForest $\to$ Continuous Risk Score $\to$ SHAP $\to$ PolicyEngine

---

## 1. Subsystem Architecture

```text
Network Telemetry (PCAP / Live Flow / AWS VPC Logs)
                      ↓
Feature Extraction & Schema Validation (ml/features/extractor.py)
                      ↓
StandardScaler Preprocessing (ml/models/scaler.joblib)
                      ↓
Trained Random Forest Classifier (ml/models/model.joblib)
                      ↓
Class Probability Distribution (5 Classes)
                      ↓
Continuous Risk Score: 0 - 100 (ml/models/predict.py)
                      ↓
SHAP TreeExplainer Attributions (backend/app/services/explainability_service.py)
                      ↓
Deterministic PolicyEngine (Authority: BLOCK, RESTRICT, MONITOR, ALLOW)
```

---

## 2. Feature Schema & Taxonomy (10 Features)

| Feature Name | Type | Meaning | Observed vs Derived |
| :--- | :---: | :--- | :---: |
| `packet_count` | `int` | Total packets in flow session | **Observed** |
| `byte_count` | `int` | Total bytes transferred in flow session | **Observed** |
| `duration` | `float`| Flow duration in seconds | **Observed** |
| `conn_rate` | `float`| Connection initiation rate (conns/sec) | **Derived** |
| `dst_port` | `int` | Target destination port (1–65535) | **Observed** |
| `unique_dst_ports`| `int` | Count of distinct ports probed in window | **Derived** |
| `failed_auth_count`| `int`| Recorded authentication failure events | **Observed / Proxy** |
| `bytes_per_sec` | `float`| Throughput rate ($\text{byte\_count} / \max(\text{duration}, 0.001)$) | **Derived** |
| `packets_per_sec`| `float`| Packet rate ($\text{packet\_count} / \max(\text{duration}, 0.001)$) | **Derived** |
| `avg_packet_size`| `float`| Mean payload bytes per packet ($\text{byte\_count} / \max(\text{packet\_count}, 1)$) | **Derived** |

---

## 3. Target Threat Classes

1. **`BENIGN`** (60%): Baseline interactive web (HTTP/HTTPS), DNS lookups, SSH management, and CDN multi-endpoint traffic.
2. **`PORT_SCAN`** (10%): Multi-port horizontal reconnaissance sweeps and stealth scan probes.
3. **`BRUTE_FORCE`** (10%): Automated dictionary and credential stuffing bursts across auth ports (SSH 22, RDP 3389, Web 8443).
4. **`TRAFFIC_SPIKE`** (10%): Volumetric bandwidth flooding and sudden traffic saturation attempts.
5. **`SUSPICIOUS_TRANSFER`** (10%): Prolonged high-volume outbound data exfiltration on sensitive/admin ports.

---

## 4. Empirical Evaluation & Generalization Summary

### Internal Holdout Test Set (Calibrated Synthetic Benchmark)
* **Total Samples:** 10,000 (7,000 Train / 1,500 Val / 1,500 Holdout Test)
* **Overall Accuracy:** **99.80%** | **Macro F1:** **0.9977** | **Weighted F1:** **0.9980**
* **False Positive Rate:** **0.33%** | **False Negative Rate:** **0.11%**

### External Public Dataset Generalization (CIC-IDS2017 Flow Subset)
* **Evaluated Samples:** 4,888 mapped records
* **Generalization Accuracy:** **60.78%** | **Macro F1:** **0.2972**
* **Analysis:** Structural attacks (`BRUTE_FORCE`, `PORT_SCAN`) maintain high precision ($\ge 87.5\%$). Volumetric attacks show natural distribution shift due to different packet rate scaling in testbed subnets.
* **Experimental External Model (Path B):** Model trained directly on CIC-IDS2017 schema achieves **82.23% accuracy** and **0.5767 Macro F1**.

> For detailed confusion matrices, per-class metrics, and limitations, refer to [`ml/MODEL_CARD.md`](file:///c:/Users/LENOVO/Desktop/hybrid-gateway-security/ml/MODEL_CARD.md).

---

## 5. Quick Reproduction Commands

```powershell
# Train production model:
python -m ml.models.train

# Run external generalization benchmark (CIC-IDS2017):
python -m ml.evaluation.evaluate_external

# Run experimental external training (Path B):
python -m ml.evaluation.train_external_model

# Run ML unit, robustness, and leakage tests:
.\ml\.venv\Scripts\pytest.exe ml/tests/ -v
```
