# ML Anomaly & Threat Detection Subsystem (Phase 1)

> **Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
> **Subsystem:** Machine Learning Behavioral Detection Pipeline  
> **Phase:** 1 — Real ML Detection Subsystem

---

## 1. Framing & Academic Context

This module implements a **prototype behavioral anomaly detection pipeline** using a **reproducible synthetic network-flow dataset designed to represent controlled normal and anomalous patterns**. 

### Academic Disclaimer
This pipeline is an engineering prototype for academic research and testing within a hybrid cloud security gateway architecture. It does not claim to replace enterprise IDS/IPS solutions (e.g., Palo Alto, Fortinet, AWS GuardDuty), nor does synthetic data represent all variations of real-world advanced persistent threats (APTs).

---

## 2. Architecture & Pipeline Overview

```text
Synthetic Network Traffic Generator (ml/data/generator.py)
                     ↓
Feature Extraction & Schema Validation (ml/features/extractor.py)
                     ↓
StandardScaler Preprocessing (ml/models/scaler.joblib)
                     ↓
Trained Random Forest Classifier (ml/models/model.joblib)
                     ↓
Class Probability Estimates
                     ↓
Continuous Risk Score & Action Engine (ml/models/predict.py)
                     ↓
Structured Detection Output (JSON)
```

---

## 3. Dataset & Attack Classes

The dataset generator (`ml/data/generator.py`) generates seed-controlled network flows with parameterized statistical distributions across 5 distinct classes:

| Class Name | Target Share | Behavioral Signature | Target Services |
| :--- | :---: | :--- | :--- |
| **`BENIGN`** | 60% | Normal packet/byte volumes, baseline connection rates, 0 failed authentications. | HTTP (80), HTTPS (443), DNS (53), SSH (22) |
| **`PORT_SCAN`** | 10% | High connection rates, probing across numerous unique destination ports, minimal byte footprint. | Ephemeral & Random (1–65535) |
| **`BRUTE_FORCE`** | 10% | Concentrated bursts of connection attempts with elevated authentication failures (`failed_auth_count` $\ge 3$). | SSH (22), Admin (8443), RDP (3389) |
| **`TRAFFIC_SPIKE`** | 10% | Saturation floods with high packet counts and extreme throughput (`bytes_per_sec`). | Web (80, 443), DNS (53) |
| **`SUSPICIOUS_TRANSFER`** | 10% | Large data payloads with high average packet sizes over prolonged durations on non-standard ports. | Custom/Admin (8443, 9000, 4444) |

---

## 4. Feature Set

Ten numerical flow features are extracted and normalized for each network interaction:

1. `packet_count` (`int`): Total packets transferred during the flow window.
2. `byte_count` (`int`): Total payload bytes transferred.
3. `duration` (`float`): Active connection duration in seconds.
4. `conn_rate` (`float`): Connection initiation frequency (connections/sec).
5. `dst_port` (`int`): Target destination port (1–65535).
6. `unique_dst_ports` (`int`): Count of distinct ports targeted in the observation window.
7. `failed_auth_count` (`int`): Count of recorded authentication failures.
8. `bytes_per_sec` (`float`): Flow throughput metric ($\text{byte\_count} / \max(\text{duration}, 0.001)$).
9. `packets_per_sec` (`float`): Packet rate ($\text{packet\_count} / \max(\text{duration}, 0.001)$).
10. `avg_packet_size` (`float`): Mean bytes per packet ($\text{byte\_count} / \max(\text{packet\_count}, 1)$).

---

## 5. Model Selection & Training Methodology

### Model: `RandomForestClassifier`
* **Ensemble Parameters:** `n_estimators=100`, `max_depth=12`, `min_samples_split=5`, `min_samples_leaf=2`, `random_state=42`.
* **Rationale:** Random Forest handles non-linear multi-class boundaries across heterogeneous tabular distributions, resists noise, computes class probability estimates, and outputs feature importances for transparency.
* **Leakage Prevention:** Dataset is split into Stratified Train (70%), Validation (15%), and Test (15%). `StandardScaler` is fitted *strictly* on the training split and serialized for inference.

---

## 6. Risk Scoring & Policy Action Engine

The continuous Risk Score ($R \in [0, 100]$) is derived mathematically from the model's actual class probability estimates:

1. **Anomaly Probability:**
   $$P_{\text{anomaly}} = \sum_{c \neq \text{BENIGN}} P(\text{class} = c) = 1.0 - P(\text{class} = \text{BENIGN})$$

2. **Continuous Score Calculation:**
   * If predicted class is `BENIGN`:
     $$R = \text{round}\Big( P_{\text{anomaly}} \times 39.0 \Big)$$
   * If predicted class is anomalous:
     $$R = \text{round}\Big( 40.0 + (P_{\text{anomaly}} \times 60.0) \Big)$$
   * Clamped to $[0, 100]$.

3. **Tier & Policy Action Mapping:**
   * **`0 – 39`** $\rightarrow$ **`LOW`** Severity | Recommended Action: **`Allow`**
   * **`40 – 69`** $\rightarrow$ **`MEDIUM`** Severity | Recommended Action: **`Monitor`**
   * **`70 – 100`** $\rightarrow$ **`HIGH`** Severity | Recommended Action: **`Restrict`** (or **`Block`** if $R \ge 85$ or high-confidence brute-force)

4. **Root-Cause Anomaly Explanation:**
   Calculates the feature's $z$-score distance against the learned benign baseline ($z = \frac{x - \mu_{\text{benign}}}{\sigma_{\text{benign}}}$) to pinpoint which feature caused the alert.

---

## 7. How to Run Training, Inference & Tests

### Setup Environment
```bash
# Create dedicated virtual environment
python -m venv ml/.venv

# Activate virtual environment
# Windows PowerShell:
.\ml\.venv\Scripts\Activate.ps1
# Linux / macOS:
# source ml/.venv/bin/activate

# Install dependencies
pip install -r ml/requirements.txt
```

### Train Model & Generate Artifacts
```bash
python -m ml.models.train
```

### Run Inference Module Standalone
```bash
python -m ml.models.predict
```

### Run Test Suite
```bash
python -m pytest ml/tests/test_inference.py -v
```

---

## 8. Phase 2 FastAPI Integration Plan

In Phase 2, this ML subsystem connects directly to the FastAPI gateway without refactoring:

```python
# Phase 2 FastAPI route preview
from fastapi import FastAPI, Depends
from ml.models.predict import ThreatPredictor, PredictionOutput
from ml.features.extractor import NetworkFlowInput

app = FastAPI()
predictor = ThreatPredictor()

@app.post("/api/v1/predict", response_model=PredictionOutput)
async def predict_traffic(flow: NetworkFlowInput):
    return predictor.predict_flow(flow)
```

---

## 9. Limitations & Future Scope

1. **Synthetic Data Boundaries:** While realistic distributions with Gaussian variance are used, real enterprise traffic exhibits complex protocol variations and encrypted payload behaviors.
2. **Tabular Features:** Operates on aggregated flow metrics rather than deep packet payload inspection (DPI).
3. **Phase Exclusions:** Phase 1 explicitly excludes live network sniffing (eBPF/pcap), firewall blocking, database logging, and frontend REST endpoints, which are scheduled for subsequent vertical phases.
