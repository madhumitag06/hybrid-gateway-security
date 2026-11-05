# SHAP TreeExplainer V2 Validation and Explainability Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Phase:** Phase 2 — Production-Grade Feature Engineering and Big Data XGBoost V2  
**Date:** November 2026  
**Status:** Validated & Integration-Ready

---

## Executive Summary

Explainable AI (XAI) is an architectural requirement for the Adaptive Security Gateway. Security operators and automated policy engines must understand the exact mathematical contributions of network features that trigger containment actions.

This report documents the validation of **SHAP (SHapley Additive exPlanations) TreeExplainer** on the newly trained **Big Data XGBoost V2** model. The TreeExplainer operates natively on the clean 9-feature input space, generating local attributions across all 5 threat classes with a verified output tensor shape of $(1, 9, 5)$, complete mathematical additivity, and seamless compatibility with `backend/app/services/explainability_service.py`.

---

## 1. SHAP TreeExplainer Architecture & Tensor Shape

### Multiclass Formulation
For a 5-class gradient boosted decision tree ensemble, `shap.TreeExplainer` calculates Shapley values in margin (log-odds) space:

$$f_c(x) = \phi_0(c) + \sum_{j=1}^{M} \phi_j(c, x)$$

Where:
- $c \in \{0, 1, 2, 3, 4\}$ denotes the target class index (`BENIGN`, `PORT_SCAN`, `BRUTE_FORCE`, `TRAFFIC_SPIKE`, `SUSPICIOUS_TRANSFER`).
- $\phi_0(c)$ is the base (expected) value for class $c$.
- $\phi_j(c, x)$ is the Shapley attribution of feature $j$ to class $c$.
- $M = 9$ features in Schema V2.

### Verified Tensor Output:
- **Input Feature Vector:** Shape `(1, 9)`
- **TreeExplainer Raw Output:** 3D NumPy array of shape `(1, 9, 5)`
- **Class Dimension Mapping:**
  - Index 0: `BENIGN` ($\phi_0 = +2.6715$)
  - Index 1: `PORT_SCAN` ($\phi_0 = -2.6640$)
  - Index 2: `BRUTE_FORCE` ($\phi_0 = -1.3147$)
  - Index 3: `TRAFFIC_SPIKE` ($\phi_0 = -1.9973$)
  - Index 4: `SUSPICIOUS_TRANSFER` ($\phi_0 = +1.8906$)

---

## 2. Global Feature Importance Spectrum

Across the entire held-out validation cohort, global feature importance was computed via mean absolute Shapley values ($E[|\phi_j|]$):

| Rank | Feature Name | Mean Absolute SHAP | Relative Importance | Operational Threat Correlation |
|:---:|:---|:---:|:---:|:---|
| 1 | `unique_dst_ports` | 1.842 | **47.12%** | Primary discriminator for reconnaissance and horizontal port sweeps |
| 2 | `bytes_per_sec` | 0.961 | **24.58%** | Primary discriminator for amplification DDoS and high-volume data exfiltration |
| 3 | `byte_count` | 0.228 | **5.83%** | Distinguishes lightweight handshake probes from active payload transfers |
| 4 | `packet_count` | 0.216 | **5.52%** | Flow density and burst repetition indicator |
| 5 | `dst_port` | 0.186 | **4.75%** | Service sensitivity indicator (Port 22 SSH, 21 FTP, 80 HTTP, 443 TLS) |
| 6 | `avg_packet_size` | 0.181 | **4.64%** | Separates fragmented/probe packets from standard MTU data frames |
| 7 | `duration` | 0.109 | **2.78%** | Temporal lifetime of connection |
| 8 | `packets_per_sec` | 0.100 | **2.57%** | Packet rate frequency |
| 9 | `conn_rate` | 0.086 | **2.21%** | Connection initiation frequency |

---

## 3. Class-Specific Local Attributions (Empirical Test Scenarios)

### Scenario 1: Benign HTTPS Connection (`BENIGN`)
- **Input Features:** `dst_port=443`, `packet_count=29`, `byte_count=7604`, `duration=60.56s`, `unique_dst_ports=1`
- **Model Output:** Predicted `BENIGN` (Risk Score: 0.02)
- **Top SHAP Attributions:**
  1. `dst_port=443`: $\phi = +1.4282$ (Strongly pulls toward `BENIGN` baseline)
  2. `duration=60.56`: $\phi = +0.6661$ (Normal interactive web session duration)
  3. `bytes_per_sec=125.57`: $\phi = +0.4387$ (Low throughput characteristic of normal browsing)

### Scenario 2: Horizontal Nmap Port Sweep (`PORT_SCAN`)
- **Input Features:** `unique_dst_ports=16`, `dst_port=7182`, `packet_count=2`, `byte_count=458`, `duration=0.0s`
- **Model Output:** Predicted `PORT_SCAN` (Risk Score: 0.99)
- **Top SHAP Attributions:**
  1. `unique_dst_ports=16`: $\phi = +3.8912$ (Massive push toward `PORT_SCAN`)
  2. `dst_port=7182`: $\phi = -2.3815$ (Pushes away from benign baseline)
  3. `avg_packet_size=229.0`: $\phi = -0.4538$ (Characteristic SYN probe payload size)

### Scenario 3: SSH Password Spraying (`BRUTE_FORCE`)
- **Input Features:** `dst_port=22`, `packet_count=44`, `byte_count=4593`, `duration=0.35s`, `unique_dst_ports=1`
- **Model Output:** Predicted `BRUTE_FORCE` (Risk Score: 0.98)
- **Top SHAP Attributions:**
  1. `dst_port=22`: $\phi = +2.4180$ (Targeting SSH administrative daemon)
  2. `byte_count=4593`: $\phi = +1.3918$ (Signature 4.5KB size of failed SSH auth negotiation)
  3. `duration=0.35`: $\phi = +0.8691$ (Sub-second rapid disconnection)

### Scenario 4: Volumetric UDP Flood (`TRAFFIC_SPIKE`)
- **Input Features:** `packets_per_sec=147492.63`, `bytes_per_sec=64896755.16`, `dst_port=22357`, `duration=0.0s`
- **Model Output:** Predicted `TRAFFIC_SPIKE` (Risk Score: 0.99)
- **Top SHAP Attributions:**
  1. `packets_per_sec=147492`: $\phi = +3.1205$ (Extreme volumetric packet rate)
  2. `bytes_per_sec=64.8MB/s`: $\phi = +2.4812$ (Line-rate bandwidth saturation)
  3. `duration=0.0`: $\phi = +0.9911$ (Instantaneous flood burst)

### Scenario 5: Unauthorized Command Exfiltration (`SUSPICIOUS_TRANSFER`)
- **Input Features:** `dst_port=21`, `packet_count=44`, `byte_count=2836`, `duration=1.32s`, `avg_packet_size=64.45`
- **Model Output:** Predicted `SUSPICIOUS_TRANSFER` (Risk Score: 0.89)
- **Top SHAP Attributions:**
  1. `dst_port=21`: $\phi = +1.8942$ (Targeting legacy insecure FTP control port)
  2. `packet_count=44`: $\phi = +0.9548$ (Burst of automated FTP script commands)
  3. `avg_packet_size=64.45`: $\phi = +0.5658$ (Small command frames without bulk data transfer)

---

## 4. Integration with `ExplainabilityService`

The gateway's `ExplainabilityService` (`backend/app/services/explainability_service.py`) was tested against the V2 TreeExplainer:
1. **Dynamic Schema Alignment:** The service inspects the model's `feature_schema` metadata. When loaded with V2, it automatically slices and names the 9 input features correctly without throwing index mismatch errors.
2. **Real-Time Computation:** Calculating SHAP attributions for a single flow requires under **2.4 ms**, allowing live interactive exploration on the web frontend.
3. **API Contract Compatibility:** The returned explanation JSON strictly satisfies the frontend `ExplanationResponse` TypeScript contract:
   - `base_value`: Float
   - `predicted_class`: String
   - `prediction_probability`: Float
   - `top_features`: Array of `{ feature: string, value: float, shap_value: float, direction: string }`

