# XGBoost V2 AWS Telemetry Integration & Parity Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Primary Authoritative Model:** Big Data XGBoost V2 (`candidate_xgboost_v2`)  
**Standby Rollback Model:** Random Forest Baseline (`production_rf`)  
**Inference Context:** AWS VPC Flow Logs Streaming Telemetry  
**Target AWS Account:** 698766075180 (ap-southeast-2)  
**Date:** November 15, 2026  
**Status:** VALIDATED & COMPLIANT  

---

## 1. Executive Summary

This report certifies the machine learning normalization and inference pipeline connecting live AWS VPC Flow Logs telemetry to the authoritative Big Data XGBoost V2 model. 

Every ingested flow record from Amazon CloudWatch Logs is normalized into the canonical 9-feature representation, evaluated for threat category and calibrated risk score, assigned an adaptive policy action, and persisted to the PostgreSQL security event store without modifying production AWS infrastructure or Windows host firewall rules.

---

## 2. Canonical 9-Feature Normalization Engine

In Phase 1 / Phase 2, the gateway established the canonical 9-feature schema for high-throughput cloud network flows, eliminating legacy host-centric variables (`su_attempted`, `num_file_creations`, `num_shells`, `is_host_login`) that do not exist in layer-3/4 VPC flow records.

### 2.1 Canonical Feature Mapping

| # | Feature Name | Source in AWS VPC Flow Log v2 | Data Type | Transformation Logic |
|---|---|---|---|---|
| 1 | `duration` | `start`, `end` | Float | $\max(\text{end} - \text{start}, 0.001)$ seconds |
| 2 | `src_bytes` | `bytes` | Float | Extracted directly from flow byte count; split for bi-directional flows |
| 3 | `dst_bytes` | `bytes` | Float | Calculated return bytes or derived from bidirectional stream pairing |
| 4 | `wrong_fragment` | Derived | Float | Hardcoded to `0.0` (L4 flow logs do not segment raw IP fragments) |
| 5 | `urgent` | Derived | Float | Hardcoded to `0.0` (TCP URG pointer not captured in v2 flow logs) |
| 6 | `hot` | Derived | Float | Hardcoded to `0.0` (indicates sensitive directory access in packet data) |
| 7 | `num_failed_logins` | `action` | Float | `1.0` if `action == "REJECT"`, else `0.0` (zero synthetic auth noise) |
| 8 | `num_compromised` | Derived | Float | Hardcoded to `0.0` |
| 9 | `count` | `packets` | Float | Flow packet count or windowed connection aggregation count |

### 2.2 Mathematical Parity & Zero Synthetic Distortion Guarantee
Prior iterations of cloud telemetry normalization occasionally introduced synthetic authentication attempts to simulate brute-force attacks. In this integration:
- **Zero Synthetic Injection:** No random or hardcoded authentication failures are added.
- **Strict Provenance:** `num_failed_logins` is derived solely from AWS Security Group or Network ACL `REJECT` actions recorded by AWS VPC Flow Logs.
- **Exact Parity:** Passing a canonical record through `ml.features.extractor.extract_features_v2()` produces an identical feature vector ($1 \times 9$) matching the Big Data XGBoost V2 model training schema.

---

## 3. Authoritative XGBoost V2 Inference Architecture

### 3.1 Model Registry State

```
+---------------------------------------------------------------------------------+
|                                 Model Registry                                  |
|                                                                                 |
|  [AUTHORITATIVE PRIMARY]                                                        |
|  Model ID: candidate_xgboost_v2                                                 |
|  Algorithm: XGBoost Classifier (Native C++ Runtime 3.4.1)                       |
|  Feature Dimension: 9 Canonical Features                                        |
|  Classes: BENIGN, DOS, PROBE, R2L, U2R                                          |
|  Enforcement Authority: ACTIVE PRIMARY                                          |
|  Decision Threshold: 0.50 (Calibrated Class Probabilities)                     |
|                                                                                 |
|  [STANDBY ROLLBACK]                                                             |
|  Model ID: production_rf                                                        |
|  Algorithm: Random Forest Classifier (scikit-learn)                             |
|  Feature Dimension: 10 Features                                                 |
|  Enforcement Authority: STANDBY (Ready for zero-downtime hot-swap)              |
+---------------------------------------------------------------------------------+
```

### 3.2 Calibrated Risk Scoring
The model computes class probability distributions:
$$P = [p_{\text{BENIGN}}, p_{\text{DOS}}, p_{\text{PROBE}}, p_{\text{R2L}}, p_{\text{U2R}}]$$

Risk scores are computed using severity-weighted calibrated scaling:
$$\text{Risk Score} = \min\left(100.0,\; \sum_{c \in \text{threats}} w_c \cdot p_c \times 100.0\right)$$
where $w_{\text{U2R}} = 1.0$, $w_{\text{R2L}} = 0.9$, $w_{\text{DOS}} = 0.8$, and $w_{\text{PROBE}} = 0.7$.

### 3.3 Adaptive Policy Action Matrix

| Risk Score Range | Predicted Class | Recommended Policy Action | Gateway Behavior |
|---|---|---|---|
| $0.0 \le \text{Risk} < 30.0$ | BENIGN | `ALLOW` | Flow permitted; counters incremented |
| $30.0 \le \text{Risk} < 60.0$ | BENIGN / Low PROBE | `MONITOR` | Flow permitted; enhanced metrics collected |
| $60.0 \le \text{Risk} < 80.0$ | PROBE / DOS | `ALERT` | Security event persisted; dashboard notification |
| $80.0 \le \text{Risk} \le 100.0$ | DOS / R2L / U2R | `QUARANTINE` | Event persisted; in-memory containment rule generated with TTL |

---

## 4. Test Verification Suite Evidence

The integration suite was executed against real XGBoost V2 artifacts:

```
backend/tests/test_aws_flow_logs_pipeline.py::test_xgboost_v2_feature_normalization_parity PASSED [0.03s]
backend/tests/test_aws_flow_logs_pipeline.py::test_xgboost_v2_inference_and_event_persistence PASSED [0.28s]
backend/tests/test_predict_api.py::test_predict_api_with_xgboost_v2 PASSED [0.12s]
backend/tests/test_predict_api.py::test_predict_duration_consistency PASSED [0.08s]
```

### Verified Test Assertions:
1. Canonical vectors contain exactly 9 feature keys in identical alphabetical order:
   `['count', 'dst_bytes', 'duration', 'hot', 'num_compromised', 'num_failed_logins', 'src_bytes', 'urgent', 'wrong_fragment']`.
2. XGBoost native inference executes in under 2.5 ms per batch.
3. Every predicted flow contains a non-null `attack_type`, calibrated `risk_score` $\in [0.0, 100.0]$, and an authorized `policy_action` $\in \{\text{ALLOW}, \text{MONITOR}, \text{ALERT}, \text{QUARANTINE}\}$.
4. High-risk flows ($\text{risk} \ge 70$) are persisted to `security_events` with matching provenance data (`account_id="698766075180"`, `provider="AWS"`).
