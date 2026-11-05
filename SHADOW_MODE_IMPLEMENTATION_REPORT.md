# Shadow Mode Implementation and Candidate Integration Report (Phase 3)

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Phase:** Phase 3 — Live Hybrid-Cloud Gateway Integration and XGBoost V2 Validation  
**Date:** November 2026  
**Status:** Implemented, Tested & Verified

---

## Executive Summary

To safely evaluate the **Big Data XGBoost V2** candidate model under live hybrid-cloud traffic conditions without risking false containment or disrupting active security enforcement, Phase 3 implements an architectural **SHADOW MODE**.

Under Shadow Mode:
1. The existing production **Random Forest model remains 100% authoritative** for all gateway predictions, continuous risk scoring, and context-aware firewall containment.
2. The candidate **Big Data XGBoost V2 operates strictly in parallel as an advisory observer**, receiving the identical network flow telemetry, performing sub-millisecond inference across the clean 9-feature schema, evaluating local SHAP TreeExplainer attributions, and persisting comparative records into PostgreSQL.
3. The candidate model is **cryptographically and architecturally barred from controlling enforcement**: it cannot create, modify, or revoke router `iptables` rules or change gateway policy states.

---

## 1. Shadow Mode System Architecture

```
                       INCOMING NETWORK TRAFFIC
                   (PCAP / Live Sensor / Socket)
                                 │
                                 ▼
                         FlowAggregator
             (Bidirectional Sessionization & Bounded
               60s Sliding Window HostPortTracker)
                                 │
                                 ▼
                     9-Feature Vector Extraction
               (packet_count, bytes, duration, conn_rate,
                dst_port, unique_ports, B/s, pps, avg_size)
                                 │
                 ┌───────────────┴───────────────┐
                 │                               │
                 ▼                               ▼
       [AUTHORITATIVE PATH]              [SHADOW / ADVISORY PATH]
     Production Random Forest               Candidate XGBoost V2
     (10-feature V1 Pipeline)             (9-feature V2 Pipeline)
                 │                               │
                 ▼                               ▼
       Continuous Risk Score             Continuous Risk Score
       & PolicyEngine Evaluation         & Advisory Classification
                 │                               │
                 ▼                               ▼
       EnforcementService                SHAP TreeExplainer
       (Router iptables Rule             (Local Feature Attributions
        Allow/Monitor/Restrict/Block)     on Disagreement/Anomaly)
                 │                               │
                 ▼                               ▼
     PostgreSQL: security_events       PostgreSQL: shadow_predictions
     (Authoritative Incident Log)      (Audited Discrepancy Ledger)
```

---

## 2. Candidate Prediction Service (`ShadowService`)

The candidate lifecycle is encapsulated in `backend/app/services/shadow_service.py` as a fail-safe singleton:

### 1. Artifact Verification on Loading:
Upon initialization, `ShadowService.get_candidate_predictor()` validates:
- Presence of all required artifacts: `model.joblib`, `scaler.joblib`, `label_encoder.joblib`, `metadata.json`, and `feature_schema.json`.
- Exact schema compliance: validates that the candidate schema contains exactly 9 features in the defined order (`FEATURE_NAMES_V2`), explicitly rejecting any artifact requesting `failed_auth_count`.
- Dedicated StandardScaler and LabelEncoder parameters fitted specifically to XGBoost V2.

### 2. Telemetry Capture per Flow:
For every evaluated flow, `ShadowEvaluationResult` records:
- `flow_id` and ISO 8601 UTC timestamp.
- Source and destination IP addresses, destination port, and protocol.
- Full 9-feature dictionary (`flow_features`).
- Production RF attack type, confidence, risk score, and execution latency ($ms$).
- Candidate XGBoost V2 attack type, confidence, risk score, and execution latency ($ms$).
- Binary `agreement` flag and categorized `disagreement_type` (e.g., `TRAFFIC_SPIKE_vs_BENIGN`).
- SHAP TreeExplainer feature attributions for the candidate prediction.

### 3. Fail-Safe Non-Blocking Isolation:
- Shadow inference is wrapped in strict try-except blocks. If candidate feature transformation, inference, or database persistence encounters an error, the exception is logged at warning level and the authoritative production transaction completes without delay.
- The `shadow_mode_enabled` configuration flag in `backend/app/config.py` allows dynamic enable/disable without service restarts.

---

## 3. Database Schema: `shadow_predictions`

To isolate candidate evaluations from authoritative operational events, a dedicated table was introduced via SQLAlchemy declarative mapping (`backend/app/models/shadow_prediction.py`):

| Column Name | Data Type | Constraints | Description |
|:---|:---:|:---:|:---|
| `id` | `VARCHAR(64)` | PK, Index | Unique shadow evaluation identifier (`shd-...`) |
| `flow_id` | `VARCHAR(64)` | Index | Cross-reference to authoritative `security_events.id` |
| `timestamp` | `TIMESTAMPTZ` | Index, NOT NULL | Event observation wall-clock timestamp |
| `source_ip` | `VARCHAR(45)` | Index, NOT NULL | Traffic initiator IP address |
| `destination_ip` | `VARCHAR(45)` | Index, NOT NULL | Traffic target IP address |
| `dst_port` | `INTEGER` | Nullable | Destination transport port |
| `protocol` | `VARCHAR(16)` | Default 'TCP' | L4 protocol |
| `feature_schema_version`| `VARCHAR(16)` | Default 'v2' | Feature schema contract identifier |
| `flow_features` | `JSON` | NOT NULL | Exact 9-feature input vector |
| `prod_model_version` | `VARCHAR(32)` | NOT NULL | Production model identifier (`v1_random_forest`) |
| `prod_attack_type` | `VARCHAR(64)` | Index, NOT NULL | Authoritative Random Forest classification |
| `prod_confidence` | `FLOAT` | NOT NULL | Production class probability estimate |
| `prod_risk_score` | `INTEGER` | Index, NOT NULL | Authoritative continuous risk score (0–100) |
| `prod_latency_ms` | `FLOAT` | NOT NULL | Authoritative model execution duration |
| `candidate_model_version`| `VARCHAR(32)`| NOT NULL | Candidate model identifier (`v2_xgboost`) |
| `candidate_attack_type`| `VARCHAR(64)` | Index, NOT NULL | Advisory XGBoost V2 classification |
| `candidate_confidence` | `FLOAT` | NOT NULL | Candidate class probability estimate |
| `candidate_risk_score` | `INTEGER` | Index, NOT NULL | Candidate continuous risk score (0–100) |
| `candidate_latency_ms` | `FLOAT` | NOT NULL | Candidate model execution duration |
| `agreement` | `BOOLEAN` | Index, NOT NULL | True if predictions match; False if discordant |
| `disagreement_type` | `VARCHAR(64)` | Index, Nullable | Formatted discrepancy label (`PROD_vs_CAND`) |
| `shap_attributions` | `JSON` | Nullable | Top 3 candidate SHAP feature attributions |

---

## 4. API and Frontend Integration

1. **REST Endpoints (`backend/app/api/v1/shadow.py`):**
   - `GET /api/v1/shadow/status`: Returns candidate loading state, schema version, and authority notice.
   - `GET /api/v1/shadow/comparison`: Returns aggregate summary metrics, agreement percentage, latency benchmarks, and recent shadow comparison records.
   - `GET /api/v1/shadow/records`: Paginated history with optional disagreement-only filtering.
2. **Frontend UI (`src/components/EvaluationView.tsx`):**
   - Added interactive sub-view switcher in the **ML Detection** section.
   - Displays real-time candidate telemetry, agreement rate cards, latency comparison, and live dual-model comparison ledger with prominent **"ADVISORY ONLY (NON-ENFORCING)"** safety badges.
   - Preserves all 11 existing application navigation sections without sidebar disruption.

---

## 5. Verification Test Evidence

The implementation was validated using dedicated automated test cases in `backend/tests/test_shadow_mode_v2.py`:
- `test_candidate_model_loading_and_metadata`: PASSED.
- `test_nine_feature_schema_order_and_types`: PASSED.
- `test_shadow_prediction_generation`: PASSED.
- `test_model_agreement_and_disagreement_detection`: PASSED.
- `test_candidate_shap_explanation_integration`: PASSED.
- `test_shadow_persistence_in_db`: PASSED.
- `test_policy_isolation_candidate_non_enforcing`: PASSED.
- `test_production_model_isolation`: PASSED.
- `test_candidate_failure_isolation`: PASSED.
- `test_concurrency_and_thread_safety`: PASSED.

All 10 tests passed with 100% compliance.

