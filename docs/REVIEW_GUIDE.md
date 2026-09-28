# Reviewer Demonstration Guide: Adaptive AI-Powered Security Gateway

This guide provides an academic and technical evaluation committee with a structured **5–10 minute demonstration walkthrough** of the Adaptive AI-Powered Security Gateway for Hybrid Cloud.

---

## 🧭 System Architecture & Decision Flow Overview

Before reviewing individual components, note the central architectural principle: **Strict Separation of Authoritative Security vs Advisory AI**.

```
[ INGESTION ]         PCAP / Network Flow / AWS VPC Flow Logs
                            ↓
[ ML THREAT ENGINE ]  10 Features → RandomForest (5 Classes) → Continuous Risk Score (0-100)
                            ↓
[ EXPLAINABILITY ]    Exact Shapley Attributions (shap.TreeExplainer)
                            ↓
[ POLICY ENGINE ]     Deterministic Rules → Management Allowlist → DRY_RUN / SANDBOX Containment
                            ↓
[ PERSISTENCE ]       PostgreSQL Relational Ledger (Events, Active Rules, Audit History)
                            ↓
[ PRESENTATION ]      React 18 Console & (Optional) Advisory AI Analyst Copilot
```

---

## ⏱️ 5–10 Minute Demonstration Walkthrough

### Step 1: Automated Test Suite Verification
Run the backend and ML test suite from the terminal to verify complete system integrity:
```powershell
.\ml\.venv\Scripts\pytest.exe -q
```
*Expected Result:* `119 passed, 0 failed, 2 warnings` covering API endpoints, PolicyEngine logic, ML inference, SHAP compatibility, and data leakage checks.

---

### Step 2: Ingest a Normal (Benign) Network Flow
* **Simulated Input:** Standard HTTPS traffic (`dst_port=443`, `conn_rate=2.5`, `failed_auth_count=0`, `duration=3.0s`).
* **Expected ML Output:**
  - **Predicted Threat:** `BENIGN`
  - **Risk Score:** $< 40$ (Low Risk Tier)
  - **SHAP Explanation:** Features show neutral or negative risk contribution.
* **Expected PolicyEngine Action:** `ALLOW` with continuous monitoring. Zero host containment applied.

---

### Step 3: Ingest a Multi-Port Reconnaissance Probe (Port Scan)
* **Simulated Input:** Rapid sweep across 60 destination ports (`unique_dst_ports=60`, `conn_rate=120.0`, `packet_count=120`).
* **Expected ML Output:**
  - **Predicted Threat:** `PORT_SCAN`
  - **Risk Score:** $\ge 85$ (Critical / High Risk Tier)
  - **SHAP Explanation:** `unique_dst_ports` and `conn_rate` are highlighted as top positive risk drivers.
* **Expected PolicyEngine Action:** `BLOCK` / `QUARANTINE`.
* **Enforcement Behavior:** In `SANDBOX` mode, a temporary quarantine rule with a 300-second TTL is created and stored in PostgreSQL (`active_enforcements`).

---

### Step 4: Verify Management Allowlist Protection (Safety Bypass)
* **Simulated Input:** Suspicious flow originating from an authorized internal management subnet (e.g., `10.100.0.1` or `192.168.1.1`).
* **Expected Behavior:**
  - The ML model accurately detects the anomalous traffic pattern.
  - The **PolicyEngine intercepts the decision** and overrides automated blocking, logging `ALLOWLIST_PROTECTION_TRIGGERED`.
  - Guarantees critical administrative access cannot be severed by automated false positives.

---

### Step 5: Relational Persistence & Audit Ledger
* **Database Tables:** Inspect PostgreSQL or the API audit endpoints:
  - `security_events`: Historical flow records with risk scores, predicted classes, and SHAP features.
  - `policy_audit_logs`: Immutable ledger of every policy evaluation and enforcement trigger.
  - `active_enforcements`: Live containment rules with remaining TTL timestamps and revocation endpoints.

---

### Step 6: Review the Advisory AI Security Analyst Copilot
* **Interaction:** Request an executive briefing on a high-risk security event.
* **Demonstrated Safeguards:**
  1. **Advisory Only:** The LLM receives read-only event telemetry and outputs markdown narrative analysis.
  2. **Zero Enforcement Power:** The LLM has no API path to create firewall rules or alter ML risk scores.
  3. **Deterministic Fallback:** If API keys (`GROQ_API_KEY`, `OPENAI_API_KEY`) are omitted, the gateway generates local deterministic XAI summaries seamlessly.

---

### Step 7: Model Transparency & Academic Validation
Navigate to the **Evaluation** tab or review [`ml/MODEL_CARD.md`](file:///c:/Users/LENOVO/Desktop/hybrid-gateway-security/ml/MODEL_CARD.md):

* **Internal Holdout Test Accuracy:** **99.80%** (Calibrated continuous synthetic benchmark, seed 42).
* **External Public Benchmark Accuracy (CIC-IDS2017):** **60.78%** (Zero-shot evaluation without retraining).
* **Academic Review Discussion Point:** The performance difference highlights the classic **distribution shift** between synthetic network simulators and university testbed packet captures. When evaluated on structural attacks (`BRUTE_FORCE`, `PORT_SCAN`), precision remains $\ge 87.5\%$.

---

## 🔍 Key Academic & Technical Distinctions

1. **Why Random Forest instead of a Deep Neural Network?**  
   Random Forest offers sub-millisecond inference latency, exact Shapley computation via `TreeExplainer`, deterministic reproducibility, and high resilience to collinear flow features without requiring GPU acceleration.

2. **How does the system prevent data leakage?**  
   The `StandardScaler` is strictly fitted on the training split only. Test and validation data are transformed using stored parameters (`scaler.joblib`).

3. **What is the real scope of AWS integration?**  
   The gateway includes a production-grade VPC Flow Log parser and high-fidelity deterministic fixtures (`AWS_VPC_FLOW_LOG_FIXTURE`). It does not modify cloud provider infrastructure.
