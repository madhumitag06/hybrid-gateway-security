# FINAL MANUAL VERIFICATION CHECKLIST FOR USER

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Target:** User Acceptance Testing for Standalone Executable & Docker Frontend  
**Status:** READY FOR OPERATOR VERIFICATION  

---

> [!IMPORTANT]
> **STRICT NO-LOCALHOST TESTING COMPLIANCE NOTICE**:  
> In accordance with project instructions, the AI agent has executed zero browser visits and zero HTTP network requests to `localhost` or `127.0.0.1`. All interactive visual and browser validation checks below are designated as:  
> **`NOT TESTED — MANUAL USER VERIFICATION REQUIRED`**

---

## 1. Prerequisites Checklist

Before launching, ensure:
1. Docker desktop is running.
2. PostgreSQL container `gateway-postgres` is running on port `5434`.
3. Redis container `gateway-redis` is running on port `6380`.
4. Router container `hybrid-lab-router` is running.

---

## 2. Standalone Executable Verification Checklist

### Step 2.1: Launch Executable
- Navigate to: `backend/executable/AdaptiveSecurityGateway/`
- Double-click `AdaptiveSecurityGateway.exe` (or run from PowerShell: `.\AdaptiveSecurityGateway.exe`).
- **Observation**:
  - [ ] Terminal window opens without crashing.
  - [ ] Log displays: `[ML-STARTUP] XGBoost native dynamic library loaded successfully`.
  - [ ] Log displays: `[MODEL-STARTUP] Initial authoritative active model: ...`.
  - [ ] Server indicates listening on `http://127.0.0.1:8000` (or configured port).

### Step 2.2: Login Verification
- Open your browser to: `http://localhost:8000` (or `http://localhost:5173` if running Vite dev server).
- **Credentials to test**:
  - Email: `test10@gmail.com`
  - Password: `test@123`
- **Observation**:
  - [ ] Login screen displays `test10@gmail.com` (no stale `admin@gateway.local`).
  - [ ] Login succeeds immediately and navigates to the Security Gateway Dashboard.

### Step 2.3: Telemetry & PCAP Ingestion Persistence (Workstream 2)
- Click on **📦 PCAP Ingestion** in the sidebar.
- **Verify Model Badge**:
  - [ ] Header displays: `🛡️ Model: XGBoost V2` (or current active model) with standby indicator.
- **Ingest a PCAP**:
  - [ ] Under *Built-In Benchmark Captures*, click **Ingest** on `port_scan.pcap` (or upload any PCAP).
  - [ ] Processing completes with packet/flow counts and populates the telemetry table.
- **Test Persistence Across Navigation**:
  - [ ] Click **⌂ Dashboard** or **⚖ ML Detection** in the sidebar.
  - [ ] Click back on **📦 PCAP Ingestion**.
  - [ ] **Verification**: The evaluated capture telemetry and flow table remain visible! No blank screen, no reset to empty state.
- **Test Ingestion History**:
  - [ ] Click **📜 Ingestion History** button in the header.
  - [ ] Table opens displaying past ingestions saved in PostgreSQL.
  - [ ] Clicking **Load** on a past capture successfully re-loads its telemetry.

### Step 2.4: Adaptive ML Learning & Feedback Console (Workstream 3)
- Click on **⚖ ML Detection** in the sidebar.
- Look at the top sub-view tab switcher:
  - `[⚡ Experimental Benchmark Suite] | [🛡️ Candidate Model Shadow Mode] | [🧠 Adaptive ML Learning & Feedback]`
- Click on **🧠 Adaptive ML Learning & Feedback**.
- **Verify Pipeline Telemetry Strip**:
  - [ ] Displays Ingested PCAPs, Extracted Flows, Verified Labels, Unverified Inflow, Active Model, and Retraining Readiness.
- **Verify Analyst Feedback Ledger**:
  - [ ] Table displays unverified flows from the ingested PCAP.
  - [ ] Click **✓ Confirm** on a flow: Row updates to `CONFIRMED` with green pill badge.
  - [ ] Click **✏ Correct** on a flow: Dropdown opens (`BENIGN`, `BRUTE_FORCE`, `PORT_SCAN`, `SUSPICIOUS_TRANSFER`, `TRAFFIC_SPIKE`). Select a label and click **Save**: Row updates to `CORRECTED`.
  - [ ] Click **✕ Exclude** on a flow: Row updates to `EXCLUDED`.
  - [ ] Telemetry strip updates the count of verified labels.
- **Verify Versioned Dataset Preparation**:
  - [ ] When $\ge 5$ flows are verified, click **📦 Prepare Versioned Dataset**.
  - [ ] Card displays verified dataset version, sample count, and feature validation (9 features verified).
- **Verify Isolated Candidate Retraining**:
  - [ ] Click **🚀 Retrain Candidate**.
  - [ ] Retraining executes in sandbox (`ml/models/candidates/<candidate_version>/`).
  - [ ] Active production model is NOT affected.
- **Verify Promotion Acceptance Gate**:
  - [ ] Candidate appears in *Candidate Evaluation & Promotion Gate* ledger with Accuracy, F1, and FPR.
  - [ ] Click **👑 Approve Promotion**: Confirmation dialog appears. Upon confirming, model is promoted to active authoritative model!
  - [ ] Click **🛡️ Safety Rollback to Standby**: Active model immediately reverts to standby.

---

## 3. Verification Result Log

| Item # | Verification Task | Expected Result | Operator Check |
|---|---|---|---|
| 1 | Launch `AdaptiveSecurityGateway.exe` | Zero `XGBoostLibraryNotFound` crashes | `[ ] PASS` |
| 2 | Login with `test10@gmail.com` | Authenticates cleanly to Dashboard | `[ ] PASS` |
| 3 | PCAP Ingestion | Ingests packets and displays flows | `[ ] PASS` |
| 4 | Navigation Persistence | PCAP telemetry persists across sidebar tabs | `[ ] PASS` |
| 5 | Ingestion History | Past captures stored in DB are loadable | `[ ] PASS` |
| 6 | Flow Feedback | Confirm, Correct, Exclude flow labels | `[ ] PASS` |
| 7 | Candidate Retraining | Trains isolated candidate model | `[ ] PASS` |
| 8 | Controlled Promotion & Rollback | One-click promotion and instant rollback | `[ ] PASS` |

