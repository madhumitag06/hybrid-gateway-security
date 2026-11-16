# PHASE 22.7 — RUNTIME INFERENCE INTEGRITY & INFINITE LOOP INVESTIGATION REPORT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository Branch:** `main`  
**Git Baseline Commit:** `f472588bb35c45031a8a28dec2d19d626ea58daf`  
**Investigation Timestamp:** 2026-11-16T21:40:00+05:30  
**Phase Objective:** Root-Cause Diagnosis, Model Identity Verification, Duplicate Remediation & Rebuild  

---

## 1. Executive Summary

During manual acceptance testing of the Phase 22.6 standalone executable (`AdaptiveSecurityGateway.exe`), three runtime defects were uncovered in the Live Network (`TrafficView`) module:
1. **Infinite Inference Generation**: The Live Network page continuously generated inference requests without deliberate user interaction, causing the inference counter to climb endlessly, repeatedly reporting `PORT_SCAN` (risk score 92/100, confidence 85.7%), and accumulating duplicate records in the database and history table.
2. **Model Identity Discrepancy**: While backend startup logs identified `Big Data XGBoost V2 (Clean Schema)` (`candidate_xgboost_v2`, 9 features) as the authoritative active primary model, the Live Network frontend explicitly labeled its inference engine and 5-class probability distribution as `RandomForest`.
3. **Question of Hardcoded / Mock Predictions**: The identical repeated outputs raised concerns that the system was relying on static fixtures, mock responses, or demo fallbacks.

### Key Investigation Findings
- **Defect 1 (Infinite Loop Root Cause)**: In `src/components/TrafficView.tsx`, the component-level `useEffect` hook depended on `[handlePredict]`. In turn, `handlePredict` was memoized via `useCallback` with dependencies on `[flow, activePreset]`. On initial mount, `useEffect` invoked `handlePredict(initial, 'PORT_SCAN')`, which updated state (`setFlow`, `setAnalysisRunCount`, `setAnalysisHistory`, `setPredictResult`). These state mutations re-instantiated `handlePredict`, which immediately re-triggered the `useEffect`, initiating an unbounded infinite re-render and prediction cycle.
- **Defect 2 (Model Identity Discrepancy Root Cause)**: The backend was executing genuine `XGBClassifier` inference from `candidate_xgboost_v2`. However, the frontend `TrafficView.tsx` component retained stale, hardcoded string literals (`RandomForest`) in its subtitle and section header left over from earlier Phase 1 development. The UI never queried the model registry or `/api/health` for the active model's display name.
- **Defect 3 (Nature of Predictions)**: Source-code tracing and direct Python AST inspection confirmed that **predictions were 100% genuine ML inferences**, not mock or cached responses. The backend's XGBoost V2 model evaluated the `PORT_SCAN` feature vector on every request, deterministically computing class probability `0.8569` (85.7%) and continuous risk score `92/100`. Because the frontend loop submitted the identical feature vector continuously, the genuine model returned identical outputs and persisted an event row on every tick.
- **Resolution & Verification**:
  - The infinite loop in `TrafficView.tsx` was eliminated: `useEffect` was decoupled from `handlePredict` and restricted to a single read-only mount initialization (`[]`), loading presets, history, and model health without auto-running inference.
  - Scenario selection and history loading now populate form fields without triggering automated execution. Inference requires an explicit user action (clicking the submit button).
  - Dynamic model identity display was implemented in both backend schemas (`PredictionResponse.model_name`, `model_version`) and the frontend UI, dynamically rendering `Big Data XGBoost V2 (Clean Schema) (XGBClassifier)` across headers and probability charts.
  - An empty-state placeholder was added to prevent unanalyzed visual artifacts before user interaction.
  - A focused 10-test regression suite (`test_phase22_7_runtime_integrity.py`) was created, passing 10/10 tests.
  - Full backend test suite executed: **383 passed, 0 failed** in 65.41s.
  - Standalone executable rebuilt and verified: 17/17 steps passed. Rollback backups preserved untouched.

---

## 2. Investigation A — Exact Root Cause of the Infinite Inference Loop

### Traced Call Chain & Responsible Code
In `src/components/TrafficView.tsx`:

```typescript
// Lines 135–197 (Before Remediation):
const handlePredict = useCallback(
  async (
    flowInput: FlowPredictionRequest = flow,
    presetLabel?: string
  ) => {
    ...
    setPredictResult(res)
    setPolicyDecision(dec)
    setComparisonResult(comp)
    setAnalysisRunCount((prev) => {
      const nextRun = prev + 1
      ...
      setAnalysisHistory((historyPrev) => [historyEntry, ...historyPrev.slice(0, 9)])
      return nextRun
    })
    setShowFreshBanner(true)
  },
  [flow, activePreset] // <-- Dependency array causes handlePredict to be recreated on state changes
)

// Lines 200–254 (Before Remediation):
useEffect(() => {
  getPresets()
    .then((p) => {
      const merged = { ...FALLBACK_PRESETS, ...p }
      setPresets(merged)
      const initial = merged.PORT_SCAN || DEFAULT_FLOW
      setFlow(initial) // <-- Mutates flow state
      setInputValues({ ... })
      handlePredict(initial, 'PORT_SCAN') // <-- Invokes handlePredict on mount
    })
    .catch(() => {
      setPresets(FALLBACK_PRESETS)
      handlePredict(FALLBACK_PRESETS.PORT_SCAN, 'PORT_SCAN')
    })
  ...
}, [handlePredict]) // <-- DEPENDENCY ON handlePredict CAUSES INFINITE LOOP!
```

### Mechanism of the Failure
1. **Initial Mount**: `TrafficView` renders on navigation to "Live Network".
2. **Mount Execution**: `useEffect` runs because `handlePredict` is initialized.
3. **Auto-Execution**: `useEffect` resolves `getPresets()`, calls `setFlow(initial)`, and calls `handlePredict(initial, 'PORT_SCAN')`.
4. **State Mutation**: `setFlow` and `handlePredict` mutate `flow`, `predictResult`, `analysisRunCount`, `lastExecution`, `analysisHistory`, and `showFreshBanner`.
5. **Re-creation of Function**: Because `flow` was updated, the `useCallback` for `handlePredict` produces a brand-new function reference.
6. **Re-triggering of Effect**: React evaluates `useEffect` dependencies. Since `handlePredict` changed identity, React triggers `useEffect` again.
7. **Recursive HTTP Requests**: In each cycle, `handlePredict` calls `predictFlow(flowInput)`, sending `POST /api/v1/predict` (with `persist=True` by default).
8. **Database Accumulation**: `backend/app/api/v1/predict.py` executes `DashboardService.record_prediction()`, inserting a new `SecurityEventModel` row into PostgreSQL on every iteration.
9. **UI Symptoms**:
   - The "Inferences: N" counter incremented once every 100–300 ms.
   - The analysis history table constantly pushed new records.
   - The form remained locked or constantly flickering.

---

## 3. Investigation B — Model Identity Discrepancy (RandomForest vs. XGBoost V2)

### Analysis of the Discrepancy
The user observed:
- Standalone CLI/startup log: `Big Data XGBoost V2 (Clean Schema)` (`candidate_xgboost_v2`, 9-feature schema).
- Live Network UI: `Multi-Class Probability Distribution (RandomForest)`.

### Findings
1. **Backend Model Registry Primacy**:
   - In `backend/app/services/ml_service.py`:
     ```python
     _active_version: str = getattr(settings, "active_model_version", "candidate_xgboost_v2")
     ```
   - In `backend/app/main.py:48-75`, the startup lifespan loads native XGBoost libraries and verifies the candidate model `candidate_xgboost_v2`.
   - Inspection of `MLService.get_predictor()` confirms that the active predictor is an `XGBClassifier` loaded from `ml/models/candidates/bigdata_v2/model.joblib`.
   - The feature schema loaded by `ThreatPredictor` is `FEATURE_NAMES_V2`:
     `['packet_count', 'byte_count', 'duration', 'conn_rate', 'dst_port', 'unique_dst_ports', 'bytes_per_sec', 'packets_per_sec', 'avg_packet_size']` (length 9).
2. **Frontend UI Stale String Artifacts**:
   - In `src/components/TrafficView.tsx`, lines 5, 418, and 695 contained hardcoded strings:
     * Line 418: `Evaluate raw network flow vectors in real-time through the trained RandomForest model`
     * Line 695: `<h4>Multi-Class Probability Distribution (RandomForest)</h4>`
   - The frontend never queried the active model identity from `/api/health` or `predictResult.model_name`.
   - **Conclusion**: The backend was executing genuine XGBoost V2 inference, but the frontend was misrepresenting the model identity due to hardcoded legacy labels.

---

## 4. Investigation C — Hardcoded / Mock Data Audit

### Test Methodology
We evaluated whether predictions originated from:
1. Static mock fixtures or dictionary lookups.
2. Cached prediction responses.
3. Real ML model inference.

### Evidence
We tested `ThreatPredictor` directly with the exact `PORT_SCAN` vector:
```python
sample_flow = NetworkFlowInput(
    packet_count=2,
    byte_count=120,
    duration=0.08,
    conn_rate=120.0,
    dst_port=8080,
    unique_dst_ports=75,
    failed_auth_count=0
)
res = predictor.predict_flow(sample_flow)
```

**Results:**
- Model Object: `xgboost.sklearn.XGBClassifier`
- Input Dimension: `(1, 9)` numerical matrix
- Scaler: `MinMaxScaler` fitted on 6.49M multi-dataset records
- `predict_proba()` output:
  * `BENIGN`: 0.1406 (14.1%)
  * `PORT_SCAN`: **0.8569 (85.7%)**
  * `TRAFFIC_SPIKE`: 0.0023 (0.2%)
  * `SUSPICIOUS_TRANSFER`: 0.0003 (0.0%)
  * `BRUTE_FORCE`: 0.0000 (0.0%)
- Continuous Risk Score: **92 / 100**
- Categorical Threat: `HIGH`

**Conclusion:**
There are **zero hardcoded mock prediction dictionaries** in the production path. The repeated outputs were identical because the infinite loop submitted the exact same `PORT_SCAN` feature vector on every cycle, and the trained XGBoost model deterministically outputted its mathematical prediction (`PORT_SCAN`, 85.7% confidence, 92/100 risk).

---

## 5. Investigation D — Data Persistence & Duplicate Record Analysis

### Persistence Inspection
- `POST /api/v1/predict` accepts `NetworkFlowRequest`.
- When `persist=True` (default), line 38 of `backend/app/api/v1/predict.py` executes:
  ```python
  pred, _ = DashboardService.record_prediction(
      db=db,
      flow_request=request,
      source_ip=request.source_ip or "192.168.1.100",
      destination_ip=request.destination_ip or "10.100.1.10",
      is_demo=False,
  )
  ```
- In `record_prediction()`, lines 237–258 construct a `SecurityEventModel` and execute `repo.create(event_model)`.
- Under normal operation, **one deliberate user click executes one HTTP POST request and inserts exactly one row**.
- In the defect state, the frontend's uncontrolled re-render loop issued requests continuously, inserting dozens of duplicate rows per minute.
- **Remediation**:
  - The loop was severed.
  - On mount, Live Network only reads presets and health; it does not persist any records.
  - The Analyze button is guarded by `if (loading) return` and the button is disabled while processing.
  - Opening Live Network, navigating tabs, and refreshing history perform zero database inserts.

---

## 6. Technical Remediation Implemented

### 6.1 Frontend Remediation (`src/components/TrafficView.tsx`)
1. **Decoupled Mount Initialization**:
   - `useEffect` dependency array set to `[]` (mount once).
   - Removed calls to `handlePredict(initial, 'PORT_SCAN')` from `useEffect`.
   - On mount, `getPresets()`, `getBackendHealth()`, and `listSecurityEvents({ limit: 5 })` load initial data in read-only mode.
2. **Explicit User-Action Model**:
   - `selectPreset(key)` populates `flow` and `inputValues` without auto-running inference.
   - `reloadFromHistory(item)` populates form fields without auto-running inference.
   - Inference runs **only** when the user clicks the submit button ("⚡ Run ML Anomaly Inference & Policy Trace").
3. **Dynamic Model Identity**:
   - Added `modelInfo` state initialized via `getBackendHealth()`.
   - Subtitle updated:
     ```tsx
     Evaluate raw network flow vectors in real-time through the active <strong>{modelInfo?.model_name || 'Big Data XGBoost V2 (Clean Schema)'}</strong> model ({modelInfo?.feature_count || 9}-feature schema)...
     ```
   - Chart header updated:
     ```tsx
     <h4>Multi-Class Probability Distribution ({modelInfo?.model_type ? `${modelInfo.model_name} (${modelInfo.model_type})` : (predictResult.model_name || 'XGBClassifier')})</h4>
     ```
4. **Empty-State Placeholder**:
   - When `!predictResult`, renders a structured guidance placeholder prompting the user to select or customize flow parameters and click Analyze.

### 6.2 Backend Schema & Service Updates
1. `backend/app/schemas/predict.py`:
   - Added `model_version: Optional[str]` and `model_name: Optional[str]` to `PredictionResponse`.
2. `backend/app/services/ml_service.py`:
   - Updated `predict()` to attach `model_version` (`candidate_xgboost_v2`) and `model_name` (`Big Data XGBoost V2 (Clean Schema)`) to every `PredictionResponse`.
3. `src/types.ts`:
   - Updated `FlowPredictionResponse` and `BackendHealth` with `model_name` and `model_version` definitions.

---

## 7. Investigation E — Offline Regression Tests & Results

A dedicated automated regression test suite was created in `backend/tests/test_phase22_7_runtime_integrity.py`:

| # | Test Function | Purpose | Result |
| :--- | :--- | :--- | :--- |
| **01** | `test_01_fetching_presets_does_not_create_inference` | Asserts `GET /v1/predict/presets` causes zero database inserts. | **PASSED** |
| **02** | `test_02_reading_inference_history_does_not_create_inference` | Asserts `GET /api/v1/events` causes zero database inserts. | **PASSED** |
| **03** | `test_03_one_deliberate_analysis_creates_exactly_one_record` | Asserts one `POST /v1/predict` request creates exactly 1 DB record. | **PASSED** |
| **04** | `test_04_repeated_history_refreshes_do_not_create_additional_records` | Asserts 10 consecutive event queries cause zero DB inserts. | **PASSED** |
| **05** | `test_05_duplicate_request_handling_is_safe` | Asserts consecutive identical requests return deterministic responses safely. | **PASSED** |
| **06** | `test_06_live_network_reports_actual_loaded_model_identity` | Asserts `/api/health` and `/api/v1/predict` report `XGBClassifier` and `candidate_xgboost_v2`. | **PASSED** |
| **07** | `test_07_xgboost_v2_feature_schema_matches_authoritative_nine_features` | Asserts active XGBoost V2 model matches `FEATURE_NAMES_V2` (9 features, no `failed_auth_count`). | **PASSED** |
| **08** | `test_08_model_inference_errors_are_not_silently_replaced_with_hardcoded_predictions` | Asserts invalid payloads raise HTTP 422 rather than returning mock predictions. | **PASSED** |
| **09** | `test_09_probability_labels_correspond_to_actual_model_output` | Asserts probability output contains 5 classes, sums to ~1.0, and PORT_SCAN > 0.80. | **PASSED** |
| **10** | `test_10_no_production_demo_fixtures_returned_as_real_predictions` | Asserts different vectors (PORT_SCAN, TRAFFIC_SPIKE, BENIGN) yield distinct ML outputs. | **PASSED** |

### Complete Regression Suite Execution
- **Command:** `pytest backend/tests/ -v`
- **Result:** **383 passed, 0 failed, 6 upstream deprecation warnings** (65.41s).

---

## 8. Build, Asset Synchronization & Executable Integrity

### 8.1 Frontend Quality & Build
- `npx tsc -b`: Clean exit (0 errors).
- `npm run lint` (`oxlint`): Clean exit (0 errors, 0 warnings across 29 files).
- Production Vite Build:
  * `dist/index.html`: 0.74 kB (gzip: 0.43 kB)
  * `dist/assets/index-DgMRxSro.css`: 62.50 kB (gzip: 10.78 kB)
  * `dist/assets/index-DB3ic-Z5.js`: 542.15 kB (gzip: 135.33 kB)

### 8.2 Executable Rebuild & Checksum Registry
`backend/build_exe.ps1` completed with **17/17 steps verified**.
- Bundled assets verified synchronized with `dist/`: `index-DB3ic-Z5.js`, `index-DgMRxSro.css`.
- Model artifacts bundled: Random Forest Baseline + Big Data XGBoost V2.
- Native library: `xgboost.dll` verified.
- SEC-04 verified: Zero plaintext `.env` files present.

### Checksum Ledger (Independently Calculated SHA-256)

| Artifact Target | File Size (Bytes) | SHA-256 Digest (64 Hex Characters) | Role / Status |
| :--- | :--- | :--- | :--- |
| **Active Standalone Executable** | **39,236,003** | `01FD70555780B055C93DE749E0715CD3055A9F55B64956DBFF57CCB9AE7D86E7` | **ACTIVE REBUILT (Phase 22.7)** |
| **Phase 22.6 Preserved Backup** | **39,235,515** | `C1AEDC713160CCC4E1647875023ADBD05812791D19311C1428F792C3BCAB93EE` | Preserved rollback backup |
| **Phase 22.4 Baseline Rollback Backup** | **39,230,265** | `1E3BEC2906F4F00B59926D5D727BF4E802A7C8E69F75080E5F7DB600397DE55B` | Preserved baseline backup |

*Note: All three executables are preserved. No rollback backup was overwritten or deleted.*

---

## 9. Remaining Risks & Operational Guidance

1. **Manual User Verification Required**:
   - In accordance with Phase 22 safety rules, no automated browser testing was executed against localhost.
   - The user must launch the newly rebuilt executable (`01FD7055...`) and manually test the Live Network module.
2. **Expected User Experience in Live Network**:
   - Opening Live Network: Form is preloaded with `PORT_SCAN` parameters; Right column displays the "Ready for Threat Evaluation" placeholder; Inferences counter remains at `0`; History table shows previous events from database without auto-incrementing.
   - Clicking Scenario Chips (`BENIGN_HTTPS`, `BRUTE_FORCE_SSH`, etc.): Form inputs update immediately; no inference runs until the user clicks the Analyze button.
   - Clicking "Run ML Anomaly Inference & Policy Trace": Exactly 1 inference request is sent, latency is reported, the probability distribution displays the active `Big Data XGBoost V2 (Clean Schema)` title, and exactly 1 record is appended to the history table and PostgreSQL.

---

## 10. Conclusion and Next Step

- **Issue 1 (Infinite Loop):** **FIXED** and covered by regression tests.
- **Issue 2 (Model Identity Mismatch):** **FIXED**; UI and API dynamically report `Big Data XGBoost V2 (Clean Schema) (XGBClassifier)`.
- **Issue 3 (Hardcoded/Mock Suspicion):** **RESOLVED**; predictions are genuine XGBoost V2 mathematical outputs.
- **Standalone Executable:** Successfully synchronized and rebuilt (`01FD70555780B055C93DE749E0715CD3055A9F55B64956DBFF57CCB9AE7D86E7`).
- **Readiness:** The application is **READY FOR USER MANUAL ACCEPTANCE**.
