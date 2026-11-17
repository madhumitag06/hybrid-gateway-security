# PHASE 12 MODEL-SCHEMA INTEGRITY AUDIT REPORT
## Authoritative XGBoost V2 Feature Schema, Ordering & Systemic Parity Verification

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `C:\Users\LENOVO\Desktop\hybrid-gateway-security`  
**Authoritative Model:** Big Data XGBoost V2 (`candidate_xgboost_v2`)  
**Artifact Directory:** `ml\models\candidates\bigdata_v2\`  
**Audit Date:** 2026-11-16  
**Execution Mode:** STRICT READ-ONLY AUDIT (Zero code, model, database, or executable edits)  

---

## 1. Executive Summary & Verdict

A comprehensive, read-only mathematical and architectural audit was performed to compare feature schemas across all five specified sources:
1. `ml/models/candidates/bigdata_v2/feature_schema.json`
2. The actual authoritative XGBoost V2 model metadata (`metadata.json`) and runtime inference implementation (`ml/models/predict.py`).
3. The authoritative code constant `FEATURE_NAMES_V2` in `ml/features/extractor.py`.
4. `backend/app/services/ml_service.py` and `backend/app/cloud/services/telemetry_normalizer.py`.
5. The feature vector used by the 500-sample holdout benchmark (`ml/evaluation/run_phase10_xgb_benchmark.py`).

### Audit Findings & Verdict:

- **Mathematical & Schema Parity: 100% PERFECT MATCH**
  The production model receives **EXACTLY the same nine features, in the exact same order**, across:
  - **Training Pipeline** (`ml/training/train_and_compare_v2.py`)
  - **500-Sample Holdout Benchmark** (`ml/evaluation/run_phase10_xgb_benchmark.py`)
  - **Live AWS CloudWatch Ingestion & Inference** (`telemetry_normalizer.py` $\to$ `ml_service.py` $\to$ `predict.py`)

- **Authoritative Canonical 9-Feature Schema & Order**:
  ```python
  [
      "packet_count",       # Index 0
      "byte_count",         # Index 1
      "duration",           # Index 2
      "conn_rate",          # Index 3
      "dst_port",           # Index 4
      "unique_dst_ports",   # Index 5
      "bytes_per_sec",      # Index 6
      "packets_per_sec",    # Index 7
      "avg_packet_size"     # Index 8
  ]
  ```

- **Discrepancy Root Cause: Narrative Documentation Artifact (Zero Code/Model Impact)**:
  The secondary feature list:
  `["duration", "src_bytes", "dst_bytes", "wrong_fragment", "urgent", "hot", "failed_logins", "num_compromised", "connection_rate"]`
  is a legacy narrative artifact originating from NSL-KDD / KDD Cup 1999 documentation. 
  An exhaustive search across the entire repository confirms:
  - **Zero Python code files** implement or reference `wrong_fragment`, `urgent`, `hot`, or `num_compromised`.
  - **Zero model artifacts or preprocessors** were ever fitted on NSL-KDD host features.
  - **Zero dataset files** (CIC-IDS2017, CSE-CIC-IDS2018, CIC-DDoS2019, UNSW-NB15) contain these host variables.
  - AWS VPC Flow Logs operate strictly at Layer 3/4 and do not contain application-level host artifacts (such as directory traversal `hot` counts or TCP `urgent` pointers).
  - The appearance of that string in previous narrative reports (e.g., `FINAL_AWS_LIVE_TELEMETRY_READINESS_REPORT.md` and `PHASE12_EXECUTION_COMPLETION_REPORT.md`) was purely descriptive misattribution in markdown text, while the executed code strictly implemented `FEATURE_NAMES_V2`.

---

## 2. Comparative Evidence Across All Five Sources

### Source 1: `ml/models/candidates/bigdata_v2/feature_schema.json`
**File Path:** `ml/models/candidates/bigdata_v2/feature_schema.json`  
**File Contents:**
```json
{
  "version": "v2",
  "feature_names": [
    "packet_count",
    "byte_count",
    "duration",
    "conn_rate",
    "dst_port",
    "unique_dst_ports",
    "bytes_per_sec",
    "packets_per_sec",
    "avg_packet_size"
  ],
  "count": 9
}
```
**Observation:** Defines 9 features, index 0 to 8, beginning with `packet_count` and ending with `avg_packet_size`.

---

### Source 2: Authoritative XGBoost V2 Model Metadata & Runtime Implementation

#### 2.1 Model Metadata (`ml/models/candidates/bigdata_v2/metadata.json`)
```json
{
  "candidate_id": "bigdata_v2",
  "algorithm": "Big Data XGBoost V2",
  "timestamp_utc": "2026-11-05T19:45:59.260016+00:00",
  "feature_schema": [
    "packet_count",
    "byte_count",
    "duration",
    "conn_rate",
    "dst_port",
    "unique_dst_ports",
    "bytes_per_sec",
    "packets_per_sec",
    "avg_packet_size"
  ],
  "feature_count": 9,
  "classes": [
    "BENIGN",
    "PORT_SCAN",
    "BRUTE_FORCE",
    "TRAFFIC_SPIKE",
    "SUSPICIOUS_TRANSFER"
  ]
}
```

#### 2.2 Model Artifact & Scaler Inspection (`model.joblib`, `scaler.joblib`)
Inspection of the serialized scikit-learn/XGBoost objects directly via Python:
- `model.joblib`:
  - Class: `<class 'xgboost.sklearn.XGBClassifier'>`
  - Input Feature Dimension (`n_features_in_`): **9**
- `scaler.joblib`:
  - Class: `<class 'sklearn.preprocessing._data.StandardScaler'>`
  - Input Feature Dimension (`n_features_in_`): **9**
  - Scaler feature names: Unnamed numerical array of length 9 matching the training DataFrame column order.

#### 2.3 Runtime Inference Implementation (`ml/models/predict.py`)
In `ThreatPredictor._load_artifacts()` (lines 67–72):
```python
if meta_path.exists():
    with open(meta_path, "r", encoding="utf-8") as f:
        self.metadata = json.load(f)
self.feature_schema = self.metadata.get("feature_schema", FEATURE_NAMES)
```
In `ThreatPredictor.predict_flow()` (lines 86–93):
```python
# Extract numerical feature vector [1, n_features] matching model schema
X_raw = FeatureExtractor.extract_from_flow(flow_obj, schema=self.feature_schema)

# Apply preprocessing scaling fitted during training
X_scaled = self.scaler.transform(X_raw)

# Obtain class probability estimates from XGBoost
proba = self.model.predict_proba(X_scaled)[0]
```
**Observation:** `self.feature_schema` dynamically resolves to the 9-element list in `metadata.json`, which is `FEATURE_NAMES_V2`.

---

### Source 3: Authoritative Code Constant `FEATURE_NAMES_V2`
**File Path:** `ml/features/extractor.py`  
**Lines 26–38:**
```python
# Production-grade V2 Feature Schema (9 features)
# failed_auth_count removed due to lack of genuine L3/L4 network observability
FEATURE_NAMES_V2 = [
    "packet_count",
    "byte_count",
    "duration",
    "conn_rate",
    "dst_port",
    "unique_dst_ports",
    "bytes_per_sec",
    "packets_per_sec",
    "avg_packet_size",
]
```
And in `FeatureExtractor.extract_from_flow()` (lines 132–146):
```python
feature_map = {
    "packet_count": float(flow.packet_count),
    "byte_count": float(flow.byte_count),
    "duration": float(flow.duration),
    "conn_rate": float(flow.conn_rate),
    "dst_port": float(flow.dst_port),
    "unique_dst_ports": float(max(flow.unique_dst_ports, 1)),
    "failed_auth_count": float(max(flow.failed_auth_count, 0)),
    "bytes_per_sec": float(bytes_per_sec),
    "packets_per_sec": float(packets_per_sec),
    "avg_packet_size": float(avg_packet_size),
}

vector = [feature_map[name] for name in target_schema]
return np.nan_to_num(np.array([vector], dtype=np.float64), nan=0.0, posinf=1e9, neginf=0.0)
```
**Observation:** When `target_schema = FEATURE_NAMES_V2`, the list comprehension evaluates keys in the exact order of `FEATURE_NAMES_V2`. Note that `failed_auth_count` is in `feature_map` purely for backward-compatibility with V1, but is **never selected** when `target_schema` is `FEATURE_NAMES_V2`.

---

### Source 4: `MLService.predict` and `telemetry_normalizer.py`

#### 4.1 Telemetry Normalizer (`backend/app/cloud/services/telemetry_normalizer.py`)
In `normalize_flow_record()` (lines 188–198):
```python
# Canonical 9-feature dictionary matching FEATURE_NAMES_V2 exactly
feature_dict = {
    "packet_count": float(pkt_count),
    "byte_count": float(byte_count),
    "duration": float(duration),
    "conn_rate": float(conn_rate),
    "dst_port": float(dst_port),
    "unique_dst_ports": float(unique_dst_ports),
    "bytes_per_sec": float(bytes_per_sec),
    "packets_per_sec": float(packets_per_sec),
    "avg_packet_size": float(avg_packet_size),
}
```
In `process_canonical_batch()` (lines 244–257):
```python
flow_req = NetworkFlowRequest(
    packet_count=int(feat_dict["packet_count"]),
    byte_count=int(feat_dict["byte_count"]),
    duration=feat_dict["duration"],
    conn_rate=feat_dict["conn_rate"],
    dst_port=int(feat_dict["dst_port"]),
    unique_dst_ports=int(feat_dict["unique_dst_ports"]),
    failed_auth_count=0,  # Zero by definition for network flow telemetry
    bytes_per_sec=feat_dict["bytes_per_sec"],
    packets_per_sec=feat_dict["packets_per_sec"],
    avg_packet_size=feat_dict["avg_packet_size"],
)

prediction: PredictionResponse = MLService.predict(flow_req)
```

#### 4.2 MLService Routing (`backend/app/services/ml_service.py`)
In `MLService.predict()` (lines 206–208):
```python
predictor = cls.get_predictor()
flow_input = NetworkFlowInput(**request.model_dump())
pred_output: PredictionOutput = predictor.predict_flow(flow_input)
```
Where `cls.get_predictor()` selects `candidate_xgboost_v2` (configured as active primary in `settings.active_model_version`).

**Observation:** `telemetry_normalizer.py` extracts the exact 9 features matching `FEATURE_NAMES_V2`, bundles them into `NetworkFlowRequest`, passes them through `MLService.predict`, and `ThreatPredictor` reconstructs the 9-element array using `self.feature_schema` (`FEATURE_NAMES_V2`).

---

### Source 5: Feature Vector in 500-Sample Holdout Benchmark
**File Path:** `ml/evaluation/run_phase10_xgb_benchmark.py`  
**Lines 23–56:**
```python
schema_path = model_dir / "feature_schema.json"
...
with open(schema_path, "r", encoding="utf-8") as f:
    schema_data = json.load(f)
feature_names = schema_data.get("feature_names", [])

# Verification:
assert len(feature_names) == 9, f"Expected 9 features, got {len(feature_names)}"
...
df_500 = pd.concat(sampled_dfs, ignore_index=True)
X_raw = df_500[feature_names].to_numpy(dtype=np.float64)
X_scaled = scaler.transform(X_raw)
y_pred_idx = model.predict(X_scaled)
```
**Output Artifact:** `ml/evaluation/phase10_benchmark_results.json` (lines 6–16):
```json
  "feature_schema": [
    "packet_count",
    "byte_count",
    "duration",
    "conn_rate",
    "dst_port",
    "unique_dst_ports",
    "bytes_per_sec",
    "packets_per_sec",
    "avg_packet_size"
  ]
```
**Observation:** The benchmark directly reads `feature_names` from `feature_schema.json` and slices the test DataFrame with `df_500[feature_names]`, resulting in the exact same 9 columns in the exact same order.

---

## 3. Training Pipeline Feature Ordering Verification
**File Path:** `ml/training/train_and_compare_v2.py`  
**Lines 64–81:**
```python
table = pq.read_table(parquet_path, columns=FEATURE_NAMES_V2 + ["label", "dataset_source"])
df = table.to_pandas()
...
X = df[FEATURE_NAMES_V2].to_numpy(dtype=np.float64)
```
And in lines 110–152:
```python
scaler = StandardScaler().fit(X_train)
X_train_scaled = scaler.transform(X_train)
xgb_model.fit(X_train_scaled, y_train_enc)
```
And in lines 418–438:
```python
metadata_v2 = {
    ...
    "feature_schema": FEATURE_NAMES_V2,
    "feature_count": len(FEATURE_NAMES_V2),
}
with open(meta_p, "w", encoding="utf-8") as f:
    json.dump(metadata_v2, f, indent=2)

with open(schema_p, "w", encoding="utf-8") as f:
    json.dump({"version": "v2", "feature_names": FEATURE_NAMES_V2, "count": len(FEATURE_NAMES_V2)}, f, indent=2)
```
**Observation:** The training pipeline fitted the `StandardScaler` and `XGBClassifier` directly on `df[FEATURE_NAMES_V2]`.

---

## 4. End-to-End Parity Matrix

| Feature Index | Training (`train_and_compare_v2.py`) | Model Metadata (`metadata.json`) | Schema Spec (`feature_schema.json`) | 500-Sample Benchmark (`run_phase10_xgb_benchmark.py`) | AWS Ingestion (`telemetry_normalizer.py`) | Live Inference Vector (`predict.py`) |
|:---:|:---|:---|:---|:---|:---|:---|
| **0** | `packet_count` | `packet_count` | `packet_count` | `packet_count` | `packet_count` | `packet_count` |
| **1** | `byte_count` | `byte_count` | `byte_count` | `byte_count` | `byte_count` | `byte_count` |
| **2** | `duration` | `duration` | `duration` | `duration` | `duration` | `duration` |
| **3** | `conn_rate` | `conn_rate` | `conn_rate` | `conn_rate` | `conn_rate` | `conn_rate` |
| **4** | `dst_port` | `dst_port` | `dst_port` | `dst_port` | `dst_port` | `dst_port` |
| **5** | `unique_dst_ports`| `unique_dst_ports`| `unique_dst_ports`| `unique_dst_ports`| `unique_dst_ports`| `unique_dst_ports`|
| **6** | `bytes_per_sec` | `bytes_per_sec` | `bytes_per_sec` | `bytes_per_sec` | `bytes_per_sec` | `bytes_per_sec` |
| **7** | `packets_per_sec` | `packets_per_sec` | `packets_per_sec` | `packets_per_sec` | `packets_per_sec` | `packets_per_sec` |
| **8** | `avg_packet_size` | `avg_packet_size` | `avg_packet_size` | `avg_packet_size` | `avg_packet_size` | `avg_packet_size` |

**Conclusion:** Every stage of the system evaluates the **identical 9 features in identical order**.

---

## 5. Investigation of the Discrepant Feature Schema

### The Discrepant Feature List:
`["duration", "src_bytes", "dst_bytes", "wrong_fragment", "urgent", "hot", "failed_logins", "num_compromised", "connection_rate"]`

### Forensic Investigation:
1. **Source of the Discrepant Names**:
   In classic intrusion detection benchmarks (specifically **KDD Cup 1999** and **NSL-KDD**), network connections were represented using 41 attributes categorized into:
   - Basic TCP connection features: `duration`, `protocol_type`, `service`, `flag`, `src_bytes`, `dst_bytes`, `land`, `wrong_fragment`, `urgent`.
   - Content / Host features: `hot`, `num_failed_logins`, `logged_in`, `num_compromised`, `root_shell`, `su_attempted`, `num_root`, `num_file_creations`, `num_shells`, `num_access_files`, `is_host_login`, `is_guest_login`.
   - Traffic / Window features: `count`, `srv_count`, etc.
   
   A subset of 9 numerical features from KDD/NSL-KDD frequently appears in academic papers and lab tutorials:
   `["duration", "src_bytes", "dst_bytes", "wrong_fragment", "urgent", "hot", "num_failed_logins", "num_compromised", "count/connection_rate"]`.

2. **Codebase Grep Results**:
   - `wrong_fragment`: 0 occurrences in `backend/*.py` or `ml/*.py`. Found only in 5 Markdown report files.
   - `hot`: 0 occurrences in Python source files.
   - `num_compromised`: 0 occurrences in Python source files.
   - `src_bytes`: 0 occurrences in Python source files.
   - `dst_bytes`: 0 occurrences in Python source files.

3. **Prior Forensic Acknowledgments in Repository**:
   This discrepancy was already audited and documented in two earlier reports:
   - `FINAL_STANDALONE_APPLICATION_READINESS_REPORT.md` (Section 2.3):
     > *"Diagnosis: An earlier milestone report documented NSL-KDD host-based features (src_bytes, dst_bytes, wrong_fragment, etc.) for XGBoost V2.*  
     > *Resolution: Verified that the serialized model ml/models/candidates/bigdata_v2/model.joblib and training schema feature_schema.json are trained on 9 network flow telemetry features: [packet_count, byte_count, duration, conn_rate, dst_port, unique_dst_ports, bytes_per_sec, packets_per_sec, avg_packet_size]."*
   - `XGBOOST_V2_FEATURE_SCHEMA_VERIFICATION.md` (Section 1):
     > *"An immediate audit of the physical model artifact (model.joblib), serialized preprocessor (scaler.joblib), and training schema metadata (feature_schema.json) confirms that the actual Big Data XGBoost V2 model was NEVER trained on NSL-KDD host features.*  
     > *The NSL-KDD list in the prior report was a documentation artifact from an early hybrid-lab prototype. The actual production code, normalizers, and serialized model checkpoints have consistently used 9 network flow telemetry features designed for real-time packet and flow inspection."*

4. **Why it Reappeared in Phase 12 Summary Prose**:
   In Phase 12 turn 11, the report author paraphrased canonical feature isolation by pasting the string from the older report narrative (`FINAL_AWS_LIVE_TELEMETRY_READINESS_REPORT.md`), even though the actual Phase 12 code edits in `telemetry_normalizer.py` and `test_phase12_aws_risk_attribution.py` strictly imported and tested `FEATURE_NAMES_V2`.

5. **Physical Impossibility in Cloud Telemetry**:
   AWS VPC Flow Logs (versions 2 through 5) capture layer 3/4 header metadata (`srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`, `packets`, `bytes`, `start`, `end`, `action`, `log-status`). They do not perform deep packet inspection (DPI) to count TCP urgent pointers (`urgent`), application-layer directory traversals (`hot`), or operating system privilege escalations (`num_compromised`). The 9 network flow features (`packet_count`, `byte_count`, `duration`, `conn_rate`, `dst_port`, `unique_dst_ports`, `bytes_per_sec`, `packets_per_sec`, `avg_packet_size`) are the only mathematically sound features observable from cloud flow logs.

---

## 6. Live Programmatic Proof of Parity

An automated execution in the project Python virtual environment confirmed:
```
1. feature_schema.json == FEATURE_NAMES_V2: True
2. metadata.json == FEATURE_NAMES_V2      : True
3. predictor.feature_schema == V2         : True
4. feat_dict keys == V2                   : True
5. Extracted vector shape                 : (1, 9)
6. Extracted vector feature names order   : ['packet_count', 'byte_count', 'duration', 'conn_rate', 'dst_port', 'unique_dst_ports', 'bytes_per_sec', 'packets_per_sec', 'avg_packet_size']
7. Extracted vector values                : [10.0, 1500.0, 2.0, 5.0, 443.0, 1.0, 750.0, 5.0, 150.0]
8. MLService.predict success              : BENIGN Risk: 0 Severity: LOW
```

---

## 7. Conclusion & Recommendation

1. **No Code or Model Discrepancy Exists**:
   All production code, training scripts, model artifacts, benchmarks, and normalizers are in 100% mutual alignment on the canonical 9-feature network telemetry schema.
2. **Zero Action Required on Code/Artifacts**:
   No code edits, retrainings, or executable rebuilds are necessary.
3. **Documentation Standard**:
   All future reports must exclusively cite the authoritative `FEATURE_NAMES_V2` list:
   `["packet_count", "byte_count", "duration", "conn_rate", "dst_port", "unique_dst_ports", "bytes_per_sec", "packets_per_sec", "avg_packet_size"]`.
