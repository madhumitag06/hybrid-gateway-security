# PHASE 17 — WORKSTREAMS D, E, F: RELEASE INTEGRITY & REGRESSION AUDIT REPORT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `https://github.com/madhumitag06/hybrid-gateway-security.git`  
**Branch:** `main` (Commit `af3b640e1b9f7a924dd0bafac78ab2f8b24676dd`)  
**Audit Mode:** STRICT READ-ONLY FORENSIC INVESTIGATION  
**Audit Date:** November 16, 2026  

---

## 1. Executive Summary & Verification Matrix

| Workstream | Inspection Target | Verification Criteria | Status / Forensic Hash |
| :--- | :--- | :--- | :--- |
| **Workstream D** | Phase 16 Port Scan Remediation | 60 ports preserved, directed 5-tuple | **PASS (10/10 tests pass)** |
| **Workstream D** | Canonical Feature Schema | Exact 9 features in canonical order | **PASS (`FEATURE_NAMES_V2`)** |
| **Workstream D** | Feature Vector Purity | Absence of `failed_auth_count` | **PASS (Verified 0% presence)** |
| **Workstream D** | Active Model Registry | `candidate_xgboost_v2` authoritative | **PASS** |
| **Workstream E** | Executable Binary | `AdaptiveSecurityGateway.exe` execution | **PASS (`API v1.0.0`)** |
| **Workstream E** | Executable Size & Hash | Integrity verification | **37,874,457 bytes / SHA-256 Validated** |
| **Workstream E** | Bundled UI Assets | Parity with `dist/assets` | **PASS (Byte-for-byte SHA-256 match)** |
| **Workstream F** | Git Branch & Remote | `main` synchronized with `origin/main` | **PASS (Zero diff, clean working tree)** |
| **Overall Release Integrity** | Master Package Validation | Full production baseline intact | **PASS** |

---

## 2. Workstream D: Phase 16 Aggregation & Model Parity Verification

### A. Directed Service 5-Tuple Aggregation Key
In `backend/app/services/aws_vpc_flow_parser.py` (lines 35–42):
```python
@dataclass
class FlowGroupKey:
    interface_id: str
    src_addr: str
    dst_addr: str
    dst_port: int
    protocol: int
```
- Multi-destination port sweeps (such as the 60-port reconnaissance fixture) are now partitioned by `dst_port`.
- All 60 individual destination ports (21, 22, 23, 24, 25, etc.) are individually preserved into 60 distinct flow records instead of being squashed into a single flow.

### B. Temporal Tracking Parity via `HostPortTracker`
- In `backend/app/services/aws_vpc_flow_parser.py`:
  - `HostPortTracker` maintains a 60-second sliding window per source IP.
  - As each flow arrives, the cumulative count of unique destination ports scanned within the last 60 seconds is assigned to `unique_dst_ports`.
  - For `192.168.10.55`, `unique_dst_ports` elevates from 1 to 60 as ports are probed.
  - This elevated `unique_dst_ports` feature drives model confidence to **68.83%**, naturally elevating threat level to `HIGH` and triggering `Block` under `RECON_PORT_SCAN_QUARANTINE`.

### C. Canonical Nine-Feature Schema Integrity
Feature schema verified against `ml/models/candidates/bigdata_v2/feature_schema.json` and `ml/features/extractor.py`:
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
- **Integrity Check:** The 9 features and their exact order are strictly identical across:
  1. `FEATURE_NAMES_V2` in `ml/features/extractor.py`.
  2. Model metadata in `ml/models/candidates/bigdata_v2/feature_schema.json`.
  3. `MLService.predict` feature extraction.
  4. `TelemetryNormalizer.normalize_flow_features`.
  5. `AwsVpcFlowParser._process_parsed_records`.
- **Exclusion of `failed_auth_count`:**
  - `failed_auth_count` is confirmed absent from `FEATURE_NAMES_V2`.
  - In `SecurityEventModel.flow_features`, `failed_auth_count` is only stored as an auxiliary descriptive metadata field for legacy display compatibility and is never passed to the XGBoost V2 input array.

### D. Automated Test Suite Execution
Executed offline test suite:
```
ml\.venv\Scripts\python.exe -m pytest backend/tests/test_phase16_destination_port_remediation.py
============================= 10 passed in 3.19s ==============================
```
All 10 regression tests pass with 0 warnings or failures.

---

## 3. Workstream E: Standalone Executable Release Integrity

### A. Executable Specifications
- **Target File:** `backend\executable\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe`
- **File Size:** `37,874,457 bytes`
- **Last Modified Timestamp:** `16-11-2026 02:19:33`
- **SHA-256 Checksum:**  
  `16DDF219CEF2D170321B800B6A90B77458B30EB71B933315DC7D0D70B4C5BD5C`

### B. Executable Self-Verification
Executed:
```powershell
backend\executable\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe --version
```
**Output:**
```
Adaptive AI Hybrid Security Gateway API v1.0.0
```
Exit code: `0` (Success).

### C. Bundled Frontend Assets Parity
Compared bundled assets in `backend\executable\AdaptiveSecurityGateway\_internal\dist\assets` with source distribution `dist\assets`:

| Asset File | Source Hash (`dist/assets`) | Bundled Executable Hash (`_internal/...`) | Parity Status |
| :--- | :--- | :--- | :--- |
| **`index-cx_lTkpC.js`** | `8C0A1AB5EF55E814EBBDC2C42D4783FE0527C91930583AC00CFA0349C8BAFB54` | `8C0A1AB5EF55E814EBBDC2C42D4783FE0527C91930583AC00CFA0349C8BAFB54` | **100% Match** |
| **`index-DgMRxSro.css`** | `EFD47A75C020F540032A014E070013C8C3E57D32527B3F704969C04A590B91AF` | `EFD47A75C020F540032A014E070013C8C3E57D32527B3F704969C04A590B91AF` | **100% Match** |

---

## 4. Workstream F: GitHub Remote Synchronization

Executed forensic git commands:
- `git status`:
  ```
  On branch main
  Your branch is up to date with 'origin/main'.
  nothing to commit, working tree clean
  ```
- `git log -1 --oneline`:
  ```
  af3b640 feat(aws): remediate destination-port aggregation in AwsVpcFlowParser and add Phase 16 regression suite
  ```
- `git diff origin/main`: Output empty (0 unpushed lines, 0 divergent commits).

---

## 5. Workstreams D, E, F Conclusion

The codebase, model schema, regression test suite, standalone executable, bundled assets, and GitHub remote repository are synchronized, verified, and in full release readiness.
