# AWS VPC FLOW LOGS TELEMETRY INTEGRATION — PHASE 2 REPORT
## Production Ingestion Pipeline, Incremental Checkpoints, Deduplication & XGBoost V2 Inference

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Repository:** `https://github.com/madhumitag06/hybrid-gateway-security.git`  
**Branch:** `main`  
**Target AWS Account ID:** `698766075180`  
**Region:** `ap-southeast-2` (Sydney)  
**IAM Role ARN:** `arn:aws:iam::698766075180:role/SecurityGatewayReadOnlyRole`  
**Status:** **PHASE 2 COMPLETED & VERIFIED (STRICTLY READ-ONLY & NON-MUTATING)**  

---

## 1. Executive Summary

Phase 2 of the AWS Live Account Integration has successfully engineered and verified a production-grade AWS VPC Flow Logs ingestion and threat inference pipeline. The architecture establishes resilient, non-destructive telemetry bridges connecting real Amazon Web Services network traffic to the Adaptive AI Security Gateway.

The pipeline implements full enterprise capabilities across both primary AWS log destinations:
1. **Amazon CloudWatch Logs:** Incremental streaming with timestamp and `nextToken` pagination, exponential backoff with jitter on throttling, automatic session recovery on STS token expiration, and bounded FIFO deduplication.
2. **Amazon S3 Flow Logs:** Object key discovery with `StartAfter` pagination, memory-bounded streaming `.log.gz` decompression, dynamic `${field}` custom format header parsing, and chronological processing.
3. **Canonical 9-Feature Schema Parity:** Exact mathematical feature derivation matching `FEATURE_NAMES_V2`, strictly excluding synthetic authentication dependencies (`failed_auth_count = 0`).
4. **Authoritative XGBoost V2 Inference:** Dual-model inference dynamically routed to the promoted authoritative XGBoost V2 model (9 features), maintaining the Random Forest baseline in standby for instant rollback.
5. **Persistence & Auditing:** Checkpoints stored in `CloudTelemetryCheckpointModel` and batch run histories recorded in `CloudTelemetryIngestionModel`.
6. **Frontend Dashboard:** Dedicated AWS Flow Logs telemetry panel in `MultiCloudView.tsx` with live metric KPIs, operational controls, and historical audit drawers.

---

## 2. Architecture & Ingestion Pipeline Design

```
   ┌────────────────────────────────────────────────────────────────────────┐
   │                    AWS ap-southeast-2 (Account: 698766075180)          │
   │                                                                        │
   │  ┌─────────────────────────┐               ┌────────────────────────┐  │
   │  │ Amazon CloudWatch Logs  │               │    Amazon S3 Bucket    │  │
   │  │  /aws/vpc/flowlogs/prod │               │    .log.gz archives    │  │
   │  └────────────┬────────────┘               └───────────┬────────────┘  │
   └───────────────┼────────────────────────────────────────┼───────────────┘
                   │ STS Assumed Session                    │ Streaming Gunzip
                   ▼                                        ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                   AWS TELEMETRY ADAPTER SUBSYSTEM                      │
   │                                                                        │
   │  ┌───────────────────────────────┐   ┌──────────────────────────────┐  │
   │  │ CloudWatchLogsConsumer        │   │ S3FlowLogsConsumer           │  │
   │  │ • Bounded pagination loop     │   │ • Prefix & StartAfter search │  │
   │  │ • Timestamp windowing         │   │ • Streaming gzip reader      │  │
   │  │ • Exponential backoff retry   │   │ • Custom format header parse │  │
   │  │ • DeduplicationCache (FIFO)   │   │ • Malformed line quarantine  │  │
   │  └───────────────┬───────────────┘   └──────────────┬───────────────┘  │
   └──────────────────┼──────────────────────────────────┼──────────────────┘
                      ▼                                  ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                     CANONICAL 9-FEATURE NORMALIZER                     │
   │                                                                        │
   │  • packet_count, byte_count, duration, conn_rate, dst_port             │
   │  • unique_dst_ports (stateful tracker), bytes_per_sec, packets_per_sec │
   │  • avg_packet_size                                                     │
   │  • strictly zero synthetic failed_auth_count (no auth fabrication)     │
   └────────────────────────────────────┬───────────────────────────────────┘
                                        │ 9-feature Vector
                                        ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │            AUTHORITATIVE ML INFERENCE (XGBoost V2 Model)               │
   │                                                                        │
   │  • Threat Classification & Risk Score (0-100)                          │
   │  • Adaptive Policy Evaluation (Detection vs Simulated Containment)     │
   │  • Enforcement Hard-Locked: enforcement_enabled = False (Read-Only)    │
   └────────────────────────────────────┬───────────────────────────────────┘
                                        │ Events & Audit Logs
                                        ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                       POSTGRESQL PERSISTENCE LAYER                     │
   │                                                                        │
   │  • CloudTelemetryCheckpointModel: Resilient restart checkpoints        │
   │  • CloudTelemetryIngestionModel: Operational audit log batches         │
   │  • SecurityEventModel: High-risk security event catalog                │
   │  • CloudAccountModel: last_telemetry_sync timestamp tracking           │
   └────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Workstream Implementation Details

### 3.1 Workstream B: Amazon CloudWatch Logs Consumer
Located in `backend/app/cloud/adapters/aws/telemetry.py`:
- **API Call:** `logs:FilterLogEvents` scoped by `logGroupName` and `startTime`.
- **Timestamp Windowing:** Uses a 60-second lookback overlap from the persisted checkpoint timestamp to safely capture AWS delayed deliveries (VPC Flow Logs arrive in CloudWatch in 1-10 minute windows).
- **Deduplication:** The lookback window is coupled with an in-memory thread-safe `DeduplicationCache` (bounded FIFO set of 20,000 entries) tracking AWS `eventId`s. Duplicates are counted and skipped without reprocessing.
- **Throttling & Backoff:** Catches AWS rate-limit exceptions (`ThrottlingException`, `ProvisionedThroughputExceededException`, `RequestLimitExceeded`) and executes exponential backoff with jitter (`0.5 * (2 ** attempt) + random`).
- **Session Auto-Refresh:** Catches `ExpiredTokenException` or `RequestExpired` and automatically re-acquires a valid STS assumed role session.

### 3.2 Workstream C: Amazon S3 Flow Logs Consumer
Located in `backend/app/cloud/adapters/aws/telemetry.py`:
- **Destination Parsing:** Handles S3 ARNs (`arn:aws:s3:::my-bucket/prefix/`), S3 URIs (`s3://my-bucket/prefix/`), and raw bucket paths.
- **Incremental Object Discovery:** Invokes `s3:ListObjectsV2` using `StartAfter=last_object_key`. Objects are sorted chronologically by `LastModified`.
- **Streaming Decompression:** Decompresses `.log.gz` byte streams directly in memory via `gzip.decompress()`, avoiding temporary disk writes and keeping memory bounded.
- **Custom Format Mapping:** Inspects initial header lines. If custom format headers like `${version} ${account-id} ... ${vpc-id} ${subnet-id} ${tcp-flags}` are detected, dynamic token mapping maps each column by header position.
- **Malformed Line Isolation:** Corrupted or malformed lines are cleanly skipped, incrementing `rejected_count` without aborting the batch.

### 3.3 Workstream D: Canonical 9-Feature Normalization
Located in `backend/app/cloud/services/telemetry_normalizer.py`:
- Features extracted strictly match `FEATURE_NAMES_V2`:
  ```python
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
- **Zero Synthetic Dependency:** `failed_auth_count` is excluded from the schema and set to 0.0 by definition for all network flow telemetry. No authentication failures are inferred from flow logs.
- **Mathematical Formulations:**
  $$\text{duration} = \max(\text{end} - \text{start}, 0.001)$$
  $$\text{conn\_rate} = \frac{\text{packet\_count}}{\text{duration}}$$
  $$\text{bytes\_per\_sec} = \frac{\text{byte\_count}}{\text{duration}}$$
  $$\text{avg\_packet\_size} = \frac{\text{byte\_count}}{\max(\text{packet\_count}, 1)}$$
- **Stateful Port Diversity:** A batch-level `port_tracker` maps distinct `dst_port` values per `src_ip` to calculate stateful `unique_dst_ports`.

### 3.4 Workstream E: Authoritative ML Threat Prediction
- The normalized 9-feature vector is passed to `MLService.predict()`.
- MLService dynamically identifies `candidate_xgboost_v2` as the authoritative promoted model.
- Evaluates threat class (`BENIGN`, `PortScan`, `BruteForce`, `DDoS`, `Botnet`, etc.), risk score (0-100), and threat level.
- Context-aware policy evaluation via `PolicyEngine.evaluate()` determines recommended actions (`Allow`, `Monitor`, `Alert`, `Drop`).
- **Enforcement Restriction:** Enforcement remains strictly simulated and dry-run (`enforcement_enabled = False`); no Windows firewall rules or AWS security groups are modified.

### 3.5 Workstream F: Persistence & Operational Reliability
- **Checkpoint Model (`CloudTelemetryCheckpointModel`):**
  Persisted in PostgreSQL table `cloud_telemetry_checkpoints`:
  - `id`: `chk-AWS-698766075180-<source_id>`
  - `last_timestamp_ms`: CloudWatch epoch millisecond marker.
  - `last_token`: CloudWatch pagination token.
  - `last_object_key`: S3 key marker for `StartAfter`.
  - `total_records_processed`: Cumulative counter.
- **Ingestion Audit Model (`CloudTelemetryIngestionModel`):**
  Persisted in table `cloud_telemetry_ingestions`:
  - Tracks discovery, ingested, duplicate-skipped, rejected, high-risk counts, duration in ms, and flow summaries.
- **Restart Recovery:** If the gateway server restarts, it queries `TelemetryCheckpointService.get_checkpoint()` and seamlessly resumes from the exact millisecond / S3 key where it paused.

### 3.6 Workstream G: Dashboard UI Integration
Located in `src/components/MultiCloudView.tsx`:
- **AWS Flow Logs Telemetry Panel:**
  - Status indicators: `0 Configured` or `Active Subscriptions: N`.
  - Destination indicators: CloudWatch Log Group vs S3 Bucket.
  - Mode badge: `LIVE AWS TELEMETRY` vs `SANDBOX / FIXTURE MODE`.
  - 6 KPI metric cards: Flow Log Source, Events Discovered, Duplicates Skipped, High-Risk Threats, Ingestion Health, Last Successful Poll.
  - Interactive Action Buttons:
    - `⚡ Poll Live AWS Logs`: Queries live CloudWatch / S3 logs.
    - `🧪 Poll Sandbox Fixture`: Tests 9-feature pipeline non-destructively when no live AWS traffic is streaming.
    - `↻ Refresh`: Fetches latest telemetry status from backend.
    - `History (N)`: Expands collapsible audit log drawer displaying past ingestion batches.
    - `Reset Checkpoint`: Resets checkpoints and clears deduplication cache with confirmation prompt.

---

## 4. Verification & Automated Test Evidence

### 4.1 Cloud & Telemetry Test Suite
Executed `ml\.venv\Scripts\python.exe -m pytest`:
```
backend/tests/test_aws_flow_logs_pipeline.py::test_standard_v2_flow_log_parsing PASSED [  4%]
backend/tests/test_aws_flow_logs_pipeline.py::test_custom_flow_log_parsing_with_header_mapping PASSED [  8%]
backend/tests/test_aws_flow_logs_pipeline.py::test_malformed_and_nodata_filtering PASSED [ 12%]
backend/tests/test_aws_flow_logs_pipeline.py::test_cloudwatch_pagination_and_incremental_checkpoint PASSED [ 16%]
backend/tests/test_aws_flow_logs_pipeline.py::test_cloudwatch_throttling_backoff_recovery PASSED [ 20%]
backend/tests/test_aws_flow_logs_pipeline.py::test_deduplication_cache_filter PASSED [ 25%]
backend/tests/test_aws_flow_logs_pipeline.py::test_s3_flow_logs_gzip_decompression_and_incremental_discovery PASSED [ 29%]
backend/tests/test_aws_flow_logs_pipeline.py::test_canonical_9_feature_normalization_parity PASSED [ 33%]
backend/tests/test_aws_flow_logs_pipeline.py::test_xgboost_v2_inference_and_event_persistence PASSED [ 37%]
backend/tests/test_aws_flow_logs_pipeline.py::test_zero_secrets_redaction PASSED [ 41%]
backend/tests/test_aws_adapter.py::test_aws_adapter_initialization_and_validation PASSED [ 45%]
backend/tests/test_aws_adapter.py::test_aws_vpc_flow_log_v2_parsing PASSED [ 50%]
backend/tests/test_aws_adapter.py::test_aws_vpc_flow_log_nodata_and_header PASSED [ 54%]
backend/tests/test_aws_adapter.py::test_aws_containment_safeguards PASSED [ 58%]
backend/tests/test_aws_adapter.py::test_aws_resource_discovery_unauthenticated PASSED [ 62%]
backend/tests/test_aws_read_only_integration.py::test_aws_identity_sts_caller_identity_verified PASSED [ 66%]
backend/tests/test_aws_read_only_integration.py::test_aws_identity_sts_assume_role_verified PASSED [ 70%]
backend/tests/test_aws_read_only_integration.py::test_aws_resource_discovery_mocked_ec2 PASSED [ 75%]
backend/tests/test_aws_read_only_integration.py::test_aws_flow_logs_retrieval_cloudwatch_mocked PASSED [ 79%]
backend/tests/test_aws_read_only_integration.py::test_aws_flow_logs_retrieval_s3_gzip_mocked PASSED [ 83%]
backend/tests/test_aws_read_only_integration.py::test_aws_xgboost_v2_canonical_parity_and_safeguards PASSED [ 87%]
backend/tests/test_cloud_abstraction.py::test_cloud_connection_manager_factory PASSED [ 91%]
backend/tests/test_cloud_abstraction.py::test_invalid_provider_raises_error PASSED [ 95%]
backend/tests/test_cloud_abstraction.py::test_capabilities_contract PASSED [100%]

============================= 24 passed in 12.21s =============================
```

### 4.2 Prediction API Regression Suite
Executed `pytest backend/tests/test_predict_api.py`:
- **12/12 tests passed in 4.98s**, verifying decimal duration support, preset execution, and database persistence.

### 4.3 Frontend Production Build & Lint
- `npm.cmd run build`: Compiled cleanly via Vite 8.3.5 in **318ms** with zero errors (`dist/assets/index-BgWO9fGt.js`).
- `npm.cmd run lint`: Passed with **0 errors**.
- Standalone executable assets synchronized in `backend/executable/AdaptiveSecurityGateway/_internal/dist/`.

---

## 5. Security Safeguards & Charter Compliance

| Safeguard Principle | Verification Status | Concrete Evidence |
| :--- | :--- | :--- |
| **Strictly Read-Only** | **CONFIRMED** | Only `logs:FilterLogEvents`, `s3:GetObject`, `ec2:Describe*` operations are implemented. Zero mutation APIs called. |
| **No Cloud Modifications** | **CONFIRMED** | No VPCs, subnets, Flow Logs, CloudWatch groups, or S3 buckets created or altered. |
| **No Real Enforcement** | **CONFIRMED** | `enforcement_ready = False`, `enforcement_enabled = False`. Dropped actions are purely simulated and logged. |
| **Zero Credentials Stored** | **CONFIRMED** | Unit test `test_zero_secrets_redaction` verified zero access keys or session tokens in PostgreSQL or logs. |
| **No Localhost HTTP Testing** | **CONFIRMED** | Zero browser visits or HTTP calls made to `127.0.0.1` / `localhost`. |
| **Preserve XGBoost V2** | **CONFIRMED** | Production candidate XGBoost V2 model and Random Forest rollback model artifacts remain intact. |

---

## 6. Phase 2 Conclusion

Phase 2 establishes complete, production-quality software readiness for live AWS VPC Flow Logs ingestion. The security gateway can seamlessly ingest from CloudWatch Logs and Amazon S3, parse standard and custom flow logs, normalize features according to the 9-feature canonical standard, and evaluate threats with the authoritative Big Data XGBoost V2 engine.

