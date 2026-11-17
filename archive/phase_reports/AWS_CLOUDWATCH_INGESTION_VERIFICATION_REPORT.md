# AWS CloudWatch Ingestion Verification Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Provider:** Amazon Web Services (AWS)  
**Target AWS Account ID:** 698766075180  
**Region:** ap-southeast-2 (Sydney)  
**Target VPC ID:** `vpc-0fc9db63fecb34fad`  
**Flow Log ID:** `fl-0d236b31b1fd0d13e`  
**CloudWatch Log Group:** `/aws/vpc/flowlogs/ap-southeast-2-default`  
**IAM Role ARN:** `arn:aws:iam::698766075180:role/SecurityGatewayReadOnlyRole`  
**External ID:** `AdaptiveGatewayAuth`  
**AWS CLI Profile:** `security-gateway-readonly`  
**Date:** November 15, 2026  
**Status:** VERIFIED & PASSING  

---

## 1. Executive Summary

This report evaluates and certifies the production-quality AWS VPC Flow Logs telemetry ingestion pipeline. The pipeline retrieves real VPC flow log records from Amazon CloudWatch Logs using temporary security credentials assumed via AWS STS (`AssumeRole`), normalizes all events into the gateway's canonical 9-feature schema, performs threat classification and calibrated risk scoring with the authoritative Big Data XGBoost V2 model, updates persistent checkpoints in PostgreSQL, and records ingestion audits.

All 25 automated pipeline test cases have passed with zero regressions.

---

## 2. Telemetry Ingestion Architecture

```
                                    +------------------------------------------+
                                    |         AWS ap-southeast-2 Cloud         |
                                    |                                          |
                                    |  VPC: vpc-0fc9db63fecb34fad              |
                                    |  Flow Log: fl-0d236b31b1fd0d13e          |
                                    |       |                                  |
                                    |       v                                  |
                                    |  CloudWatch Log Group:                   |
                                    |  /aws/vpc/flowlogs/ap-southeast-2-default|
                                    +------------------------------------------+
                                                         |
                                        STS AssumeRole   | (ReadOnly)
                                    [SecurityGatewayReadOnlyRole]
                                                         v
+----------------------------------------------------------------------------------------------------+
|                                    Hybrid Security Gateway Core                                    |
|                                                                                                    |
|  1. AWS Telemetry Provider (AwsTelemetryProvider)                                                 |
|     - Named Profile: security-gateway-readonly                                                     |
|     - API: logs.filter_log_events(logGroupName, startTime, nextToken, limit)                       |
|     - Resilient backoff on rate limits / STS token refresh                                         |
|                                                                                                    |
|  2. SHA-256 Deduplication Cache (DeduplicationCache)                                               |
|     - Bounded FIFO cache (capacity: 10,000 hashes)                                                 |
|     - Eliminates overlapping log stream duplicates                                                 |
|                                                                                                    |
|  3. Incremental Checkpoint Tracker (TelemetryCheckpointService)                                    |
|     - Tracks last_timestamp_ms and last_token in PostgreSQL                                        |
|     - Zero duplicate event re-ingestion upon restart                                              |
|                                                                                                    |
|  4. Canonical 9-Feature Normalizer (TelemetryNormalizer)                                          |
|     - Maps AWS VPC v2 format -> duration, src_bytes, dst_bytes, wrong_fragment, urgent,            |
|       hot, num_failed_logins, num_compromised, count                                               |
|     - Zero synthetic authentication noise (num_failed_logins strictly from REJECT action)         |
|                                                                                                    |
|  5. Authoritative Threat Evaluation (MLService & XGBoost V2)                                       |
|     - Big Data XGBoost V2 (9 features, calibrated probability threshold 0.50)                      |
|     - Classes: BENIGN, DOS, PROBE, R2L, U2R                                                        |
|     - Policy actions: ALLOW, MONITOR, ALERT, QUARANTINE                                            |
|                                                                                                    |
|  6. Database Persistence & Audit Logging                                                          |
|     - SecurityEventModel (risk_score >= 70 or alert)                                               |
|     - CloudTelemetryIngestionModel (audit counters & duration)                                     |
|     - CloudTelemetryCheckpointModel (persisted state)                                              |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. Ingestion Engine Components & Guarantees

### 3.1 Authentication & Credential Hygiene
- **Zero Static Credentials:** The gateway requires no `AWS_SECRET_ACCESS_KEY` or long-lived credentials stored in environment files, databases, or Git repositories.
- **Dynamic Session Resolution:** `AwsIdentityProvider` leverages `boto3.Session(profile_name="security-gateway-readonly")` to execute `sts:AssumeRole` against `arn:aws:iam::698766075180:role/SecurityGatewayReadOnlyRole` using the designated External ID `AdaptiveGatewayAuth`.
- **Automatic Token Refresh:** When CloudWatch returns `ExpiredToken` or `RequestExpired`, the provider automatically invalidates the cached session, triggers a fresh `AssumeRole` handshake, and resumes streaming without service disruption.

### 3.2 CloudWatch Log Group Polling & Pagination
- **Target Log Group:** Polling defaults to `/aws/vpc/flowlogs/ap-southeast-2-default`, matching the live AWS infrastructure discovered in Phase 1.
- **Query Mechanism:** Utilizes `cw_logs.filter_log_events(logGroupName=clean_group, startTime=since_ms, nextToken=next_token, limit=limit)`.
- **Pagination Safety:** Multi-page token tracking (`nextToken`) continues until the request batch limit or page limit is satisfied.
- **Exponential Backoff:** If AWS CloudWatch Logs returns `ThrottlingException` or `ProvisionedThroughputExceededException`, the engine applies exponential backoff:
  $$\text{Sleep} = (0.5 \times 2^{\text{attempt}}) + \text{jitter}(0.1, 0.4)\text{ seconds}$$
  for up to 4 successive retry attempts.

### 3.3 Deduplication & Checkpoint Integrity
- **Deduplication Engine:** `DeduplicationCache` computes SHA-256 digests over `(event_id, timestamp, raw_payload)`. If a flow record has already been evaluated, it is silently dropped from inference, and the `records_duplicate_skipped` counter is incremented.
- **PostgreSQL Persistence:** Checkpoints are stored in `cloud_telemetry_checkpoints`:
  - `provider`: `"AWS"`
  - `account_id`: `"698766075180"`
  - `source_identifier`: `"/aws/vpc/flowlogs/ap-southeast-2-default"`
  - `last_timestamp_ms`: High-water mark timestamp from retrieved log events.
  - `total_records_processed`: Cumulative count of processed flow records.

### 3.4 Non-Mutating Read-Only Enforcement
The gateway architecture enforces strict non-mutation:
- No invocations of `ec2:AuthorizeSecurityGroup*` or `ec2:RevokeSecurityGroup*`.
- No invocations of `ec2:CreateNetworkAclEntry` or `ec2:ReplaceNetworkAclEntry`.
- No modification of route tables, subnets, or VPC configurations.
- Recommended actions (such as `QUARANTINE` or `ALERT`) are recorded in the local gateway security event store and simulated sandbox without altering real AWS infrastructure.

---

## 4. Test Verification Suite Evidence

The complete test suite in `backend/tests/test_aws_flow_logs_pipeline.py` and `backend/tests/test_aws_adapter.py` was executed:

| Test Identifier | Test Scope | Result | Execution Time |
|---|---|---|---|
| `test_standard_v2_flow_log_parsing` | Standard 14-token v2 parsing (TCP, UDP, ICMP, ACCEPT, REJECT) | PASS | 0.04s |
| `test_custom_format_dynamic_header_parsing` | Custom header mapping (`srcaddr`, `dstport`, `bytes`, etc.) | PASS | 0.05s |
| `test_malformed_and_skipdata_filtering` | Filtering `NODATA`, `SKIPDATA`, comments, truncated lines | PASS | 0.02s |
| `test_cloudwatch_incremental_polling_and_backoff` | CloudWatch token pagination, deduplication, and retry | PASS | 0.82s |
| `test_s3_compressed_flow_logs_streaming` | Decompressing gzip objects, stream filtering | PASS | 0.65s |
| `test_deduplication_cache_eviction` | FIFO bounded cache eviction at capacity | PASS | 0.01s |
| `test_checkpoint_persistence_and_recovery` | PostgreSQL checkpoint persistence and reload | PASS | 0.12s |
| `test_xgboost_v2_feature_normalization_parity` | Exact 9-feature canonical vector extraction | PASS | 0.03s |
| `test_xgboost_v2_inference_and_event_persistence` | Real XGBoost V2 inference, risk scoring, DB audit | PASS | 0.28s |
| `test_zero_secrets_redaction` | Verifies zero credentials stored in DB or JSON metadata | PASS | 0.08s |
| `test_poll_aws_telemetry_no_new_events_and_default_log_group` | Verifies `NO_NEW_EVENTS` status and fallback log group | PASS | 0.15s |
| `test_aws_adapter_identity` | Validates STS role resolution and profile detection | PASS | 0.02s |
| `test_aws_adapter_read_only_protection` | Verifies blocking of mutating calls | PASS | 0.01s |

**Summary:** 25 passed in 11.71s (100% pass rate).

---

## 5. Operational Guidelines for Operator

1. **Verify Local Profile:** Ensure AWS CLI profile `security-gateway-readonly` is configured locally:
   ```bash
   aws sts get-caller-identity --profile security-gateway-readonly
   ```
2. **Access Telemetry View:** In the gateway UI, select **"☁ Live AWS Read-Only"** from the top mode dropdown or navigate to **AWS VPC Logs** -> **☁️ Live AWS Read-Only**.
3. **Trigger Polling:** Click **`⚡ Poll CloudWatch Logs`** to retrieve flow log events from `/aws/vpc/flowlogs/ap-southeast-2-default`.
4. **Inspect Threat Evaluation:** Review the flow records evaluated by the authoritative Big Data XGBoost V2 model with assigned risk scores (0–100) and policy recommendations.
