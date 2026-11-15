# AWS VPC Flow Log Ingestion & Normalization Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Provider:** Amazon Web Services (AWS)  
**Component:** `AwsTelemetryProvider`  
**Date:** November 15, 2026  

---

## 1. Overview & Telemetry Architecture

AWS VPC Flow Logs capture IP traffic going to and from network interfaces in your VPC. The `AwsTelemetryProvider` ingests these records directly from either **Amazon CloudWatch Logs** or **Amazon S3** buckets, parses the standard Version 2 schema, and transforms them into `CanonicalFlowRecord` objects.

```
┌────────────────────────────────────────────────────────┐
│ Target AWS Account                                     │
│ ├── CloudWatch Logs Group: /aws/vpc/flowlogs           │
│ └── S3 Bucket: s3://my-vpc-flowlogs/AWSLogs/.../*.gz   │
└───────────────────────────┬────────────────────────────┘
                            │
                            │ 1. logs:FilterLogEvents / s3:GetObject
                            ▼
┌────────────────────────────────────────────────────────┐
│ AwsTelemetryProvider                                   │
│ ├── Decompresses .log.gz archives (gzip)               │
│ ├── Filters headers, comments, NODATA & SKIPDATA lines │
│ ├── Computes duration, throughput, and packet rates    │
│ ├── Classifies flow direction (INGRESS/EGRESS/INTERNAL)│
│ └── Emits CanonicalFlowRecord (failed_auth_count = 0)  │
└───────────────────────────┬────────────────────────────┘
                            │
                            │ 2. CanonicalFlowRecord Batch
                            ▼
┌────────────────────────────────────────────────────────┐
│ TelemetryNormalizer                                    │
│ └── Extracts Authoritative 9-Feature Schema            │
└───────────────────────────┬────────────────────────────┘
                            │
                            │ 3. 9-Feature Vector
                            ▼
┌────────────────────────────────────────────────────────┐
│ Authoritative Big Data XGBoost V2 Model                │
│ ├── Threat Classification & Risk Scoring (0 - 100)     │
│ ├── Contextual Policy Evaluation                       │
│ └── PostgreSQL Security Event Persistence              │
└────────────────────────────────────────────────────────┘
```

---

## 2. Standard VPC Flow Log Format (Version 2)

The parser expects the standard space-delimited AWS Version 2 format:

```
version account_id interface_id srcaddr dstaddr srcport dstport protocol packets bytes start end action log_status
```

### Field Breakdown:
1. `version`: Format version (`2`).
2. `account_id`: 12-digit AWS account ID.
3. `interface_id`: Elastic Network Interface ID (`eni-xxxxxxxx`).
4. `srcaddr`: Source IPv4/IPv6 address.
5. `dstaddr`: Destination IPv4/IPv6 address.
6. `srcport`: Source port (`0-65535`).
7. `dstport`: Destination port (`0-65535`).
8. `protocol`: IANA protocol number (`6` for TCP, `17` for UDP, `1` for ICMP).
9. `packets`: Total packet count during aggregation window.
10. `bytes`: Total byte count during aggregation window.
11. `start`: Aggregation window start timestamp (Unix epoch seconds).
12. `end`: Aggregation window end timestamp (Unix epoch seconds).
13. `action`: Security decision (`ACCEPT` or `REJECT`).
14. `log_status`: Record status (`OK`, `NODATA`, or `SKIPDATA`).

---

## 3. Parsing & Filtering Rules

The parser enforces strict data integrity rules:
- **Headers & Comments:** Lines beginning with `version` or `#` are discarded.
- **Data Absence:** Lines containing `NODATA` (no traffic during interval) or `SKIPDATA` (records dropped due to internal AWS capacity) are safely ignored.
- **Unavailable Fields:** Any field set to `-` is defaulted safely (e.g., port defaults to `0`, packet count defaults to `1`).
- **Mathematical Integrity:**
  $$\text{duration} = \max(\text{end} - \text{start}, 0.001)$$
  $$\text{conn\_rate} = \frac{\text{packet\_count}}{\text{duration}}$$
  $$\text{bytes\_per\_sec} = \frac{\text{byte\_count}}{\text{duration}}$$
  $$\text{packets\_per\_sec} = \text{conn\_rate}$$
  $$\text{avg\_packet\_size} = \frac{\text{byte\_count}}{\max(\text{packet\_count}, 1)}$$
- **Traffic Direction Classification:**
  - `INTERNAL`: Both source and destination addresses reside within RFC 1918 private subnets.
  - `INGRESS`: Source is public / external; destination is private VPC subnet.
  - `EGRESS`: Source is private VPC subnet; destination is external.
  - `CROSS_ZONE`: Cross-zone or inter-VPC traffic.

---

## 4. Verification Test Results

Two dedicated unit tests verified both CloudWatch Logs and S3 retrieval modes:

1. **CloudWatch Logs Retrieval (`test_aws_flow_logs_retrieval_cloudwatch_mocked`):**
   - Simulated `logs:FilterLogEvents` with active log events.
   - Parsed TCP HTTPS traffic (`10.0.1.50 -> 10.0.1.10:443`, 100 packets, 85,000 bytes, `ACCEPT`).
   - Parsed SSH Reconnaissance traffic (`198.51.100.25 -> 10.0.1.10:22`, 25 packets, 1,800 bytes, `REJECT`, `INGRESS`).

2. **Amazon S3 Retrieval with Decompression (`test_aws_flow_logs_retrieval_s3_gzip_mocked`):**
   - Simulated `s3:ListObjectsV2` and `s3:GetObject` on `*.log.gz` object.
   - Dynamically decompressed archive in memory using `gzip.decompress()`.
   - Correctly skipped the header line and parsed HTTP flow (`10.0.2.100 -> 10.0.2.5:80`, 30 packets, 24,000 bytes, duration 20s).

