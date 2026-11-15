# AWS TELEMETRY CANONICAL 9-FEATURE NORMALIZATION REPORT
## Feature Derivation, Mathematical Parity & Zero Synthetic Authentication Dependencies

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Engine:** Big Data XGBoost V2 (Authoritative Primary)  
**Schema Version:** `v2_canonical` (9 Features)  
**Status:** **MATHEMATICALLY VERIFIED & PRODUCTION READY**  

---

## 1. Executive Summary

During Phase 2 Big Data model auditing, an independent investigation revealed that earlier legacy iterations relied heavily on synthetic authentication failures (`failed_auth_count`), which constituted over 55% of the model's feature importance. While synthetic authentication failures may be observable on host authentication logs, they are physically impossible to extract from standard network flow telemetry (such as NetFlow, IPFIX, or AWS VPC Flow Logs).

Under this milestone, the AWS telemetry pipeline strictly enforces the canonical 9-feature schema (`FEATURE_NAMES_V2`). It guarantees that all network flows ingested from Amazon CloudWatch Logs and Amazon S3 are normalized with exact mathematical parity to training distributions without fabricating synthetic features or inferring authentication failures from L3/L4 packet headers.

---

## 2. The Canonical 9-Feature Schema

The authoritative XGBoost V2 model consumes exactly 9 features in order:

| Index | Feature Name | Data Type | Physical Meaning |
| :---: | :--- | :--- | :--- |
| `0` | `packet_count` | `float64` | Total packets observed in the flow session |
| `1` | `byte_count` | `float64` | Total bytes transferred in the session |
| `2` | `duration` | `float64` | Flow session duration in seconds |
| `3` | `conn_rate` | `float64` | Connection / packet velocity (packets per second) |
| `4` | `dst_port` | `float64` | Target network port (1–65535) |
| `5` | `unique_dst_ports` | `float64` | Distinct destination ports targeted by the source IP |
| `6` | `bytes_per_sec` | `float64` | Byte throughput velocity |
| `7` | `packets_per_sec` | `float64` | Packet transmission rate (identical to conn_rate) |
| `8` | `avg_packet_size` | `float64` | Average payload size per packet in bytes |

---

## 3. AWS VPC Flow Log Field Mapping

### 3.1 Standard Version 2 Tokens to Canonical Features
Standard AWS VPC Flow Log records provide 14 space-delimited fields:
$$\text{version} \quad \text{account-id} \quad \text{interface-id} \quad \text{srcaddr} \quad \text{dstaddr} \quad \text{srcport} \quad \text{dstport} \quad \text{protocol} \quad \text{packets} \quad \text{bytes} \quad \text{start} \quad \text{end} \quad \text{action} \quad \text{log-status}$$

| AWS Flow Log Token | Index | Canonical Target | Mathematical Formulation / Transformation |
| :--- | :---: | :--- | :--- |
| `packets` | `8` | `packet_count` | $\max(\text{int}(\text{packets}), 1)$ |
| `bytes` | `9` | `byte_count` | $\max(\text{int}(\text{bytes}), 64)$ |
| `start`, `end` | `10`, `11` | `duration` | $\max(\text{float}(\text{end} - \text{start}), 0.001)$ |
| `packets`, `duration` | `8`, `10-11` | `conn_rate` | $\frac{\text{packet\_count}}{\text{duration}}$ |
| `dstport` | `6` | `dst_port` | $\max(\min(\text{int}(\text{dstport}), 65535), 1)$ |
| `srcaddr`, `dstport` | `3`, `6` | `unique_dst_ports` | Stateful cardinality $|\{p \in \text{dst\_port} \mid \text{src\_ip} = s\}|$ |
| `bytes`, `duration` | `9`, `10-11` | `bytes_per_sec` | $\frac{\text{byte\_count}}{\text{duration}}$ |
| `packets`, `duration` | `8`, `10-11` | `packets_per_sec` | $\frac{\text{packet\_count}}{\text{duration}}$ |
| `bytes`, `packets` | `9`, `8` | `avg_packet_size` | $\frac{\text{byte\_count}}{\max(\text{packet\_count}, 1)}$ |

### 3.2 Handling Custom VPC Flow Log Formats
When AWS VPC Flow Logs are configured with custom formats, the order or selection of tokens changes (e.g. `${version} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${tcp-flags}`).

The normalizer reads format specifications via regex pattern `\$\{([^}]+)\}` and generates a dynamic index dictionary:
$$\text{field\_map} = \{ \text{token\_name}_i : i \}$$
This dynamically resolves `srcaddr`, `dstaddr`, `dstport`, `packets`, `bytes`, `start`, `end`, and extra context like `vpc_id` and `subnet_id` regardless of field positioning.

---

## 4. Rigorous Safeguards Against Synthetic Authentication

1. **Exclusion from Schema:**
   The feature schema `FEATURE_NAMES_V2` in `ml/features/extractor.py` has 9 elements. `failed_auth_count` does not exist in `FEATURE_NAMES_V2`.
2. **Explicit Zero Enforcement:**
   When converting telemetry records to internal prediction requests (`NetworkFlowRequest`), `failed_auth_count` is explicitly locked to `0`:
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
   ```
3. **No Heuristic Guesses:**
   The parser never guesses authentication failures based on port 22 or port 3389 activity or reject actions. Reject actions are classified as network-level policy drops (`action = "REJECT"`), not authentication events.

---

## 5. Verification & Mathematical Parity Test Evidence

Unit test `test_canonical_9_feature_normalization_parity` in `backend/tests/test_aws_flow_logs_pipeline.py` executes strict assertion checks against real AWS log syntax:
- Sample log line:
  `2 698766075180 eni-0123456789abcdef0 10.20.10.15 10.20.10.2 44321 443 6 45 38500 1763160000 1763160030 ACCEPT OK`
- Evaluated features:
  - `packet_count`: `45.0`
  - `byte_count`: `38500.0`
  - `duration`: `30.0`
  - `conn_rate`: `1.5`
  - `bytes_per_sec`: `1283.3333`
  - `packets_per_sec`: `1.5`
  - `avg_packet_size`: `855.5556`
  - `dst_port`: `443.0`
  - `unique_dst_ports`: `1.0`
- Result: **PASSED (Exact floating-point parity verified).**

