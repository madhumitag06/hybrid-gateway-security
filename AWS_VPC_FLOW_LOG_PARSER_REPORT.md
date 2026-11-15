# AWS VPC Flow Log Parser Implementation & Evaluation Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Specification:** AWS VPC Flow Logs (Version 2 Format & Custom Header Formats)  
**Modules Tested:**  
- `backend/app/cloud/adapters/aws/telemetry.py` (`AwsTelemetryProvider`)  
- `backend/app/services/aws_vpc_flow_parser.py` (`AwsVpcFlowParser`)  
- `backend/app/cloud/schemas/cloud_telemetry.py` (`CanonicalFlowRecord`)  
**Date:** November 15, 2026  
**Status:** VALIDATED & PRODUCTION READY  

---

## 1. Executive Summary

Network flow telemetry in AWS VPC environments is captured by AWS VPC Flow Logs, which can be published to Amazon CloudWatch Logs or Amazon S3. To evaluate incoming AWS telemetry with the gateway's authoritative Big Data XGBoost V2 machine learning model without introducing synthetic distortion, the gateway implements a robust, schema-compliant parser.

This report details the parsing engine specifications, field mappings, validation logic, malformed record filtering, protocol translation, and canonical record extraction.

---

## 2. Standard AWS VPC Flow Log Format (Version 2)

Standard Version 2 flow log records consist of 14 space-separated tokens adhering to the official AWS VPC Flow Logs schema:

$$\langle\text{version}\rangle\ \langle\text{account-id}\rangle\ \langle\text{interface-id}\rangle\ \langle\text{srcaddr}\rangle\ \langle\text{dstaddr}\rangle\ \langle\text{srcport}\rangle\ \langle\text{dstport}\rangle\ \langle\text{protocol}\rangle\ \langle\text{packets}\rangle\ \langle\text{bytes}\rangle\ \langle\text{start}\rangle\ \langle\text{end}\rangle\ \langle\text{action}\rangle\ \langle\text{log-status}\rangle$$

### 2.1 Field Mapping Specification

| Index | Field Token | AWS Data Type | Gateway Canonical Mapping | Description |
|---|---|---|---|---|
| 0 | `version` | Integer | `metadata["version"]` | Flow log schema version (must be 2). |
| 1 | `account-id` | String | `account_id` | AWS Account ID (e.g. `698766075180`). |
| 2 | `interface-id` | String | `interface_id` / `resource_id` | Elastic Network Interface (`eni-*`). |
| 3 | `srcaddr` | IPv4 / IPv6 | `src_ip` / `source_ip` | Source IP address of flow. |
| 4 | `dstaddr` | IPv4 / IPv6 | `dst_ip` / `destination_ip` | Destination IP address of flow. |
| 5 | `srcport` | Integer | `src_port` | Source transport port (0–65535). |
| 6 | `dstport` | Integer | `dst_port` | Destination transport port (0–65535). |
| 7 | `protocol` | Integer (IANA) | `protocol_number`, `protocol` | IANA protocol ID mapped to protocol name. |
| 8 | `packets` | Integer | `packet_count` | Number of packets transferred. |
| 9 | `bytes` | Integer | `byte_count` | Number of bytes transferred. |
| 10 | `start` | Epoch Seconds | `start_time` | Aggregation window start timestamp. |
| 11 | `end` | Epoch Seconds | `end_time` | Aggregation window end timestamp. |
| 12 | `action` | String | `action` | Security decision: `ACCEPT` or `REJECT`. |
| 13 | `log-status` | String | `log_status` | Status: `OK`, `NODATA`, `SKIPDATA`. |

---

## 3. Protocol Resolution & Normalization

AWS VPC Flow Logs record the transport protocol as an integer number matching the IANA protocol assignment. The parser normalizes numeric identifiers to standard uppercase naming:

```python
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}
```

If an unmapped protocol number is encountered, the parser safely defaults to `f"IP_PROTO_{num}"` to ensure uninterrupted ingestion.

---

## 4. Filtering & Anomaly Handling

The parser implements multi-stage filtering before constructing canonical records:

### 4.1 Rejection of AWS Pseudo-Events
- **`NODATA` Records:** Produced when no traffic crossed the network interface during the aggregation window. The parser discards these lines immediately, preventing artificial zeroes from entering ML feature calculation.
- **`SKIPDATA` Records:** Produced when AWS Flow Logs capacity exceeded limits. These lines are logged with diagnostic warnings and excluded from inference.
- **Comment and Empty Lines:** Lines starting with `#` or containing whitespace only are skipped.

### 4.2 Malformed Field Validation
Each token undergoes defensive type parsing:
- `packets` and `bytes` must be non-negative integers. Records with `"-"` (unknown) are safely defaulted to `1` packet and `64` bytes.
- `srcport` and `dstport` must be within valid range $[0, 65535]$.
- `duration`: Calculated as:
  $$\text{duration} = \max(\text{end} - \text{start}, 0.001)\text{ seconds}$$
  guaranteeing numerical stability during rate divisions.
- `conn_rate`, `bytes_per_sec`, and `packets_per_sec`:
  $$\text{bytes\_per\_sec} = \frac{\text{byte\_count}}{\text{duration}}, \quad \text{packets\_per\_sec} = \frac{\text{packet\_count}}{\text{duration}}$$

### 4.3 Flow Direction Classification
Flow direction is evaluated against configured network CIDRs:
- **`INGRESS`:** Traffic originating from external/untrusted CIDRs heading toward VPC private subnets.
- **`EGRESS`:** Traffic originating from VPC subnets heading outbound toward the Internet or external partners.
- **`CROSS_ZONE`:** Traffic crossing the hybrid on-premises to AWS Direct Connect / VPN boundary.
- **`INTERNAL_CLOUD`:** Traffic strictly intra-VPC between private subnets.

---

## 5. Custom Format Support (Dynamic Header Mapping)

In addition to standard v2 formatting, the parser supports AWS VPC Flow Logs configured with custom fields (e.g., including `tcp-flags`, `type`, `pkt-srcaddr`, `pkt-dstaddr`, `flow-direction`).

When custom logs with a header line are ingested, the parser dynamically resolves token positions:
```python
# Discovered Header:
# version account-id interface-id srcaddr dstaddr srcport dstport protocol bytes packets ...
header_tokens = [col.strip().lower() for col in header_line.split()]
field_map = {col: idx for idx, col in enumerate(header_tokens)}
```
Positional values are extracted according to `field_map`, providing full forward compatibility with custom CloudWatch or S3 flow log destinations.

---

## 6. Test Evidence & Validation Results

The parser test suite was executed in `backend/tests/test_aws_flow_logs_pipeline.py`:

```
============================== test session starts ==============================
backend/tests/test_aws_flow_logs_pipeline.py::test_standard_v2_flow_log_parsing PASSED
backend/tests/test_aws_flow_logs_pipeline.py::test_custom_format_dynamic_header_parsing PASSED
backend/tests/test_aws_flow_logs_pipeline.py::test_malformed_and_skipdata_filtering PASSED
backend/tests/test_aws_flow_logs_pipeline.py::test_xgboost_v2_feature_normalization_parity PASSED
============================== 4 passed in 0.24s ===============================
```

### Verified Scenarios:
1. **TCP Normal Traffic:** Correctly parses 14-token ACCEPT record into TCP flow record.
2. **UDP Traffic:** Correctly identifies UDP port 53 / 123 traffic with accurate byte and packet counts.
3. **ICMP Echo:** Correctly maps protocol `1` to `ICMP`, sets ports to 0, and preserves packet count.
4. **REJECT Action:** Correctly maps `REJECT` action, setting `num_failed_logins = 1` for the XGBoost V2 model.
5. **NODATA / SKIPDATA:** 100% of pseudo-events filtered without exceptions.
6. **Custom Header Reordering:** Dynamic column permutation successfully parsed into identical canonical vectors.
