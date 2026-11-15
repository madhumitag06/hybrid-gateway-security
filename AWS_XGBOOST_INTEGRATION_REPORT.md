# AWS Telemetry & Authoritative XGBoost V2 ML Integration Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Authoritative Model:** Big Data XGBoost V2 (`ml/models/candidates/bigdata_v2/`)  
**Feature Schema Version:** `v2_canonical` (9 Features)  
**Date:** November 15, 2026  

---

## 1. Feature Parity & Schema Definition

The security gateway processes real AWS VPC Flow Logs strictly through the authoritative **9-feature schema** established in Phase 2. This resolves the feature integrity issues of legacy models by eliminating synthetic authentication features (`failed_auth_count = 0` by definition for network flow records).

### Authoritative 9-Feature Schema Order:
1. `packet_count` ($float$): Total packet count in the flow interval.
2. `byte_count` ($float$): Total byte count in the flow interval.
3. `duration` ($float$): Flow duration in seconds ($\ge 0.001$).
4. `conn_rate` ($float$): $\frac{\text{packet\_count}}{\text{duration}}$.
5. `dst_port` ($float$): Target service port ($1 - 65535$).
6. `unique_dst_ports` ($float$): Number of distinct destination ports contacted by source IP.
7. `bytes_per_sec` ($float$): $\frac{\text{byte\_count}}{\text{duration}}$.
8. `packets_per_sec` ($float$): $\frac{\text{packet\_count}}{\text{duration}}$.
9. `avg_packet_size` ($float$): $\frac{\text{byte\_count}}{\text{packet\_count}}$.

---

## 2. End-to-End Inference Workflow

```
┌─────────────────────────────────────────┐
│ Raw AWS VPC Flow Log Record             │
│ "2 123456789012 eni-01 ... 445 6 120 .."│
└────────────────────┬────────────────────┘
                     │
                     │ 1. AwsTelemetryProvider.parse_raw_log_record()
                     ▼
┌─────────────────────────────────────────┐
│ CanonicalFlowRecord                     │
│ (src_ip, dst_ip, ports, proto, metrics) │
└────────────────────┬────────────────────┘
                     │
                     │ 2. TelemetryNormalizer.normalize_flow_record()
                     ▼
┌─────────────────────────────────────────┐
│ Canonical 9-Feature Vector              │
│ - Exact FEATURE_NAMES_V2 Order          │
│ - Zero synthetic failed_auth_count      │
│ - Stateful unique_dst_ports tracking    │
└────────────────────┬────────────────────┘
                     │
                     │ 3. MLService.predict()
                     ▼
┌─────────────────────────────────────────┐
│ Big Data XGBoost V2 Model               │
│ - Primary Authoritative Model           │
│ - Outputs Attack Type, Risk Score,      │
│   Confidence & Threat Level             │
└────────────────────┬────────────────────┘
                     │
                     │ 4. PolicyEngine.evaluate()
                     ▼
┌─────────────────────────────────────────┐
│ Policy Evaluation (Safe Read-Only)      │
│ - Policy Action: MONITOR / DROP / BLOCK │
│ - Dry-run / Safeguard: REAL ENFORCEMENT │
│   STRICTLY DISABLED FOR AWS CLOUD       │
└────────────────────┬────────────────────┘
                     │
                     │ 5. Database Persistence
                     ▼
┌─────────────────────────────────────────┐
│ PostgreSQL (SecurityEventModel)         │
│ - Ingested flows, risk scores, labels   │
└─────────────────────────────────────────┘
```

---

## 3. Verification Test Evidence

The integration was verified by `test_aws_read_only_integration.py::test_aws_xgboost_v2_canonical_parity_and_safeguards`:

### Test Input:
```
2 123456789012 eni-0123456789abcdef0 198.51.100.77 10.0.1.15 48123 445 6 120 96000 1763163000 1763163015 ACCEPT OK
```

### Extracted 9-Feature Values:
| Feature Name | Extracted Value | Verification Assertion |
| :--- | :--- | :--- |
| `packet_count` | `120.0` | Exact match |
| `byte_count` | `96000.0` | Exact match |
| `duration` | `15.0` | $1763163015 - 1763163000 = 15.0$ |
| `conn_rate` | `8.0` | $120.0 / 15.0 = 8.0$ |
| `dst_port` | `445.0` | Target SMB port |
| `unique_dst_ports` | `1.0` | Stateful single target |
| `bytes_per_sec` | `6400.0` | $96000.0 / 15.0 = 6400.0$ |
| `packets_per_sec` | `8.0` | $120.0 / 15.0 = 8.0$ |
| `avg_packet_size` | `800.0` | $96000.0 / 120.0 = 800.0$ |

### Model Inference Output:
- **Provider:** `AWS`
- **Target Interface:** `eni-0123456789abcdef0`
- **Model Invoked:** XGBoost V2 Authoritative
- **Prediction Status:** `SUCCESS`
- **Threat Level:** Classified (`BENIGN` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`)
- **Normalization Report Provenance:**
  - `schema_version`: `v2_canonical`
  - `failed_auth_synthesized`: `False` (Strictly clean)
  - `features_extracted`: `["packet_count", "byte_count", "duration", "conn_rate", "dst_port", "unique_dst_ports", "bytes_per_sec", "packets_per_sec", "avg_packet_size"]`

---

## 4. Enforcement Safeguards for Cloud Infrastructure

In accordance with strict safety requirements:
1. **Zero Cloud Infrastructure Mutations:** The adapter does not call `ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress`, `ec2:CreateNetworkAclEntry`, or `ec2:DeleteNetworkAclEntry` on real AWS infrastructure.
2. **Read-Only Containment Provider:** `AwsEnforcementProvider` is initialized with `enabled=False` and all containment actions operate strictly in `dry_run=True` simulated mode.
3. **Simulated Hybrid Lab Isolation:** The Docker hybrid-lab containment remains fully operational and distinct from cloud adapters.

