# Cloud Telemetry Normalization & 9-Feature Parity Specification

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Engine:** `TelemetryNormalizer` (`backend/app/cloud/services/telemetry_normalizer.py`)  
**Target ML Model:** Authoritative XGBoost V2 (`ml/models/candidates/bigdata_v2/`)  
**Schema Version:** `v2_canonical` (9 features)  

---

## 1. Background & Audit Justification

During the comprehensive Big Data ML training audit, a critical flaw was identified in the legacy Phase 1 Random Forest baseline: **synthetic `failed_auth_count` accounted for 55.46% of model feature importance**, despite being an application-layer attribute completely unobservable in standard layer 3/layer 4 network flow logs.

Network flow logs from AWS VPC Flow Logs, GCP Cloud Logging, Azure Network Watcher, and router forwarding planes **do not contain authentication handshake records**. Fabricating or guessing `failed_auth_count` creates severe train/inference skew and degrades real-world intrusion detection.

Consequently, XGBoost V2 was trained on 6.49M real network intrusion records using a clean, mathematically rigorous 9-feature schema with zero dependence on synthetic authentication data.

---

## 2. Canonical 9-Feature Schema Reference

The 9 canonical features defined in `ml.features.extractor.FEATURE_NAMES_V2` are:

```python
FEATURE_NAMES_V2 = [
    "packet_count",     # Total packet count observed in session
    "byte_count",       # Total payload bytes transferred
    "duration",         # Flow duration in seconds (>= 0.001s)
    "conn_rate",        # Connection rate (packets/sec or conns/sec, clipped [0.1, 500.0])
    "dst_port",         # Destination service port (1 - 65535)
    "unique_dst_ports", # Target port diversity (stateful per source IP)
    "bytes_per_sec",    # Throughput (byte_count / max(duration, 0.001))
    "packets_per_sec",  # Packet rate (packet_count / max(duration, 0.001))
    "avg_packet_size",  # Average payload size (byte_count / max(packet_count, 1))
]
```

---

## 3. Provider Telemetry Field Mapping

The following matrix documents the exact translation from raw cloud telemetry into `CanonicalFlowRecord`:

| Canonical Feature | AWS VPC Flow Log V2 | GCP Cloud Logging VPC Flows | Azure NSG Flow Log V2 | Docker Hybrid Lab |
| :--- | :--- | :--- | :--- | :--- |
| `src_ip` | Token 3 (`srcaddr`) | `jsonPayload.connection.src_ip` | Tuple field 1 (`src_ip`) | `rec["src_ip"]` |
| `dst_ip` | Token 4 (`dstaddr`) | `jsonPayload.connection.dest_ip` | Tuple field 2 (`dst_ip`) | `rec["dst_ip"]` |
| `src_port` | Token 5 (`srcport`) | `jsonPayload.connection.src_port` | Tuple field 3 (`src_port`) | `rec["src_port"]` |
| `dst_port` | Token 6 (`dstport`) | `jsonPayload.connection.dest_port` | Tuple field 4 (`dst_port`) | `rec["dst_port"]` |
| `protocol` | Token 7 (`protocol` number) | `jsonPayload.connection.protocol` | Tuple field 5 (`protocol` T/U) | `rec["protocol"]` |
| `packet_count` | Token 8 (`packets`) | `jsonPayload.packets_sent` | Tuple 9 + 11 ($s2d + d2s$) | `rec["packets"]` |
| `byte_count` | Token 9 (`bytes`) | `jsonPayload.bytes_sent` | Tuple 10 + 12 ($s2d + d2s$) | `rec["bytes"]` |
| `duration` | Token 11 - 10 (`end - start`) | `end_time - start_time` | Session state delta (default 1.0) | `rec["duration"]` |
| `action` | Token 12 (`action`) | `jsonPayload.rule_details.action` | Tuple field 7 (`decision` A/D) | `ACCEPT` |
| `failed_auth_count` | **EXCLUDED (Never Synthesized)** | **EXCLUDED (Never Synthesized)** | **EXCLUDED (Never Synthesized)** | **EXCLUDED** |

---

## 4. Derived & Stateful Feature Calculation

### 4.1 Connection Rate (`conn_rate`)
$$\text{conn\_rate} = \text{clip}\left(\frac{\text{packet\_count}}{\max(\text{duration}, 0.01)}, 0.1, 500.0\right)$$

### 4.2 Throughput & Packet Rate
$$\text{bytes\_per\_sec} = \frac{\text{byte\_count}}{\max(\text{duration}, 0.001)}, \quad \text{packets\_per\_sec} = \frac{\text{packet\_count}}{\max(\text{duration}, 0.001)}$$

### 4.3 Average Packet Size
$$\text{avg\_packet\_size} = \frac{\text{byte\_count}}{\max(\text{packet\_count}, 1)}$$

### 4.4 Stateful Port Diversity (`unique_dst_ports`)
The normalizer maintains a stateful rolling tracker indexed by source IP (`stateful_port_tracker[src_ip]`). For every arriving flow, the target port is added to the set, and the cardinality $|\text{ports}|$ is assigned to `unique_dst_ports`. This reliably exposes horizontal port scanning across hybrid clouds.

---

## 5. Verification & Parity Guarantees

In `backend/tests/test_telemetry_normalization.py`, automated tests verify that:
1. Feature vector length is strictly equal to 9 across all provider logs.
2. `failed_auth_count` is completely absent from the feature matrix.
3. Feature values are identical regardless of whether the log originated from AWS, GCP, Azure, or Docker Lab.

