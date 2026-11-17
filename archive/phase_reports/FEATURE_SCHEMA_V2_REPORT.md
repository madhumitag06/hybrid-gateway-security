# Feature Schema V2 Specification and Architecture Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Phase:** Phase 2 — Production-Grade Feature Engineering and Big Data XGBoost V2  
**Date:** November 2026  
**Status:** Approved & Implemented

---

## Executive Summary

During the Big Data ML Phase 1 audit (`BIGDATA_MODEL_FINAL_VALIDATION.md`), the 10-feature schema (Schema V1) was identified to have critical operational vulnerabilities:
1. **Unobservable Feature (`failed_auth_count`):** Accounted for 55.46% of XGBoost V1 feature importance, yet L3/L4 network telemetry (PCAP, NetFlow/IPFIX, AWS VPC Flow Logs) contains no plaintext application authentication headers. In Phase 1, this feature was artificially injected into SSH brute-force samples during training, but was forced to constant `0` during live gateway packet capture.
2. **Stateful Accumulator Drift (`unique_dst_ports`):** Accounted for 22.29% of V1 importance but lacked rolling temporal eviction, thread safety, bounded memory guarantees, and client/server directional awareness.
3. **Connection Rate Formula Divergence (`conn_rate`):** Training scripts computed connection rates with an artificial `/ 2.0` divisor, whereas live inference computed connection rate with `/ 1.0`, introducing an undocumented $2\times$ scale divergence.

Schema V2 resolves all three integrity flaws. It defines a lean, 100% observable, 9-feature vector derived strictly from L3/L4 packet headers and bounded stateful flow trackers.

---

## 1. Feature Schema Comparison: V1 vs. V2

| Index | Feature Name | Schema V1 (10-Features) | Schema V2 (9-Features) | Status in V2 | Source Layer |
|:---:|:---|:---|:---|:---|:---|
| 0 | `packet_count` | Included | Included | Retained | L3/L4 Flow Header |
| 1 | `byte_count` | Included | Included | Retained | L3/L4 Flow Header |
| 2 | `duration` | Included | Included | Retained | Flow Timestamps |
| 3 | `conn_rate` | Included (Divergent formula) | Included (Unified formula) | Re-engineered | Derived Flow Metric |
| 4 | `dst_port` | Included | Included | Retained | L4 TCP/UDP Header |
| 5 | `unique_dst_ports` | Included (Unbounded dict) | Included (60s Rolling Window) | Re-engineered | Stateful Host Tracker |
| 6 | `failed_auth_count` | Included (55.46% Synthetic) | **REMOVED** | **Dropped** | Unobservable in L3/L4 |
| 7 | `bytes_per_sec` | Included | Included | Retained | Derived Flow Metric |
| 8 | `packets_per_sec` | Included | Included | Retained | Derived Flow Metric |
| 9 | `avg_packet_size` | Included | Included | Retained | Derived Flow Metric |

---

## 2. Mathematical Definitions of V2 Features

### Feature 1: `packet_count`
- **Definition:** Total number of IP packets transmitted between the flow endpoints during the flow observation window.
- **Formula:**
  $$N_{\text{packets}} = \sum_{i=1}^{k} 1$$
- **Unit:** Dimensionless integer count ($N \ge 1$).
- **Source:** Network packet capture engine (`FlowAggregator` packet counter / PCAP frame counter).
- **Default / Missing Behavior:** Defaults to `1` on single-packet flows. Negative values clamped to `0`.

### Feature 2: `byte_count`
- **Definition:** Total volume of IP payload and L4 header bytes exchanged across the flow.
- **Formula:**
  $$S_{\text{bytes}} = \sum_{i=1}^{N_{\text{packets}}} \text{wire\_length}(p_i)$$
- **Unit:** Bytes ($B \ge 0$).
- **Source:** Network packet capture engine (`Flow.byte_count` / `frame.len`).
- **Default / Missing Behavior:** Defaults to `0` if no payload bytes recorded.

### Feature 3: `duration`
- **Definition:** Total elapsed wall-clock time between the reception of the first packet and the latest packet of the flow.
- **Formula:**
  $$\Delta t = t_{\text{last\_packet}} - t_{\text{first\_packet}}$$
- **Unit:** Seconds ($s \ge 0.0$).
- **Source:** System monotonic clock timestamps attached to packet arrival.
- **Default / Missing Behavior:** Defaults to `0.001` seconds for single-packet flows or instantaneous micro-bursts to avoid division-by-zero in rate calculations. Minimum floor: $\max(\Delta t, 0.001)$.

### Feature 4: `conn_rate`
- **Definition:** Flow initiation packet frequency, representing the intensity of packet generation normalized by the effective duration.
- **Unified Formula (Shared Across Training and Live Inference):**
  $$R_{\text{conn}} = \frac{N_{\text{packets}}}{\max(\Delta t, 1.0)}$$
- **Unit:** Packets per second ($\text{pps}$).
- **Source:** Derived from `packet_count` and `duration`.
- **Mathematical Rationale:**
  - Using $\max(\Delta t, 1.0)$ provides numeric stability: for micro-bursts and single-packet connection probes lasting under $1.0\text{ s}$, the connection rate cleanly reflects the instantaneous packet burst count without asymptotic explosion toward infinity.
  - In Schema V1, training code divided by $2.0 \times \Delta t$ while live gateway divided by $1.0 \times \Delta t$. Schema V2 establishes the single shared function `calculate_conn_rate()` in `ml/features/extractor.py`.

### Feature 5: `dst_port`
- **Definition:** Destination transport-layer port number identifying the targeted network service.
- **Formula:**
  $$P_{\text{dst}} = \text{TCP.dport} \quad \text{or} \quad \text{UDP.dport}$$
- **Unit:** Integer $[0, 65535]$.
- **Source:** L4 transport header.
- **Default / Missing Behavior:** Defaults to `0` for non-TCP/non-UDP packets (e.g., ICMP, GRE).

### Feature 6: `unique_dst_ports`
- **Definition:** Cardinality of distinct destination transport ports contacted by the client host within a sliding 60-second temporal window.
- **Formula:**
  $$U_{\text{ports}}(H_{\text{src}}, t) = \left| \left\{ P_{\text{dst}} \mid (P_{\text{dst}}, t_i) \in W(H_{\text{src}}), \, t - t_i \le 60.0\text{ s} \right\} \right|$$
- **Unit:** Unique port count integer ($U \ge 1$).
- **Source:** Stateful rolling memory tracker (`HostPortTracker` in `backend/app/services/flow_aggregator.py`).
- **Operational Guarantees:**
  - **Temporal Expiration:** Uses `collections.deque` with automatic eviction of entries older than 60.0 seconds upon each insertion.
  - **Bounded Host Capacity:** Maximum of 10,000 distinct source hosts tracked simultaneously via LRU eviction policy.
  - **Thread-Safety:** Concurrency-protected via `threading.RLock()` across multi-threaded packet capture workers.
  - **Directional Consistency:** Evaluated strictly from client (initiator) to server, preventing server reply traffic from polluting port tracking.
- **Default / Missing Behavior:** Defaults to `1` when no prior history exists or for stateless single-flow inspection.

### Feature 7: `bytes_per_sec`
- **Definition:** Flow byte transmission throughput.
- **Formula:**
  $$B_{\text{sec}} = \frac{S_{\text{bytes}}}{\max(\Delta t, 0.001)}$$
- **Unit:** Bytes per second ($\text{B/s}$).
- **Source:** Derived from `byte_count` and `duration`.
- **Default / Missing Behavior:** Defaults to `0.0` when `byte_count == 0`.

### Feature 8: `packets_per_sec`
- **Definition:** Flow packet transmission throughput.
- **Formula:**
  $$P_{\text{sec}} = \frac{N_{\text{packets}}}{\max(\Delta t, 0.001)}$$
- **Unit:** Packets per second ($\text{pps}$).
- **Source:** Derived from `packet_count` and `duration`.
- **Default / Missing Behavior:** Defaults to `1000.0` for single-packet micro-bursts ($\Delta t \le 0.001\text{ s}$).

### Feature 9: `avg_packet_size`
- **Definition:** Mean payload and header volume per packet in the flow.
- **Formula:**
  $$S_{\text{avg}} = \frac{S_{\text{bytes}}}{\max(N_{\text{packets}}, 1)}$$
- **Unit:** Bytes per packet ($\text{B/packet}$).
- **Source:** Derived from `byte_count` and `packet_count`.
- **Default / Missing Behavior:** Defaults to `0.0` if `byte_count == 0`.

---

## 3. Justification for Dropping `failed_auth_count`

1. **Unobservability in L3/L4 Network Infrastructure:**
   - Transport encryption (SSHv2, TLS 1.3, HTTPS) cryptographically encapsulates authentication handshakes.
   - Middleboxes, gateway firewalls, and VPC flow log collectors cannot inspect decrypted authentication failure tokens without active man-in-the-middle proxying and TLS termination.
2. **False Sense of ML Accuracy:**
   - In Schema V1, XGBoost relied on `failed_auth_count` for 55.46% of its feature importance.
   - Because live packet captures set this to `0`, live brute-force attacks were misclassified as `BENIGN` ($FNR > 95\%$).
3. **Decoupling ML from Application Safeguards:**
   - In Schema V2, brute-force behavior is identified by observable flow signatures (rapid connection rate on port 22, low byte volumes characteristic of failed handshakes).
   - In addition, a deterministic behavioral safeguard (`SSHProbeTracker`) in `PolicyEngine` monitors burst frequencies without tainting the machine-learning feature vector.

---

## 4. Verification and Schema Contract Compatibility

The schema vector is formalized in `ml/features/extractor.py` and `ml/models/candidates/bigdata_v2/feature_schema.json`:
```json
{
  "version": "2.0.0",
  "num_features": 9,
  "features": [
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
}
```

The gateway runtime automatically detects schema versions via `metadata.json`:
- If `feature_schema` contains 10 features, V1 compatibility mode is engaged.
- If `feature_schema` contains 9 features, V2 native pipeline is engaged.
- Unit tests (`backend/tests/test_feature_pipeline_v2.py`) verify that both schemas operate simultaneously with zero cross-contamination.

