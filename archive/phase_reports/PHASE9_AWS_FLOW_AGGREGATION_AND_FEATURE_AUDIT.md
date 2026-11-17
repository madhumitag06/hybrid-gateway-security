# PHASE 9 REPORT: AWS FLOW AGGREGATION & FEATURE EXTRACTION AUDIT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Deliverable:** VPC Flow Log Aggregation Semantics & 9-Feature Parity Verification  
**Date:** November 15, 2026  
**Status:** IMPLEMENTED & AUDITED  

---

## 1. Executive Summary

This audit establishes mathematically rigorous aggregation semantics and feature normalization rules for AWS VPC Flow Logs in accordance with the Phase 9 technical corrections:

1. **No Undirected Double-Counting**: Forward and reverse VPC flow log records are **not** blindly combined. They represent distinct directional observations at an Elastic Network Interface (ENI).
2. **Directed Session Aggregation**: Records sharing the same interface, directed endpoint pair (`src_ip`, `dst_ip`, `src_port`, `dst_port`), protocol, and flow direction within an aggregation window are aggregated to prevent flow fragmentation.
3. **Training Methodology Parity**: Rate features (`conn_rate`, `bytes_per_sec`, `packets_per_sec`, `avg_packet_size`) are calculated strictly according to `ml/data/clean_and_preprocess.py` and `ml/features/extractor.py`.
4. **Window-Level Host Port Diversity**: Destination port dispersion (`unique_dst_ports`) is pre-calculated across the entire batch/window for each source IP to ensure accurate reconnaissance detection.

---

## 2. Aggregation Semantics

### 2.1 The Directed Session Key
AWS VPC Flow Logs are recorded per-interface. Combining forward (`A -> B`) and reverse (`B -> A`) records into an undirected tuple causes:
- Double-counting of packets and bytes.
- Loss of initiator vs responder attribution.
- Misrepresentation of asymmetric flows.

Therefore, `TelemetryNormalizer.aggregate_canonical_records()` groups records by:
$$\text{SessionKey} = \left(\text{interface\_id}, \text{src\_ip}, \text{dst\_ip}, \text{src\_port}, \text{dst\_port}, \text{protocol}, \text{flow\_direction}\right)$$

### 2.2 Mathematical Accumulation
When records in the same capture window match the session key:
- $\text{packet\_count} = \sum_{r \in \text{group}} r.\text{packet\_count}$
- $\text{byte\_count} = \sum_{r \in \text{group}} r.\text{byte\_count}$
- $\text{start\_time} = \min_{r \in \text{group}} r.\text{start\_time}$
- $\text{end\_time} = \max_{r \in \text{group}} r.\text{end\_time}$
- $\text{duration} = \max(t_{\text{end}} - t_{\text{start}}, 0.001)$

Forward and reverse traffic remain independent observations, preserving strict directional fidelity.

---

## 3. Comparison with Training Pipeline (`clean_and_preprocess.py`)

| Feature | Training Methodology (`clean_and_preprocess.py`) | Phase 9 Telemetry Implementation | Parity Status |
|:---|:---|:---|:---:|
| `packet_count` | Raw observed integer $\ge 1$ | `max(int(record.packet_count), 1)` | **EXACT** |
| `byte_count` | Raw observed integer $\ge 64$ | `max(int(record.byte_count), 64)` | **EXACT** |
| `duration` | Safe divisor $\max(d, 0.001)$ | `max(float(record.duration), 0.001)` | **EXACT** |
| `conn_rate` | $\text{clip}(\text{pkts} / \max(d, 0.01), 0.1, 500.0)$ | `calculate_conn_rate(pkts, duration)` | **EXACT** |
| `dst_port` | Numerical port $[1, 65535]$ | `max(min(int(record.dst_port), 65535), 1)` | **EXACT** |
| `unique_dst_ports` | Host-window distinct ports $[1, 1000]$ | Pre-calculated distinct ports per `src_ip` in window | **EXACT** |
| `bytes_per_sec` | `byte_count / max(duration, 0.001)` | `float(byte_count) / duration` | **EXACT** |
| `packets_per_sec` | `packet_count / max(duration, 0.001)` | `float(pkt_count) / duration` | **EXACT** |
| `avg_packet_size` | `byte_count / max(packet_count, 1)` | `float(byte_count) / float(pkt_count)` | **EXACT** |

---

## 4. Synthetic Aggregation Verification

A unit test was executed with synthetic offline flow records (zero traffic sent to AWS, zero infrastructure modifications):
- Input: 2 forward EGRESS records (`5 pkts / 1200 B`, `8 pkts / 3500 B`) + 1 reverse INGRESS record (`12 pkts / 14500 B`).
- Result: Exactly 2 aggregated sessions.
  - Forward: `13 pkts / 4700 B` (EGRESS).
  - Reverse: `12 pkts / 14500 B` (INGRESS).
- Verification: Zero double-counting; directional attribution 100% preserved.
