# FINAL PERFORMANCE BENCHMARK REPORT (PHASE 7)

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Phase:** Phase 7 — Comprehensive Performance & Throughput Evaluation  
**Date:** November 2026  
**Artifacts Audited:** `data/reports/performance_stability_benchmark.json`, `data/reports/live_scenario_validation_report.json`  
**Test Harness:** `ml/evaluation/benchmark_performance_stability.py`  

---

## 1. Executive Summary

This report documents the final empirical performance benchmarks of the **Adaptive AI-Powered Security Gateway for Hybrid Cloud** following the promotion of Big Data XGBoost V2 to the active authoritative primary engine.

### Key Benchmark Takeaways:
- **Sub-Millisecond Inference:** Single-flow mean latency is **0.897 ms** (P95: **1.10 ms**, P99: **1.76 ms**), providing a **23.1x speedup** over the legacy Random Forest baseline (20.73 ms).
- **Extreme Batch Throughput:** In-memory vectorized flow evaluation achieves **507,372 flows/sec**, easily accommodating line-rate PCAP ingestion and bulk VPC Flow Log parsing.
- **Efficient Explainability:** SHAP TreeExplainer calculates exact top-3 feature log-odds attributions in **$<35\text{ ms}$**.
- **Asynchronous Persistence Decoupling:** Full end-to-end database persistence completes in **45.74 ms/flow** inside background worker threads, completely eliminating latency bottlenecks from the router forwarding path.
- **Zero Memory Leaks:** 5 concurrent threads processing 50 transactional flows demonstrated **zero memory growth (+0.00 MB)** and zero dropped transactions.

---

## 2. Single-Flow Inference Latency Profile

Measured over **200 consecutive flow evaluations** with real-time feature extraction, scaling, and probability estimation:

| Latency Percentile | Active XGBoost V2 | Baseline Random Forest | Speedup Factor | Latency Budget (< 5ms) |
| :--- | :---: | :---: | :---: | :---: |
| **Minimum** | **0.68 ms** | 17.40 ms | **25.6x faster** | Met (13.6% of budget) |
| **P50 (Median)** | **0.85 ms** | 19.80 ms | **23.3x faster** | Met (17.0% of budget) |
| **Mean** | **0.897 ms** | 20.73 ms | **23.1x faster** | Met (17.9% of budget) |
| **P95** | **1.10 ms** | 30.63 ms | **27.8x faster** | Met (22.0% of budget) |
| **P99** | **1.76 ms** | 33.24 ms | **18.9x faster** | Met (35.2% of budget) |
| **Maximum** | **2.15 ms** | 38.50 ms | **17.9x faster** | Met (43.0% of budget) |

### Why P99 Latency Matters for Hybrid Cloud Gateways:
In high-throughput perimeter routers, tail latency spikes cause packet buffer queue bloat and dropped TCP handshakes. XGBoost V2's predictable **P99 latency of 1.76 ms** ensures deterministic routing performance under bursty network conditions.

---

## 3. High-Throughput Batch Processing Benchmark

Batch throughput was benchmarked on an in-memory matrix of **10,000 synthetic flow records**:

| Model Architecture | Batch Sample Size | Elapsed Time (s) | Throughput (Flows/Sec) | Performance Gain |
| :--- | :---: | :---: | :---: | :---: |
| **Active XGBoost V2** | 10,000 | **0.0197 s** | **507,372 fps** | **2.24x Gain** |
| **Baseline Random Forest** | 10,000 | 0.0441 s | 226,671 fps | Baseline (1.00x) |

With a capacity exceeding **500,000 flows per second**, the gateway easily processes bulk PCAP file ingestion and high-volume AWS CloudWatch VPC Flow Log streams without CPU exhaustion.

---

## 4. Subsystem Latency Breakdown

The table below breaks down the time consumed across each stage of a live flow's lifecycle:

```
[ Ingress Packet ] ──> [ Feature Extraction: 0.11 ms ] ──> [ XGBoost Inference: 0.90 ms ]
                             │                                           │
                             ▼                                           ▼
             [ Policy Decision: 0.08 ms ]              [ SHAP Explainability: 32.4 ms ] (Conditional)
                             │                                           │
                             ▼                                           ▼
             [ Netfilter Drop: 1.45 ms ] (If High Risk)  [ DB Persistence: 45.74 ms ] (Async Background)
```

| Pipeline Component | Average Latency | Execution Mechanism | Latency Impact on Forwarding |
| :--- | :---: | :--- | :--- |
| **1. Feature Extraction** | 0.11 ms | Python C-extensions (NumPy) | Inline (Blocking) |
| **2. Active ML Inference** | 0.897 ms | Native C++ XGBoost Core | Inline (Blocking) |
| **3. Policy Engine Evaluation** | 0.08 ms | In-memory allowlist & tracker | Inline (Blocking) |
| **4. Netfilter Enforcement** | 1.45 ms | HTTP control to `router_agent.py` | Inline for blocked flows only |
| **5. SHAP TreeExplainer** | 32.40 ms | `shap.TreeExplainer` | Gated (Anomalies $\ge 50$ risk only) |
| **6. Database Persistence** | 45.74 ms | SQLAlchemy + PostgreSQL Pool | **Asynchronous Worker Thread (Zero Impact)** |

---

## 5. Multi-Threaded Concurrency & Memory Stability

A sustained multi-threaded load test was executed against the active gateway service and PostgreSQL database pool:
- **Concurrent Workers:** 5 parallel threads
- **Transaction Volume:** 10 flows per thread (50 total end-to-end evaluations)
- **Workload Content:** Mixed benign and attack flows requiring policy evaluation and database persistence

```
=== CONCURRENCY & STABILITY REPORT ===
Concurrent Threads    : 5
Total Flows Evaluated : 50
Total Elapsed Time    : 1.573 seconds
Effective Throughput  : 31.8 flows/sec (Full End-to-End Persistence)
Execution Errors      : 0
Memory Delta (MB)     : +0.00 MB
Status                : STABLE
```

### Memory Footprint & Resource Utilization:
- **Idle Memory Footprint:** $\approx 85\text{ MB}$ RAM
- **Active Load Memory Footprint:** $\approx 140\text{ MB}$ RAM
- **Memory Growth Delta:** Measured at **0.00 MB** after garbage collection, confirming zero connection pool leakage or unreleased model references.

---

## 6. Performance Conclusion

The promoted Big Data XGBoost V2 model easily satisfies all real-time hybrid-cloud operational constraints:
- **0.897 ms mean inference latency** meets the $<5.0\text{ ms}$ budget with an 82% margin.
- **507,372 fps batch throughput** ensures rapid ingestion of bulk network logs.
- Decoupled asynchronous persistence guarantees that database operations never degrade router forwarding responsiveness.

