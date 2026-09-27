"""
Explainability & ML Performance Benchmark
==========================================
Measures empirical single-flow ML inference, single-flow SHAP evaluation,
combined ML+SHAP latency, and batch SHAP throughput using the real model.joblib
and scaler.joblib artifacts.
"""

import sys
import os
import time
from typing import Dict, List
import numpy as np

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from ml.models.predict import ThreatPredictor
from backend.app.services.explainability_service import ExplainabilityService

BENCHMARK_SAMPLE_FLOWS = [
    {"packet_count": 25, "byte_count": 15000, "duration": 2.5, "conn_rate": 2.0, "dst_port": 443, "unique_dst_ports": 1, "failed_auth_count": 0},
    {"packet_count": 2, "byte_count": 120, "duration": 0.08, "conn_rate": 120.0, "dst_port": 8080, "unique_dst_ports": 75, "failed_auth_count": 0},
    {"packet_count": 35, "byte_count": 8500, "duration": 1.8, "conn_rate": 18.0, "dst_port": 22, "unique_dst_ports": 1, "failed_auth_count": 12},
    {"packet_count": 4500, "byte_count": 4500000, "duration": 4.0, "conn_rate": 60.0, "dst_port": 80, "unique_dst_ports": 1, "failed_auth_count": 0},
    {"packet_count": 1200, "byte_count": 1600000, "duration": 120.0, "conn_rate": 3.0, "dst_port": 8443, "unique_dst_ports": 1, "failed_auth_count": 0},
]


def run_benchmark(iterations: int = 200) -> Dict[str, Any]:
    print(f"[*] Running Explainability Benchmark ({iterations} iterations per test)...")
    predictor = ThreatPredictor()
    explain_svc = ExplainabilityService(predictor)

    # Warmup
    for f in BENCHMARK_SAMPLE_FLOWS:
        out = predictor.predict_flow(f)
        _ = explain_svc.explain_flow(f, out.attack_type)

    ml_latencies: List[float] = []
    shap_latencies: List[float] = []
    combined_latencies: List[float] = []

    for i in range(iterations):
        flow = BENCHMARK_SAMPLE_FLOWS[i % len(BENCHMARK_SAMPLE_FLOWS)]

        # 1. Baseline ML Latency
        t0 = time.perf_counter()
        pred_out = predictor.predict_flow(flow)
        t1 = time.perf_counter()
        ml_latencies.append((t1 - t0) * 1000.0)

        # 2. SHAP Latency
        t2 = time.perf_counter()
        _ = explain_svc.explain_flow(flow, pred_out.attack_type)
        t3 = time.perf_counter()
        shap_latencies.append((t3 - t2) * 1000.0)

        # 3. Combined Latency
        combined_latencies.append(((t1 - t0) + (t3 - t2)) * 1000.0)

    # 4. Batch SHAP Throughput
    batch_size = 100
    batch_flows = [BENCHMARK_SAMPLE_FLOWS[i % len(BENCHMARK_SAMPLE_FLOWS)] for i in range(batch_size)]
    t_batch_start = time.perf_counter()
    for f in batch_flows:
        p = predictor.predict_flow(f)
        _ = explain_svc.explain_flow(f, p.attack_type)
    t_batch_end = time.perf_counter()
    batch_throughput = batch_size / (t_batch_end - t_batch_start)

    results = {
        "iterations": iterations,
        "baseline_ml_ms": {
            "mean": round(float(np.mean(ml_latencies)), 3),
            "p95": round(float(np.percentile(ml_latencies, 95)), 3),
            "p99": round(float(np.percentile(ml_latencies, 99)), 3),
        },
        "single_flow_shap_ms": {
            "mean": round(float(np.mean(shap_latencies)), 3),
            "p95": round(float(np.percentile(shap_latencies, 95)), 3),
            "p99": round(float(np.percentile(shap_latencies, 99)), 3),
        },
        "combined_ml_shap_ms": {
            "mean": round(float(np.mean(combined_latencies)), 3),
            "p95": round(float(np.percentile(combined_latencies, 95)), 3),
            "p99": round(float(np.percentile(combined_latencies, 99)), 3),
        },
        "batch_throughput_flows_per_sec": round(float(batch_throughput), 1),
    }

    print("\n" + "=" * 60)
    print("EMPIRICAL PERFORMANCE BENCHMARK RESULTS")
    print("=" * 60)
    print(f"• Baseline ML Inference (mean/p95/p99):   {results['baseline_ml_ms']['mean']} ms / {results['baseline_ml_ms']['p95']} ms / {results['baseline_ml_ms']['p99']} ms")
    print(f"• Single-Flow SHAP Eval (mean/p95/p99):   {results['single_flow_shap_ms']['mean']} ms / {results['single_flow_shap_ms']['p95']} ms / {results['single_flow_shap_ms']['p99']} ms")
    print(f"• Combined ML + SHAP (mean/p95/p99):     {results['combined_ml_shap_ms']['mean']} ms / {results['combined_ml_shap_ms']['p95']} ms / {results['combined_ml_shap_ms']['p99']} ms")
    print(f"• Batch Throughput:                      {results['batch_throughput_flows_per_sec']} flows/sec")
    print("=" * 60 + "\n")

    return results


if __name__ == "__main__":
    run_benchmark(iterations=200)
