"""
Performance, Latency and Stability Benchmark (Phase 3)
======================================================
Measures single-flow latency, batch throughput, shadow mode overhead,
memory consumption, and concurrency stability for the production Random Forest
and candidate Big Data XGBoost V2 models.
"""

from concurrent.futures import ThreadPoolExecutor
import gc
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import settings
from backend.app.db.session import SessionLocal, init_db
from backend.app.schemas.predict import NetworkFlowRequest
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.ml_service import MLService
from backend.app.services.shadow_service import ShadowService
from ml.features.extractor import NetworkFlowInput


def get_current_memory_mb() -> float:
    try:
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(
            handle, ctypes.byref(counters), counters.cb
        ):
            return counters.WorkingSetSize / (1024 * 1024)
    except Exception:
        pass
    return 0.0


def benchmark_single_flow_latency(iterations: int = 1000) -> Dict[str, Any]:
    prod_pred = MLService.get_predictor()
    cand_pred = ShadowService.get_candidate_predictor()

    sample = NetworkFlowInput(
        packet_count=25,
        byte_count=15000,
        duration=2.5,
        conn_rate=10.0,
        dst_port=443,
        unique_dst_ports=1,
        failed_auth_count=0,
    )

    # Warmup
    for _ in range(50):
        prod_pred.predict_flow(sample)
        cand_pred.predict_flow(sample)

    # Production RF Latency
    prod_times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        prod_pred.predict_flow(sample)
        prod_times.append((time.perf_counter() - t0) * 1000.0)

    # Candidate XGBoost V2 Latency
    cand_times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        cand_pred.predict_flow(sample)
        cand_times.append((time.perf_counter() - t0) * 1000.0)

    return {
        "iterations": iterations,
        "prod_rf_mean_ms": round(float(sum(prod_times) / len(prod_times)), 4),
        "prod_rf_p95_ms": round(float(sorted(prod_times)[int(iterations * 0.95)]), 4),
        "prod_rf_p99_ms": round(float(sorted(prod_times)[int(iterations * 0.99)]), 4),
        "cand_xgb_mean_ms": round(float(sum(cand_times) / len(cand_times)), 4),
        "cand_xgb_p95_ms": round(float(sorted(cand_times)[int(iterations * 0.95)]), 4),
        "cand_xgb_p99_ms": round(float(sorted(cand_times)[int(iterations * 0.99)]), 4),
        "latency_speedup_factor": round(
            (sum(prod_times) / len(prod_times)) / (sum(cand_times) / len(cand_times)), 2
        ),
    }


def benchmark_batch_throughput(batch_size: int = 10000) -> Dict[str, Any]:
    prod_pred = MLService.get_predictor()
    cand_pred = ShadowService.get_candidate_predictor()

    import numpy as np

    # Generate synthetic 10,000-flow matrix matching 9 features
    X_raw_cand = np.random.uniform(1.0, 100.0, size=(batch_size, len(cand_pred.feature_schema)))
    X_scaled_cand = cand_pred.scaler.transform(X_raw_cand)

    X_raw_prod = np.random.uniform(1.0, 100.0, size=(batch_size, len(prod_pred.feature_schema)))
    X_scaled_prod = prod_pred.scaler.transform(X_raw_prod)

    # Warmup
    prod_pred.model.predict_proba(X_scaled_prod[:50])
    cand_pred.model.predict_proba(X_scaled_cand[:50])

    # Production RF Batch Matrix Throughput
    t0 = time.perf_counter()
    prod_pred.model.predict_proba(X_scaled_prod)
    prod_dur = time.perf_counter() - t0
    prod_fps = batch_size / prod_dur

    # Candidate XGBoost V2 Batch Matrix Throughput
    t0 = time.perf_counter()
    cand_pred.model.predict_proba(X_scaled_cand)
    cand_dur = time.perf_counter() - t0
    cand_fps = batch_size / cand_dur

    return {
        "batch_size": batch_size,
        "prod_rf_duration_sec": round(prod_dur, 4),
        "prod_rf_throughput_fps": int(prod_fps),
        "cand_xgb_duration_sec": round(cand_dur, 4),
        "cand_xgb_throughput_fps": int(cand_fps),
        "throughput_gain_factor": round(cand_fps / prod_fps, 2),
    }


def benchmark_shadow_overhead(num_flows: int = 200) -> Dict[str, Any]:
    init_db()

    flow_req = NetworkFlowRequest(
        packet_count=30,
        byte_count=18000,
        duration=2.0,
        conn_rate=15.0,
        dst_port=443,
        unique_dst_ports=1,
        failed_auth_count=0,
    )

    # 1. Baseline: Production Only (no DB persistence)
    t0 = time.perf_counter()
    for _ in range(num_flows):
        MLService.predict(flow_req)
    prod_only_sec = time.perf_counter() - t0

    # 2. Production + Shadow Inference (evaluate_shadow_flow only)
    t0 = time.perf_counter()
    for _ in range(num_flows):
        p = MLService.predict(flow_req)
        ShadowService.evaluate_shadow_flow(flow_req, p)
    shadow_inf_sec = time.perf_counter() - t0

    # 3. Full Production Pipeline + PolicyEngine + DB Persistence + Shadow Persistence
    with SessionLocal() as db:
        t0 = time.perf_counter()
        for i in range(min(num_flows, 50)):  # 50 persistent transactions
            DashboardService.record_prediction(
                db=db,
                flow_request=flow_req,
                source_ip=f"10.10.10.{10 + (i % 20)}",
                destination_ip="10.20.10.20",
                is_demo=False,
            )
        db.commit()
        full_persist_sec = time.perf_counter() - t0

    return {
        "evaluated_flows": num_flows,
        "prod_only_avg_ms": round((prod_only_sec / num_flows) * 1000.0, 3),
        "prod_plus_shadow_inf_avg_ms": round((shadow_inf_sec / num_flows) * 1000.0, 3),
        "shadow_inference_overhead_ms": round(
            ((shadow_inf_sec - prod_only_sec) / num_flows) * 1000.0, 3
        ),
        "full_persist_pipeline_50_flows_sec": round(full_persist_sec, 3),
        "avg_persist_latency_per_flow_ms": round((full_persist_sec / 50) * 1000.0, 3),
    }


def benchmark_concurrency_and_stability(threads: int = 10, flows_per_thread: int = 20) -> Dict[str, Any]:
    init_db()
    mem_before = get_current_memory_mb()

    flow_req = NetworkFlowRequest(
        packet_count=15,
        byte_count=8000,
        duration=1.2,
        conn_rate=12.0,
        dst_port=443,
        unique_dst_ports=1,
        failed_auth_count=0,
    )

    errors = []

    def worker(worker_id: int):
        with SessionLocal() as db:
            for j in range(flows_per_thread):
                try:
                    DashboardService.record_prediction(
                        db=db,
                        flow_request=flow_req,
                        source_ip=f"10.10.{worker_id}.{j + 1}",
                        destination_ip="10.20.10.40",
                        is_demo=False,
                    )
                except Exception as e:
                    errors.append(str(e))
            try:
                db.commit()
            except Exception as e:
                errors.append(str(e))

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, w) for w in range(threads)]
        for f in futures:
            f.result()
    elapsed = time.perf_counter() - t0

    gc.collect()
    mem_after = get_current_memory_mb()

    return {
        "concurrent_threads": threads,
        "flows_per_thread": flows_per_thread,
        "total_flows_processed": threads * flows_per_thread,
        "total_elapsed_sec": round(elapsed, 3),
        "throughput_concurrent_fps": round((threads * flows_per_thread) / elapsed, 1),
        "error_count": len(errors),
        "errors": errors[:5],
        "initial_memory_mb": round(mem_before, 2),
        "final_memory_mb": round(mem_after, 2),
        "memory_delta_mb": round(mem_after - mem_before, 2),
        "stability_status": "STABLE" if len(errors) == 0 else "UNSTABLE",
    }


def main():
    print("=" * 70)
    print(" GATEWAY SYSTEM STABILITY AND PERFORMANCE BENCHMARK (PHASE 3)")
    print("=" * 70)

    print("\n1. Measuring Single-Flow Inference Latency (200 iterations)...")
    lat_res = benchmark_single_flow_latency(200)
    print(f"   Prod RF Mean Latency   : {lat_res['prod_rf_mean_ms']} ms (P95: {lat_res['prod_rf_p95_ms']} ms)")
    print(f"   Cand XGB Mean Latency  : {lat_res['cand_xgb_mean_ms']} ms (P95: {lat_res['cand_xgb_p95_ms']} ms)")
    print(f"   Speedup Factor         : {lat_res['latency_speedup_factor']}x faster")

    print("\n2. Measuring Batch Inference Throughput (10,000 samples)...")
    thr_res = benchmark_batch_throughput(10000)
    print(f"   Prod RF Throughput     : {thr_res['prod_rf_throughput_fps']:,} flows/sec")
    print(f"   Cand XGB Throughput    : {thr_res['cand_xgb_throughput_fps']:,} flows/sec")
    print(f"   Throughput Gain Factor : {thr_res['throughput_gain_factor']}x")

    print("\n3. Measuring Shadow Mode Overhead (100 flows)...")
    ovh_res = benchmark_shadow_overhead(100)
    print(f"   Production Only        : {ovh_res['prod_only_avg_ms']} ms/flow")
    print(f"   Prod + Shadow Inference: {ovh_res['prod_plus_shadow_inf_avg_ms']} ms/flow")
    print(f"   Shadow Inference Cost  : +{ovh_res['shadow_inference_overhead_ms']} ms/flow")
    print(f"   Full Persist Latency   : {ovh_res['avg_persist_latency_per_flow_ms']} ms/flow (DB write)")

    print("\n4. Measuring Concurrency & Memory Stability (5 threads, 50 concurrent flows)...")
    con_res = benchmark_concurrency_and_stability(threads=5, flows_per_thread=10)
    print(f"   Concurrent Throughput  : {con_res['throughput_concurrent_fps']} flows/sec")
    print(f"   Errors Detected        : {con_res['error_count']}")
    print(f"   Memory Delta           : {con_res['memory_delta_mb']:+.2f} MB")
    print(f"   Stability Status       : {con_res['stability_status']}")

    benchmark_summary = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "single_flow_latency": lat_res,
        "batch_throughput": thr_res,
        "shadow_overhead": ovh_res,
        "concurrency_stability": con_res,
    }

    out_file = Path("data/reports/performance_stability_benchmark.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(benchmark_summary, f, indent=2)

    print(f"\n[+] Full benchmark metrics saved to: {out_file}")


if __name__ == "__main__":
    main()
