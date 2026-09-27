"""
Comparative Evaluation & Benchmarking Service
=============================================
Orchestrates dual-path evaluation across the Adaptive AI Gateway pipeline
and the Traditional Static Policy Baseline. Computes mathematical ground-truth
classification metrics, independent over/under-blocking rates, policy divergence,
and empirical latency/throughput distributions.
"""

from datetime import datetime, timezone
import io
import json
import time
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sqlalchemy.orm import Session

from backend.app.models.security_event import SecurityEventModel
from backend.app.repositories.security_event_repo import SecurityEventRepository
from backend.app.schemas.evaluation import (
    CLASSES,
    BenchmarkScenario,
    ConfusionMatrixSchema,
    EvaluationRunRequest,
    EvaluationRunResponse,
    EvaluationSuiteInfo,
    LatencyBreakdown,
    LatencyDistribution,
    MLClassificationMetrics,
    PerClassMetrics,
    PolicyComparisonMetrics,
    PolicyDivergenceRecord,
    SuiteNameType,
)
from backend.app.schemas.predict import PredictionResponse
from backend.app.services.evaluation.dataset_generator import EvaluationDatasetGenerator
from backend.app.services.explainability_service import ExplainabilityService
from backend.app.services.ml_service import MLService
from backend.app.services.policy_engine import PolicyEngine
from backend.app.services.static_policy_engine import StaticPolicyEngine


class ComparativeEvaluationService:
    """
    Executes controlled benchmarking suites, evaluating detection efficacy and policy differences.
    """

    AVAILABLE_SUITES: List[EvaluationSuiteInfo] = [
        EvaluationSuiteInfo(
            suite_name="FULL_BENCHMARK",
            title="Comprehensive Multi-Threat & Operational Benchmark",
            description="Balanced evaluation set containing benign traffic, port scans (fast and stealth), brute-force authentication storms, volumetric surges, suspicious transfers, allowlist bypasses, and borderline flows.",
            default_sample_count=200,
            available_classes=CLASSES,
        ),
        EvaluationSuiteInfo(
            suite_name="RECON_SUITE",
            title="Reconnaissance & Port Scan Evaluation",
            description="High-frequency SYN scans and low-rate stealth probing targeting multiple destination ports.",
            default_sample_count=100,
            available_classes=["PORT_SCAN"],
        ),
        EvaluationSuiteInfo(
            suite_name="BRUTE_FORCE_SUITE",
            title="Credential Brute Force Evaluation",
            description="Repetitive authentication failure bursts on SSH, RDP, and FTP administrative ports.",
            default_sample_count=100,
            available_classes=["BRUTE_FORCE"],
        ),
        EvaluationSuiteInfo(
            suite_name="VOLUMETRIC_SUITE",
            title="Volumetric Traffic Spike Evaluation",
            description="High-frequency packet floods and volumetric throughput surges towards web endpoints.",
            default_sample_count=100,
            available_classes=["TRAFFIC_SPIKE"],
        ),
        EvaluationSuiteInfo(
            suite_name="EVASION_BORDERLINE_SUITE",
            title="Evasion, Allowlist, and Borderline Ambiguity Suite",
            description="Scenarios specifically testing confidence gating on ambiguous flows, management CIDR allowlist protection, and sub-threshold slow scans.",
            default_sample_count=100,
            available_classes=["BENIGN", "PORT_SCAN"],
        ),
        EvaluationSuiteInfo(
            suite_name="BENIGN_SUITE",
            title="Benign Baseline & False Positive Evaluation",
            description="Standard web browsing, API interactions, and normal business network communications.",
            default_sample_count=100,
            available_classes=["BENIGN"],
        ),
    ]

    @classmethod
    def list_suites(cls) -> List[EvaluationSuiteInfo]:
        return cls.AVAILABLE_SUITES

    @classmethod
    def run_evaluation(
        cls,
        request: EvaluationRunRequest,
        db: Optional[Session] = None,
    ) -> EvaluationRunResponse:
        """
        Executes a controlled benchmark run and calculates all ground-truth, policy, and latency metrics.
        """
        scenarios: List[BenchmarkScenario] = EvaluationDatasetGenerator.generate_suite(
            suite_name=request.suite_name,
            sample_count=request.sample_count,
        )

        explain_svc = ExplainabilityService.get_instance() if request.include_shap else None

        # Data collection containers
        ground_truth_labels: List[str] = []
        predicted_labels: List[str] = []

        pipeline_latencies: List[float] = []
        ml_latencies: List[float] = []
        shap_latencies: List[float] = []
        policy_latencies: List[float] = []

        divergence_records: List[PolicyDivergenceRecord] = []

        static_actions: Dict[str, int] = {"Allow": 0, "Block": 0}
        adaptive_actions: Dict[str, int] = {"Allow": 0, "Monitor": 0, "Restrict": 0, "Block": 0}

        static_overblock_count = 0
        adaptive_overblock_count = 0
        static_underblock_count = 0
        adaptive_underblock_count = 0

        total_benign_count = 0
        total_malicious_count = 0

        borderline_count = 0
        borderline_gated_count = 0

        total_start = time.perf_counter()

        events_to_persist: List[SecurityEventModel] = []

        for scn in scenarios:
            t_pipe_start = time.perf_counter()

            gt = scn.ground_truth_class
            ground_truth_labels.append(gt)

            if gt == "BENIGN":
                total_benign_count += 1
            else:
                total_malicious_count += 1

            if scn.is_borderline:
                borderline_count += 1

            # PATH A: Adaptive AI Pipeline (ML -> SHAP -> PolicyEngine)
            t_ml_start = time.perf_counter()
            pred: PredictionResponse = MLService.predict(scn.flow)
            t_ml_end = time.perf_counter()
            ml_latencies.append((t_ml_end - t_ml_start) * 1000.0)

            predicted_labels.append(pred.attack_type)

            # Optional SHAP
            if explain_svc:
                t_shap_start = time.perf_counter()
                _ = explain_svc.explain_flow(scn.flow, pred.attack_type, top_n=3)
                t_shap_end = time.perf_counter()
                shap_latencies.append((t_shap_end - t_shap_start) * 1000.0)

            t_pol_start = time.perf_counter()
            adaptive_decision = PolicyEngine.evaluate(
                prediction=pred,
                source_ip=scn.source_ip,
                destination_ip=scn.destination_ip,
                dst_port=scn.flow.dst_port,
                protocol="TCP",
            )
            t_pol_end = time.perf_counter()
            policy_latencies.append((t_pol_end - t_pol_start) * 1000.0)

            t_pipe_end = time.perf_counter()
            pipeline_latencies.append((t_pipe_end - t_pipe_start) * 1000.0)

            adaptive_act = adaptive_decision.policy_action
            adaptive_actions[adaptive_act] = adaptive_actions.get(adaptive_act, 0) + 1

            # PATH B: Traditional Static Policy Baseline
            static_act, static_rule = StaticPolicyEngine.evaluate(
                flow=scn.flow,
                source_ip=scn.source_ip,
                dst_port=scn.flow.dst_port,
            )
            static_actions[static_act] = static_actions.get(static_act, 0) + 1

            # Check Over-blocking (Ground Truth BENIGN getting RESTRICT or BLOCK)
            if gt == "BENIGN":
                if static_act in ["Restrict", "Block"]:
                    static_overblock_count += 1
                if adaptive_act in ["Restrict", "Block"]:
                    adaptive_overblock_count += 1

            # Check Under-blocking (Ground Truth Malicious getting ALLOW)
            if gt != "BENIGN":
                if static_act == "Allow":
                    static_underblock_count += 1
                if adaptive_act == "Allow":
                    adaptive_underblock_count += 1

            # Check Borderline Confidence Gating to MONITOR
            if scn.is_borderline:
                if adaptive_act == "Monitor":
                    borderline_gated_count += 1

            # Check Decision Divergence
            is_divergent = static_act.upper() != adaptive_act.upper()
            div_cat = "SAME_DECISION"
            if is_divergent:
                if gt == "BENIGN" and static_act in ["Restrict", "Block"] and adaptive_act in ["Allow", "Monitor"]:
                    div_cat = "STATIC_OVERBLOCK"
                elif gt != "BENIGN" and static_act == "Allow" and adaptive_act in ["Restrict", "Block"]:
                    div_cat = "STATIC_UNDERBLOCK"
                elif gt == "BENIGN" and adaptive_act in ["Restrict", "Block"]:
                    div_cat = "ADAPTIVE_OVERBLOCK"
                else:
                    div_cat = "POLICY_DIFFERENCE"

            rationale = (
                f"Adaptive: '{adaptive_act}' ({adaptive_decision.rule_name}, Risk {adaptive_decision.risk_score}) vs "
                f"Static: '{static_act}' ({static_rule or 'DEFAULT_ALLOW'})."
            )

            div_record = PolicyDivergenceRecord(
                scenario_id=scn.scenario_id,
                ground_truth_class=gt,
                source_ip=scn.source_ip,
                destination_ip=scn.destination_ip,
                dst_port=scn.flow.dst_port,
                packet_count=scn.flow.packet_count,
                conn_rate=scn.flow.conn_rate,
                static_action=static_act,
                static_rule_matched=static_rule,
                adaptive_action=adaptive_act,
                adaptive_risk_score=adaptive_decision.risk_score,
                adaptive_confidence=adaptive_decision.confidence,
                adaptive_rule_matched=adaptive_decision.rule_name,
                divergence_category=div_cat,
                divergence_rationale=rationale,
                is_borderline=scn.is_borderline,
                is_allowlisted=scn.is_allowlisted,
            )

            if is_divergent:
                divergence_records.append(div_record)

            # Optional Persistence (is_demo=True, telemetry_source='BENCHMARK_EVALUATION')
            if request.persist_events and db is not None:
                events_to_persist.append(
                    SecurityEventModel(
                        id=f"evt-bench-{scn.scenario_id}",
                        timestamp=datetime.now(timezone.utc),
                        source_ip=scn.source_ip,
                        destination_ip=scn.destination_ip,
                        attack_type=pred.attack_type,
                        risk_score=pred.risk_score,
                        threat_level=pred.threat_level,
                        confidence=pred.confidence,
                        action_recommendation=pred.action_recommendation,
                        current_policy_action=adaptive_act,
                        status="Simulated",
                        description=f"Phase 8 Benchmark: {scn.description}",
                        is_anomaly=pred.is_anomaly,
                        is_demo=True,
                        flow_features={
                            **scn.flow.model_dump(),
                            "telemetry_source": "BENCHMARK_EVALUATION",
                            "ground_truth_class": gt,
                        },
                        class_probabilities=pred.class_probabilities,
                        top_contributing_features=[f.model_dump() for f in pred.top_contributing_features],
                    )
                )

        if events_to_persist and db is not None:
            repo = SecurityEventRepository(db)
            for ev in events_to_persist:
                repo.create(ev)

        total_duration = max(time.perf_counter() - total_start, 0.001)
        throughput = round(len(scenarios) / total_duration, 1)

        # 1. Compute ML Classification Metrics
        ml_metrics = cls._calculate_ml_metrics(ground_truth_labels, predicted_labels)

        # 2. Compute Policy Comparison Metrics
        total_divergent = sum(1 for d in divergence_records if d.divergence_category != "SAME_DECISION")
        div_rate = round(total_divergent / float(len(scenarios)), 4) if scenarios else 0.0

        static_ob_rate = round(static_overblock_count / float(max(total_benign_count, 1)), 4)
        adaptive_ob_rate = round(adaptive_overblock_count / float(max(total_benign_count, 1)), 4)

        static_ub_rate = round(static_underblock_count / float(max(total_malicious_count, 1)), 4)
        adaptive_ub_rate = round(adaptive_underblock_count / float(max(total_malicious_count, 1)), 4)

        gating_eff = round(borderline_gated_count / float(max(borderline_count, 1)), 4) if borderline_count > 0 else 1.0

        pol_metrics = PolicyComparisonMetrics(
            adaptive_action_distribution=adaptive_actions,
            static_action_distribution=static_actions,
            static_over_blocking_count=static_overblock_count,
            static_over_blocking_rate=static_ob_rate,
            adaptive_over_blocking_count=adaptive_overblock_count,
            adaptive_over_blocking_rate=adaptive_ob_rate,
            static_under_blocking_count=static_underblock_count,
            static_under_blocking_rate=static_ub_rate,
            adaptive_under_blocking_count=adaptive_underblock_count,
            adaptive_under_blocking_rate=adaptive_ub_rate,
            total_divergent_decisions=total_divergent,
            divergence_rate=div_rate,
            borderline_scenarios_count=borderline_count,
            borderline_gated_to_monitor_count=borderline_gated_count,
            borderline_gating_effectiveness=gating_eff,
        )

        # 3. Compute Latency Metrics
        latency_breakdown = LatencyBreakdown(
            total_pipeline_latency_ms=cls._calc_lat_dist(pipeline_latencies),
            ml_inference_latency_ms=cls._calc_lat_dist(ml_latencies),
            shap_attribution_latency_ms=cls._calc_lat_dist(shap_latencies) if shap_latencies else None,
            policy_evaluation_latency_ms=cls._calc_lat_dist(policy_latencies),
            throughput_flows_per_sec=throughput,
            total_duration_seconds=round(total_duration, 3),
        )

        return EvaluationRunResponse(
            suite_name=request.suite_name,
            total_flows_evaluated=len(scenarios),
            evaluation_timestamp=datetime.now(timezone.utc),
            ml_classification_metrics=ml_metrics,
            policy_comparison_metrics=pol_metrics,
            latency_metrics=latency_breakdown,
            divergent_scenarios_sample=divergence_records[:30],
        )

    @classmethod
    def _calculate_ml_metrics(
        cls, ground_truth: List[str], predicted: List[str]
    ) -> MLClassificationMetrics:
        """
        Computes exact confusion matrix, per-class Precision/Recall/F1/FPR/FNR, and macro metrics.
        """
        n_classes = len(CLASSES)
        class_to_idx = {c: i for i, c in enumerate(CLASSES)}
        matrix = [[0 for _ in range(n_classes)] for _ in range(n_classes)]

        total_samples = len(ground_truth)
        correct_samples = 0

        for gt, pred in zip(ground_truth, predicted):
            r = class_to_idx.get(gt, 0)
            c = class_to_idx.get(pred, 0)
            matrix[r][c] += 1
            if gt == pred:
                correct_samples += 1

        overall_acc = round(correct_samples / float(max(total_samples, 1)), 4)

        per_class_list: List[PerClassMetrics] = []
        precisions: List[float] = []
        recalls: List[float] = []
        f1s: List[float] = []

        for i, c_name in enumerate(CLASSES):
            tp = matrix[i][i]
            fp = sum(matrix[r][i] for r in range(n_classes) if r != i)
            fn = sum(matrix[i][c] for c in range(n_classes) if c != i)
            tn = total_samples - (tp + fp + fn)

            # Division safety
            precision = (tp / float(tp + fp)) if (tp + fp) > 0 else 0.0
            recall = (tp / float(tp + fn)) if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall / float(precision + recall)) if (precision + recall) > 0 else 0.0
            fpr = (fp / float(fp + tn)) if (fp + tn) > 0 else 0.0
            fnr = (fn / float(fn + tp)) if (fn + tp) > 0 else 0.0

            per_class_list.append(
                PerClassMetrics(
                    class_name=c_name,
                    tp=tp,
                    fp=fp,
                    tn=tn,
                    fn=fn,
                    precision=round(precision, 4),
                    recall=round(recall, 4),
                    f1_score=round(f1, 4),
                    fpr=round(fpr, 4),
                    fnr=round(fnr, 4),
                )
            )
            precisions.append(precision)
            recalls.append(recall)
            f1s.append(f1)

        macro_p = round(float(np.mean(precisions)), 4)
        macro_r = round(float(np.mean(recalls)), 4)
        macro_f1 = round(float(np.mean(f1s)), 4)

        return MLClassificationMetrics(
            overall_accuracy=overall_acc,
            macro_precision=macro_p,
            macro_recall=macro_r,
            macro_f1=macro_f1,
            confusion_matrix=ConfusionMatrixSchema(classes=CLASSES, matrix=matrix),
            per_class_metrics=per_class_list,
        )

    @classmethod
    def _calc_lat_dist(cls, latencies: List[float]) -> LatencyDistribution:
        if not latencies:
            return LatencyDistribution(mean=0.0, p50=0.0, p95=0.0, p99=0.0)
        return LatencyDistribution(
            mean=round(float(np.mean(latencies)), 3),
            p50=round(float(np.percentile(latencies, 50)), 3),
            p95=round(float(np.percentile(latencies, 95)), 3),
            p99=round(float(np.percentile(latencies, 99)), 3),
        )

    @classmethod
    def export_report_csv(cls, res: EvaluationRunResponse) -> str:
        """
        Exports summary metrics into clean tabular CSV.
        """
        output = io.StringIO()
        output.write("============================================================\n")
        output.write(f"GATEWAY EVALUATION BENCHMARK REPORT: {res.suite_name}\n")
        output.write(f"Timestamp: {res.evaluation_timestamp.isoformat()}\n")
        output.write(f"Total Flows Evaluated: {res.total_flows_evaluated}\n")
        output.write("============================================================\n\n")

        output.write("--- 1. ML CLASSIFICATION PERFORMANCE ---\n")
        output.write("Class,TP,FP,TN,FN,Precision,Recall,F1-Score,FPR,FNR\n")
        for pc in res.ml_classification_metrics.per_class_metrics:
            output.write(f"{pc.class_name},{pc.tp},{pc.fp},{pc.tn},{pc.fn},{pc.precision},{pc.recall},{pc.f1_score},{pc.fpr},{pc.fnr}\n")
        output.write(f"\nOverall Accuracy: {res.ml_classification_metrics.overall_accuracy}\n")
        output.write(f"Macro F1-Score: {res.ml_classification_metrics.macro_f1}\n\n")

        output.write("--- 2. POLICY COMPARISON (ADAPTIVE AI VS TRADITIONAL STATIC BASELINE) ---\n")
        pm = res.policy_comparison_metrics
        output.write(f"Static Over-blocking (False Alarm Containment Rate): {pm.static_over_blocking_rate} ({pm.static_over_blocking_count} flows)\n")
        output.write(f"Adaptive Over-blocking (False Alarm Containment Rate): {pm.adaptive_over_blocking_rate} ({pm.adaptive_over_blocking_count} flows)\n")
        output.write(f"Static Under-blocking (Missed Threat Rate): {pm.static_under_blocking_rate} ({pm.static_under_blocking_count} flows)\n")
        output.write(f"Adaptive Under-blocking (Missed Threat Rate): {pm.adaptive_under_blocking_rate} ({pm.adaptive_under_blocking_count} flows)\n")
        output.write(f"Decision Divergence Rate: {pm.divergence_rate} ({pm.total_divergent_decisions} divergent decisions)\n")
        output.write(f"Borderline Confidence Gating Effectiveness: {pm.borderline_gating_effectiveness}\n\n")

        output.write("--- 3. LATENCY & THROUGHPUT ---\n")
        lm = res.latency_metrics
        output.write(f"Total Pipeline Latency (mean/p50/p95/p99 ms): {lm.total_pipeline_latency_ms.mean} / {lm.total_pipeline_latency_ms.p50} / {lm.total_pipeline_latency_ms.p95} / {lm.total_pipeline_latency_ms.p99}\n")
        output.write(f"ML Inference Latency (mean ms): {lm.ml_inference_latency_ms.mean}\n")
        output.write(f"Measured Throughput: {lm.throughput_flows_per_sec} flows/sec\n")
        output.write(f"Total Benchmark Execution Time: {lm.total_duration_seconds} seconds\n")

        return output.getvalue()
