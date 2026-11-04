"""
Traffic Ingestion Service
=========================
Orchestrates PCAP file parsing using Scapy PcapReader, bidirectional flow aggregation,
Phase 1 ML inference, and PostgreSQL persistence with comprehensive performance metrics.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import platform
import time
from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

from backend.app.config import settings
from backend.app.schemas.ingest import (
    FlowFeatureSummary,
    IngestedFlowResult,
    IngestionMetrics,
    IngestionStatusResponse,
    PcapIngestionResponse,
    SamplePcapInfo,
)
from backend.app.schemas.predict import NetworkFlowRequest, PredictionResponse
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.flow_aggregator import FlowAggregator, FlowSession, PacketRecord
from backend.app.services.ml_service import MLService
from backend.app.services.sample_pcap_generator import ensure_sample_pcaps, SAMPLE_DIR


class IngestionService:
    """
    Core service managing PCAP parsing, feature transformation, ML pipeline execution,
    and PostgreSQL persistence.
    """
    _total_pcaps_ingested: int = 0
    _total_packets_processed: int = 0
    _total_flows_generated: int = 0

    @classmethod
    def get_status(cls) -> IngestionStatusResponse:
        """
        Return the operational status and cumulative telemetry of the ingestion engine.
        """
        return IngestionStatusResponse(
            engine_status="ONLINE",
            active_mode="PCAP_INGESTION_PRIMARY",
            raw_socket_capture_supported=False,  # Factual statement for standard unprivileged Windows execution
            platform=f"{platform.system()} {platform.release()}",
            supported_formats=["pcap", "pcapng", "cap"],
            max_upload_size_mb=15,
            total_pcaps_ingested=cls._total_pcaps_ingested,
            total_packets_processed=cls._total_packets_processed,
            total_flows_generated=cls._total_flows_generated,
        )

    @classmethod
    def list_samples(cls) -> List[SamplePcapInfo]:
        """
        Return available built-in benchmark PCAPs.
        """
        return ensure_sample_pcaps()

    @classmethod
    def get_sample_path(cls, filename: str) -> Path:
        """
        Safely resolve a sample PCAP path with path traversal protection.
        """
        safe_name = os.path.basename(filename)
        ensure_sample_pcaps()
        target = SAMPLE_DIR / safe_name
        if not target.exists() or not target.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Sample PCAP fixture '{safe_name}' not found.",
            )
        return target

    @classmethod
    def _select_representative_sessions(
        cls,
        sessions: List[FlowSession],
        aggregator: FlowAggregator,
        max_eval: int = 500,
    ) -> List[FlowSession]:
        """
        Intelligently and deterministically select up to `max_eval` representative flow sessions
        from a large population using multi-criteria priority scoring and stratified diversity.
        
        Selection criteria:
          1. Anomaly & volume indicators: high packet count, byte volume, and high connection rates.
          2. Protocol diversity: non-TCP (UDP/ICMP) flows receive priority boosts to catch covert channels/floods.
          3. Port scan detection: flows from source IPs probing multiple unique destination ports.
          4. Full capture temporal representation: remaining quota uniformly samples across the time window.
        """
        if len(sessions) <= max_eval:
            return sessions

        scored = []
        for idx, s in enumerate(sessions):
            score = 0.0
            # Volumetric weight
            score += min(s.packet_count, 100) * 2.0
            score += min(s.byte_count / 1000.0, 50.0)
            
            # Protocol anomaly weight (e.g. UDP/ICMP anomalies in flood captures)
            if s.protocol != "TCP":
                score += 20.0
                
            # Scan indicator weight
            unique_ports = len(aggregator.host_target_ports.get(s.initiator_ip, set()))
            if unique_ports > 1:
                score += min(unique_ports * 5.0, 50.0)

            scored.append((score, idx, s))

        # Deterministic sort: highest priority first, with stable tie-breaking by packet count, bytes, first_seen, and index
        scored.sort(
            key=lambda x: (x[0], x[2].packet_count, x[2].byte_count, x[2].first_seen, -x[1]),
            reverse=True,
        )

        # Stratified allocation:
        # Top 60% of quota allocated to highest-signal anomalous / high-volume flows
        top_quota = int(max_eval * 0.6)
        selected = [x[2] for x in scored[:top_quota]]
        selected_set = {x[1] for x in scored[:top_quota]}

        # Remaining 40% uniformly distributed across the remainder for representative temporal coverage
        remaining = [x for x in scored[top_quota:] if x[1] not in selected_set]
        rem_quota = max_eval - len(selected)
        if remaining and rem_quota > 0:
            step = max(len(remaining) / rem_quota, 1.0)
            for i in range(rem_quota):
                rem_idx = int(i * step)
                if rem_idx < len(remaining):
                    selected.append(remaining[rem_idx][2])

        return selected[:max_eval]

    @classmethod
    def ingest_pcap_file(
        cls,
        filepath: Path,
        filename: str,
        persist: bool = True,
        db: Optional[Session] = None,
    ) -> PcapIngestionResponse:
        """
        Ingest and evaluate a PCAP / PCAPNG capture file.
        
        Steps:
          1. Stream packets with PcapReader to avoid excessive memory consumption.
          2. Parse L3 IP and L4 transport headers.
          3. Aggregate into bidirectional flow sessions via FlowAggregator.
          4. Intelligently select bounded representative flows for detailed ML inference if exceeding limit.
          5. Execute ML inference via ThreatPredictor with conditional SHAP.
          6. If persist=True, store resulting security events in PostgreSQL via batched persistence.
          7. Record precise latency, throughput, sampling, and execution metrics.
          8. Return bounded response payload to protect frontend responsiveness.
        """
        if not filepath.exists():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"PCAP file at '{filepath}' does not exist.",
            )

        file_size_bytes = filepath.stat().st_size
        if file_size_bytes == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded PCAP file is empty (0 bytes).",
            )

        start_total = time.perf_counter()
        aggregator = FlowAggregator(inactivity_timeout=10.0, max_flow_duration=30.0)

        packets_read = 0
        packets_processed = 0
        packets_skipped = 0

        # --- Step 1 & 2: Parse packets ---
        start_parse = time.perf_counter()
        try:
            with PcapReader(str(filepath)) as pcap_reader:
                for raw_pkt in pcap_reader:
                    packets_read += 1
                    try:
                        # Extract IP layer
                        if raw_pkt.haslayer(IP):
                            ip_layer = raw_pkt[IP]
                            src_ip = ip_layer.src
                            dst_ip = ip_layer.dst
                        elif raw_pkt.haslayer(IPv6):
                            ip_layer = raw_pkt[IPv6]
                            src_ip = ip_layer.src
                            dst_ip = ip_layer.dst
                        else:
                            packets_skipped += 1
                            continue

                        # Extract transport layer (TCP/UDP/ICMP)
                        protocol = "OTHER"
                        src_port = 0
                        dst_port = 0
                        tcp_flags = None

                        if raw_pkt.haslayer(TCP):
                            tcp_layer = raw_pkt[TCP]
                            protocol = "TCP"
                            src_port = int(tcp_layer.sport)
                            dst_port = int(tcp_layer.dport)
                            tcp_flags = int(tcp_layer.flags)
                            raw_payload = bytes(tcp_layer.payload) if tcp_layer.payload else b""
                            is_auth_fail = any(
                                marker in raw_payload
                                for marker in (b"AUTH_FAIL", b"401 Unauthorized", b"Permission denied")
                            )
                        elif raw_pkt.haslayer(UDP):
                            udp_layer = raw_pkt[UDP]
                            protocol = "UDP"
                            src_port = int(udp_layer.sport)
                            dst_port = int(udp_layer.dport)
                            is_auth_fail = False
                        elif raw_pkt.haslayer(ICMP):
                            protocol = "ICMP"
                            src_port = 0
                            dst_port = 0
                            is_auth_fail = False
                        else:
                            protocol = "OTHER"
                            src_port = 0
                            dst_port = 0
                            is_auth_fail = False

                        pkt_time = float(getattr(raw_pkt, "time", time.time()))
                        pkt_len = int(len(raw_pkt))

                        record = PacketRecord(
                            timestamp=pkt_time,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=protocol,
                            length_bytes=pkt_len,
                            tcp_flags=tcp_flags,
                            is_auth_failure=is_auth_fail,
                        )

                        aggregator.add_packet(record)
                        packets_processed += 1

                    except Exception:
                        # Defensive: skip corrupted single packet without crashing whole pipeline
                        packets_skipped += 1
                        continue

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Failed to read PCAP packet stream: {str(e)}",
            )

        # Flush remaining active sessions
        completed_sessions = aggregator.flush_all()
        parse_duration_ms = round((time.perf_counter() - start_parse) * 1000.0, 2)
        total_flows_count = len(completed_sessions)

        # Fix 1: Bounded Flow Evaluation with Intelligent Representative Selection
        max_eval = getattr(settings, "pcap_max_evaluated_flows", 500)
        if total_flows_count > max_eval:
            selected_sessions = cls._select_representative_sessions(completed_sessions, aggregator, max_eval)
            is_sampled = True
        else:
            selected_sessions = completed_sessions
            is_sampled = False

        flows_selected_for_evaluation = len(selected_sessions)
        flows_skipped_limit = max(0, total_flows_count - flows_selected_for_evaluation)

        # Prepare flow feature summaries and prediction requests
        flow_items_to_evaluate = []
        flow_summaries = []
        flow_ids = []

        for idx, session in enumerate(selected_sessions):
            flow_input, src_ip, dst_ip = aggregator.extract_features(session)
            flow_id = f"flow-{idx+1:04d}-{src_ip}:{session.initiator_port}->{dst_ip}:{session.responder_port}"

            flow_summary = FlowFeatureSummary(
                flow_id=flow_id,
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=session.protocol,
                dst_port=flow_input.dst_port,
                packet_count=flow_input.packet_count,
                byte_count=flow_input.byte_count,
                duration=flow_input.duration,
                conn_rate=flow_input.conn_rate,
                unique_dst_ports=flow_input.unique_dst_ports,
                failed_auth_count=flow_input.failed_auth_count,
            )

            flow_req = NetworkFlowRequest(
                packet_count=flow_input.packet_count,
                byte_count=flow_input.byte_count,
                duration=flow_input.duration,
                conn_rate=flow_input.conn_rate,
                dst_port=flow_input.dst_port,
                unique_dst_ports=flow_input.unique_dst_ports,
                failed_auth_count=flow_input.failed_auth_count,
                source_ip=src_ip,
                destination_ip=dst_ip,
                persist=persist,
            )

            flow_items_to_evaluate.append((flow_req, src_ip, dst_ip, session.protocol))
            flow_summaries.append(flow_summary)
            flow_ids.append(flow_id)

        # --- Step 3 & 4: Feature extraction & ML Inference & Persistence ---
        start_inference = time.perf_counter()
        flow_results: List[IngestedFlowResult] = []
        high_risk_count = 0
        persist_duration_ms = 0.0
        events_persisted = 0

        if persist and db is not None:
            p_start = time.perf_counter()
            batch_size = getattr(settings, "pcap_db_batch_size", 100)
            predictions_and_models = DashboardService.record_prediction_batch(
                db=db,
                items=flow_items_to_evaluate,
                is_demo=False,
                batch_size=batch_size,
            )
            persist_duration_ms = round((time.perf_counter() - p_start) * 1000.0, 2)
            events_persisted = len(predictions_and_models)

            for i, (pred, event_model) in enumerate(predictions_and_models):
                if pred.risk_score >= 70:
                    high_risk_count += 1
                flow_results.append(
                    IngestedFlowResult(
                        flow_id=flow_ids[i],
                        flow_features=flow_summaries[i],
                        prediction=pred,
                        persisted_event_id=pred.event_id,
                    )
                )
        else:
            # Non-persisted fast evaluation with conditional SHAP
            for i, (flow_req, _, _, _) in enumerate(flow_items_to_evaluate):
                pred = MLService.predict(flow_req)
                if pred.risk_score >= 70:
                    high_risk_count += 1
                flow_results.append(
                    IngestedFlowResult(
                        flow_id=flow_ids[i],
                        flow_features=flow_summaries[i],
                        prediction=pred,
                        persisted_event_id=None,
                    )
                )

        inference_duration_ms = round(max((time.perf_counter() - start_inference) * 1000.0 - persist_duration_ms, 0.0), 2)
        total_duration_ms = round((time.perf_counter() - start_total) * 1000.0, 2)
        throughput = round((packets_processed / max(total_duration_ms / 1000.0, 0.001)), 1)

        # Update telemetry counters with complete capture totals
        cls._total_pcaps_ingested += 1
        cls._total_packets_processed += packets_processed
        cls._total_flows_generated += total_flows_count

        # Fix 5: Limit API Response Payload
        max_response_flows = getattr(settings, "pcap_max_response_flows", 50)
        # Prioritize most anomalous and high-risk flows in the response list
        sorted_results = sorted(
            flow_results,
            key=lambda r: (r.prediction.risk_score, 1 if r.prediction.is_anomaly else 0, r.flow_features.packet_count),
            reverse=True,
        )
        bounded_results = sorted_results[:max_response_flows]
        results_omitted_count = max(0, len(flow_results) - len(bounded_results))

        metrics = IngestionMetrics(
            packets_read=packets_read,
            packets_processed=packets_processed,
            packets_skipped=packets_skipped,
            flows_generated=total_flows_count,
            parse_duration_ms=parse_duration_ms,
            inference_duration_ms=inference_duration_ms,
            persist_duration_ms=persist_duration_ms,
            total_duration_ms=total_duration_ms,
            throughput_packets_per_sec=throughput,
            flows_selected_for_evaluation=flows_selected_for_evaluation,
            flows_skipped_limit=flows_skipped_limit,
            events_persisted=events_persisted,
        )

        return PcapIngestionResponse(
            source_type="PCAP_INGESTION",
            filename=filename,
            file_size_bytes=file_size_bytes,
            is_demo=False,
            metrics=metrics,
            flows_generated=total_flows_count,
            flows_selected_for_evaluation=flows_selected_for_evaluation,
            flows_evaluated=len(flow_results),
            events_persisted=events_persisted,
            flows_skipped_limit=flows_skipped_limit,
            high_risk_flows_count=high_risk_count,
            results_omitted_count=results_omitted_count,
            is_sampled=is_sampled,
            results=bounded_results,
        )
