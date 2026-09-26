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
from backend.app.services.flow_aggregator import FlowAggregator, PacketRecord
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
          4. Transform flow sessions into Phase 1 NetworkFlowInput schemas.
          5. Execute ML inference via ThreatPredictor.
          6. If persist=True, store resulting security events in PostgreSQL.
          7. Record precise latency and throughput metrics.
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
                        elif raw_pkt.haslayer(UDP):
                            udp_layer = raw_pkt[UDP]
                            protocol = "UDP"
                            src_port = int(udp_layer.sport)
                            dst_port = int(udp_layer.dport)
                        elif raw_pkt.haslayer(ICMP):
                            protocol = "ICMP"
                            src_port = 0
                            dst_port = 0
                        else:
                            protocol = "OTHER"
                            src_port = 0
                            dst_port = 0

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

        # --- Step 3 & 4: Feature extraction & ML Inference ---
        start_inference = time.perf_counter()
        flow_results: List[IngestedFlowResult] = []
        high_risk_count = 0

        start_persist = time.perf_counter()
        persist_duration_total_ms = 0.0

        for idx, session in enumerate(completed_sessions):
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

            pred: PredictionResponse
            persisted_id: Optional[str] = None

            if persist and db is not None:
                p_start = time.perf_counter()
                pred, event_model = DashboardService.record_prediction(
                    db=db,
                    flow_request=flow_req,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    is_demo=False,  # Ingested PCAP traffic is explicitly not demo seed
                )
                persisted_id = pred.event_id
                persist_duration_total_ms += (time.perf_counter() - p_start) * 1000.0
            else:
                pred = MLService.predict(flow_req)

            if pred.risk_score >= 70:
                high_risk_count += 1

            flow_results.append(
                IngestedFlowResult(
                    flow_id=flow_id,
                    flow_features=flow_summary,
                    prediction=pred,
                    persisted_event_id=persisted_id,
                )
            )

        inference_duration_ms = round((time.perf_counter() - start_inference) * 1000.0 - persist_duration_total_ms, 2)
        inference_duration_ms = max(inference_duration_ms, 0.0)
        persist_duration_ms = round(persist_duration_total_ms, 2)

        total_duration_ms = round((time.perf_counter() - start_total) * 1000.0, 2)
        throughput = round((packets_processed / max(total_duration_ms / 1000.0, 0.001)), 1)

        # Update telemetry counters
        cls._total_pcaps_ingested += 1
        cls._total_packets_processed += packets_processed
        cls._total_flows_generated += len(completed_sessions)

        metrics = IngestionMetrics(
            packets_read=packets_read,
            packets_processed=packets_processed,
            packets_skipped=packets_skipped,
            flows_generated=len(completed_sessions),
            parse_duration_ms=parse_duration_ms,
            inference_duration_ms=inference_duration_ms,
            persist_duration_ms=persist_duration_ms,
            total_duration_ms=total_duration_ms,
            throughput_packets_per_sec=throughput,
        )

        return PcapIngestionResponse(
            source_type="PCAP_INGESTION",
            filename=filename,
            file_size_bytes=file_size_bytes,
            is_demo=False,
            metrics=metrics,
            flows_evaluated=len(flow_results),
            high_risk_flows_count=high_risk_count,
            results=flow_results,
        )
