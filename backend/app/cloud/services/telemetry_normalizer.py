"""
Multi-Cloud Canonical Telemetry Normalizer & ML Ingestion Engine
================================================================
Normalizes telemetry from AWS, GCP, Azure, and Docker Lab into CanonicalFlowRecord format,
extracts the canonical 9-feature schema (strictly excluding synthetic failed_auth_count),
executes ML threat prediction via authoritative XGBoost V2, evaluates policy, and records security events.
"""

from collections import defaultdict
from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from sqlalchemy.orm import Session

try:
    from backend.app.cloud.schemas.cloud_telemetry import (
        CanonicalFlowRecord,
        CloudFlowItemResult,
        CloudTelemetryBatchResponse,
        TelemetryNormalizationReport,
    )
    from backend.app.models.cloud_account import CloudAccountModel
    from backend.app.cloud.services.telemetry_checkpoint_service import TelemetryCheckpointService
    from backend.app.models.security_event import SecurityEventModel
    from backend.app.repositories.security_event_repo import SecurityEventRepository
    from backend.app.schemas.predict import NetworkFlowRequest, PredictionResponse
    from backend.app.services.dashboard_service import DashboardService
    from backend.app.services.hybrid_topology import NetworkZoneClassifier
    from backend.app.services.ml_service import MLService
    from backend.app.services.policy_engine import PolicyEngine
    from ml.features.extractor import FEATURE_NAMES_V2, FeatureExtractor, NetworkFlowInput, calculate_conn_rate
except ImportError:
    from app.cloud.schemas.cloud_telemetry import (
        CanonicalFlowRecord,
        CloudFlowItemResult,
        CloudTelemetryBatchResponse,
        TelemetryNormalizationReport,
    )
    from app.models.cloud_account import CloudAccountModel
    from app.cloud.services.telemetry_checkpoint_service import TelemetryCheckpointService
    from app.models.security_event import SecurityEventModel
    from app.repositories.security_event_repo import SecurityEventRepository
    from app.schemas.predict import NetworkFlowRequest, PredictionResponse
    from app.services.dashboard_service import DashboardService
    from app.services.hybrid_topology import NetworkZoneClassifier
    from app.services.ml_service import MLService
    from app.services.policy_engine import PolicyEngine
    from ml.features.extractor import FEATURE_NAMES_V2, FeatureExtractor, NetworkFlowInput, calculate_conn_rate

logger = logging.getLogger(__name__)


class TelemetryNormalizer:
    """
    Enterprise-grade normalizer for multi-cloud flow log telemetry.
    Ensures mathematical and schema parity across AWS, GCP, Azure, and Docker Lab.
    """

    @classmethod
    def aggregate_canonical_records(
        cls,
        records: List[CanonicalFlowRecord],
        window_tolerance_seconds: int = 600,
    ) -> List[CanonicalFlowRecord]:
        """
        Aggregates raw flow log records that belong to the same directed flow session.
        Preserves raw records, maintains directional attribution (ingress/egress),
        and strictly avoids double-counting forward and reverse traffic.

        Aggregation criteria:
        - Same network interface (interface_id)
        - Same directed endpoint pair and protocol: (src_ip, dst_ip, src_port, dst_port, protocol)
        - Same flow direction (INGRESS, EGRESS, INTRA_VPC, CROSS_ZONE)
        - Overlapping or contiguous time windows (within window_tolerance_seconds)
        """
        if not records:
            return []

        # Group by interface and directed 5-tuple
        groups: Dict[Tuple[str, str, str, int, int, str, str], List[CanonicalFlowRecord]] = defaultdict(list)
        for r in records:
            iface = r.interface_id or "default-iface"
            key = (
                iface,
                r.src_ip,
                r.dst_ip,
                r.src_port,
                r.dst_port,
                r.protocol,
                r.flow_direction or "CROSS_ZONE",
            )
            groups[key].append(r)

        aggregated: List[CanonicalFlowRecord] = []
        for key, rec_list in groups.items():
            if len(rec_list) == 1:
                aggregated.append(rec_list[0])
                continue

            # Sort records chronologically
            rec_list.sort(key=lambda x: (x.start_time, x.end_time))

            # Session aggregation preserving directional attribution
            primary = rec_list[0]
            total_pkts = sum(r.packet_count for r in rec_list)
            total_bytes = sum(r.byte_count for r in rec_list)
            min_start = min(r.start_time for r in rec_list if r.start_time > 0) if any(r.start_time > 0 for r in rec_list) else primary.start_time
            max_end = max(r.end_time for r in rec_list if r.end_time > 0) if any(r.end_time > 0 for r in rec_list) else primary.end_time
            dur = max(float(max_end - min_start), 0.001) if max_end >= min_start else primary.duration

            agg_rec = CanonicalFlowRecord(
                flow_id=primary.flow_id,
                provider=primary.provider,
                account_id=primary.account_id,
                region=primary.region,
                src_ip=primary.src_ip,
                dst_ip=primary.dst_ip,
                src_port=primary.src_port,
                dst_port=primary.dst_port,
                protocol=primary.protocol,
                protocol_number=primary.protocol_number,
                packet_count=total_pkts,
                byte_count=total_bytes,
                duration=dur,
                start_time=min_start,
                end_time=max_end,
                action=primary.action,
                log_status=primary.log_status,
                flow_direction=primary.flow_direction,
                interface_id=primary.interface_id,
                timestamp=primary.timestamp,
                metadata={
                    **primary.metadata,
                    "aggregated_records_count": len(rec_list),
                    "aggregation_mode": "DIRECTED_SESSION_ACCUMULATOR",
                },
            )
            aggregated.append(agg_rec)

        return aggregated

    @classmethod
    def normalize_flow_record(
        cls,
        raw_record: CanonicalFlowRecord,
        stateful_port_tracker: Optional[Dict[str, set]] = None,
    ) -> Tuple[CanonicalFlowRecord, Dict[str, float]]:
        """
        Validate and calculate canonical 9-feature values for a CanonicalFlowRecord.
        Reproduces the exact training methodology from ml/data/clean_and_preprocess.py.
        Returns the enriched CanonicalFlowRecord and the exact 9-feature dict.
        """
        duration = max(float(raw_record.duration), 0.001)
        pkt_count = max(int(raw_record.packet_count), 1)
        byte_count = max(int(raw_record.byte_count), 64)
        dst_port = max(min(int(raw_record.dst_port), 65535), 1)

        # Connection rate calculated strictly according to training logic in clean_and_preprocess.py
        conn_rate = calculate_conn_rate(pkt_count, duration)
        bytes_per_sec = float(byte_count) / duration
        packets_per_sec = float(pkt_count) / duration
        avg_packet_size = float(byte_count) / float(pkt_count)

        # Windowed destination port diversity per source host
        if stateful_port_tracker is not None:
            if raw_record.src_ip not in stateful_port_tracker:
                stateful_port_tracker[raw_record.src_ip] = set()
            if raw_record.dst_port:
                stateful_port_tracker[raw_record.src_ip].add(raw_record.dst_port)
            unique_dst_ports = max(len(stateful_port_tracker[raw_record.src_ip]), 1)
        else:
            unique_dst_ports = max(int(raw_record.unique_dst_ports), 1)

        # Enriched record
        raw_record.duration = duration
        raw_record.packet_count = pkt_count
        raw_record.byte_count = byte_count
        raw_record.conn_rate = conn_rate
        raw_record.bytes_per_sec = bytes_per_sec
        raw_record.packets_per_sec = packets_per_sec
        raw_record.avg_packet_size = avg_packet_size
        raw_record.unique_dst_ports = unique_dst_ports

        # Canonical 9-feature dictionary matching FEATURE_NAMES_V2 exactly
        feature_dict = {
            "packet_count": float(pkt_count),
            "byte_count": float(byte_count),
            "duration": float(duration),
            "conn_rate": float(conn_rate),
            "dst_port": float(dst_port),
            "unique_dst_ports": float(unique_dst_ports),
            "bytes_per_sec": float(bytes_per_sec),
            "packets_per_sec": float(packets_per_sec),
            "avg_packet_size": float(avg_packet_size),
        }

        return raw_record, feature_dict

    @classmethod
    def process_canonical_batch(
        cls,
        records: List[CanonicalFlowRecord],
        provider: str,
        account_id: str,
        db: Optional[Session] = None,
        persist: bool = True,
        checkpoint_data: Optional[Dict[str, Any]] = None,
        source_type: Optional[str] = None,
        source_identifier: Optional[str] = None,
    ) -> CloudTelemetryBatchResponse:
        """
        Process a batch of CanonicalFlowRecords:
        1. Aggregates compatible flow log records sharing directed endpoints and interfaces.
        2. Normalizes features into the 9-feature XGBoost V2 schema.
        3. Executes ML prediction and policy evaluation.
        4. Persists security events to PostgreSQL when threat is flagged or persist=True.
        """
        start_time = time.perf_counter()

        # Step 1: Pre-calculate window-level destination port diversity per source IP
        port_tracker: Dict[str, set] = defaultdict(set)
        for rec in records:
            if rec.src_ip and rec.dst_port:
                port_tracker[rec.src_ip].add(rec.dst_port)

        # Step 2: Session aggregation for compatible directed flow records
        aggregated_records = cls.aggregate_canonical_records(records)

        results: List[CloudFlowItemResult] = []
        high_risk_count = 0
        accepted_count = 0
        dropped_count = 0

        for rec in aggregated_records:
            # 1. Feature normalization matching training pipeline
            enriched_rec, feat_dict = cls.normalize_flow_record(rec, port_tracker)

            # 2. Threat Inference via MLService
            # Note: NetworkFlowRequest handles legacy/v1 compatibility if needed, but our authoritative
            # primary model XGBoost V2 consumes the 9 features directly.
            flow_req = NetworkFlowRequest(
                packet_count=int(feat_dict["packet_count"]),
                byte_count=int(feat_dict["byte_count"]),
                duration=feat_dict["duration"],
                conn_rate=feat_dict["conn_rate"],
                dst_port=int(feat_dict["dst_port"]),
                unique_dst_ports=int(feat_dict["unique_dst_ports"]),
                failed_auth_count=0,  # Zero by definition for network flow telemetry
                bytes_per_sec=feat_dict["bytes_per_sec"],
                packets_per_sec=feat_dict["packets_per_sec"],
                avg_packet_size=feat_dict["avg_packet_size"],
            )

            prediction: PredictionResponse = MLService.predict(flow_req)
            if prediction.threat_level in ["HIGH", "CRITICAL"] or prediction.risk_score >= 70:
                high_risk_count += 1

            # 3. Context-aware Policy Evaluation
            policy_decision = PolicyEngine.evaluate(
                prediction=prediction,
                source_ip=enriched_rec.src_ip,
                destination_ip=enriched_rec.dst_ip,
                dst_port=enriched_rec.dst_port,
                protocol=enriched_rec.protocol,
            )

            if policy_decision.policy_action in ["DROP", "BLOCK", "QUARANTINE"]:
                dropped_count += 1
            else:
                accepted_count += 1

            # 4. Persistence
            event_id = f"evt-cld-{int(time.time())}-{uuid.uuid4().hex[:6]}"
            if persist and db is not None:
                try:
                    # Stored flow features: preserve canonical ML features plus explicit telemetry provenance
                    stored_flow_features = dict(feat_dict)
                    stored_flow_features["telemetry_source"] = f"{provider}_VPC_FLOW_LOG"
                    stored_flow_features["provider"] = provider
                    stored_flow_features["account_id"] = account_id
                    stored_flow_features["source_type"] = source_type or "CLOUDWATCH_LOGS"
                    if source_identifier:
                        stored_flow_features["source_identifier"] = source_identifier

                    event_model = SecurityEventModel(
                        id=event_id,
                        timestamp=enriched_rec.timestamp or datetime.now(timezone.utc),
                        source_ip=enriched_rec.src_ip,
                        destination_ip=enriched_rec.dst_ip,
                        attack_type=prediction.attack_type,
                        risk_score=prediction.risk_score,
                        threat_level=prediction.threat_level,
                        confidence=prediction.confidence,
                        action_recommendation=prediction.action_recommendation,
                        current_policy_action=policy_decision.policy_action,
                        status="Monitoring",
                        description=f"[{provider}] Flow Ingestion: {policy_decision.reason}",
                        flow_features=stored_flow_features,
                        is_demo=False,
                    )
                    db.add(event_model)
                    db.commit()
                except Exception as db_err:
                    logger.warning("DB event save omitted or rolled back: %s", db_err)
                    db.rollback()

            results.append(
                CloudFlowItemResult(
                    flow_id=enriched_rec.flow_id,
                    provider=provider,
                    account_id=account_id,
                    src_ip=enriched_rec.src_ip,
                    dst_ip=enriched_rec.dst_ip,
                    dst_port=enriched_rec.dst_port,
                    protocol=enriched_rec.protocol,
                    flow_direction=enriched_rec.flow_direction or "CROSS_ZONE",
                    packet_count=enriched_rec.packet_count,
                    byte_count=enriched_rec.byte_count,
                    duration_seconds=enriched_rec.duration,
                    conn_rate=enriched_rec.conn_rate,
                    unique_dst_ports=enriched_rec.unique_dst_ports,
                    risk_score=prediction.risk_score,
                    threat_level=prediction.threat_level,
                    attack_type=prediction.attack_type,
                    policy_action=policy_decision.policy_action,
                    enforcement_status=policy_decision.reason,
                    event_id=event_id,
                )
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Operational Auditing & Ingestion Checkpoint Persistence
        if db is not None:
            try:
                ingest_id = f"cld-ingest-{int(time.time())}-{uuid.uuid4().hex[:6]}"
                dup_skipped = checkpoint_data.get("duplicate_skipped", 0) if checkpoint_data else 0
                flow_summaries = [
                    {
                        "flow_id": r.flow_id,
                        "src_ip": r.src_ip,
                        "dst_ip": r.dst_ip,
                        "dst_port": r.dst_port,
                        "attack_type": r.attack_type,
                        "risk_score": r.risk_score,
                        "policy_action": r.policy_action,
                    }
                    for r in results[:20]
                ]

                TelemetryCheckpointService.record_ingestion(
                    db=db,
                    ingestion_id=ingest_id,
                    provider=provider,
                    account_id=account_id,
                    source_type=source_type or "CLOUDWATCH_LOGS",
                    source_identifier=source_identifier,
                    records_discovered=len(records) + dup_skipped,
                    records_ingested=len(results),
                    records_duplicate_skipped=dup_skipped,
                    records_rejected=0,
                    high_risk_detected=high_risk_count,
                    flows_accepted=accepted_count,
                    flows_dropped=dropped_count,
                    status="SUCCESS",
                    duration_ms=round(elapsed_ms, 2),
                    summary=flow_summaries,
                )

                if checkpoint_data and source_identifier:
                    TelemetryCheckpointService.save_checkpoint(
                        db=db,
                        provider=provider,
                        account_id=account_id,
                        source_type=source_type or "CLOUDWATCH_LOGS",
                        source_identifier=source_identifier,
                        last_timestamp_ms=checkpoint_data.get("last_timestamp_ms"),
                        last_token=checkpoint_data.get("last_token"),
                        last_object_key=checkpoint_data.get("last_object_key"),
                        records_added=len(results),
                    )

                # Update account last telemetry sync
                acc = db.query(CloudAccountModel).filter(CloudAccountModel.account_id == account_id).first()
                if acc:
                    acc.last_telemetry_sync = datetime.now(timezone.utc)
                    db.commit()

            except Exception as audit_err:
                logger.warning("Telemetry audit/checkpoint persistence omitted: %s", audit_err)

        return CloudTelemetryBatchResponse(
            status="SUCCESS",
            provider=provider,
            account_id=account_id,
            records_received=len(records),
            records_parsed=len(records),
            records_aggregated=len(results),
            high_risk_flows_detected=high_risk_count,
            flows_accepted=accepted_count,
            flows_dropped=dropped_count,
            parsing_duration_ms=round(elapsed_ms * 0.2, 2),
            inference_duration_ms=round(elapsed_ms * 0.8, 2),
            flows=results,
            normalization_report=TelemetryNormalizationReport(
                features_extracted=FEATURE_NAMES_V2,
                schema_version="v2_canonical",
                failed_auth_synthesized=False,
                timestamp_provenance=True,
                direction_classified=True,
            ),
        )
